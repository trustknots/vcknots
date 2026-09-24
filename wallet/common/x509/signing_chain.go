package x509

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/trustknots/vcknots/wallet/common"
)

// SigningChainOptions contains the relying party's trust policy. Trust anchors
// are provided separately from the untrusted x5c chain. Exactly one of
// TrustAnchors and Roots must be supplied. Roots preserves CertPool-based
// integrations; TrustAnchors permits RFC 5280 self-issued rollover paths.
type SigningChainOptions struct {
	TrustAnchors []*x509.Certificate
	Roots        *x509.CertPool
	CurrentTime  time.Time
	// KeyUsages constrains EKU when the ecosystem defines a signing purpose.
	// Empty means no additional EKU policy, not TLS server authentication.
	KeyUsages []x509.ExtKeyUsage
	// Revocation belongs to one verification operation, including its candidate
	// paths. It must not be reused as process-wide protocol state.
	Revocation *CRLChecker
}

// SigningChainResult is the certification path a signing certificate was
// accepted under and the outcome of its revocation check.
type SigningChainResult struct {
	// Chain is leaf first, ending at the selected configured trust anchor.
	Chain []*x509.Certificate
	// Fingerprints identify the exact certificates without exposing raw DER.
	Fingerprints []string
	Revocation   CRLCheckResult
}

// ErrNoTrustAnchor reports that no valid certification path from the signing
// certificate reaches a configured trust anchor (crypto/x509's
// UnknownAuthorityError, which also covers a certificate in the chain that does
// not validly certify the one below it). A self-signed or CA leaf, an expired
// or mis-used certificate, a name-constraint violation and a revocation
// failure are reported without it.
var ErrNoTrustAnchor = common.NewCodedError("x509_chain_no_trust_anchor", "certificate chain reaches no configured trust anchor")

// SigningChainError keeps configuration, certificate, path and revocation
// failures distinguishable. Underlying x509 and CRL errors support errors.As.
type SigningChainError struct {
	Kind string
	Err  error
}

// Error implements error.
func (e *SigningChainError) Error() string { return fmt.Sprintf("x509 %s: %v", e.Kind, e.Err) }

// Unwrap returns the wrapped error.
func (e *SigningChainError) Unwrap() error { return e.Err }

// ErrorCode names why the signing certificate was not accepted. A revocation
// failure defers to the underlying *CRLCheckError; every other refusal is
// "x509_chain_untrusted". Use errors.Is(err, ErrNoTrustAnchor) to tell a chain
// that merely reaches no configured anchor from one that is invalid.
func (e *SigningChainError) ErrorCode() string {
	var revocationError *CRLCheckError
	if errors.As(e.Err, &revocationError) {
		return revocationError.ErrorCode()
	}
	return "x509_chain_untrusted"
}

// VerifySigningCertificateChain verifies a signing certificate before consulting
// its authenticated revocation locations. It does not impose DNS identity:
// x509_hash, DNS-based verifier identifiers and credential issuers bind identity
// differently and apply that binding at their protocol boundary.
func VerifySigningCertificateChain(ctx context.Context, certificates []*x509.Certificate, options SigningChainOptions) (*SigningChainResult, error) {
	invalid := func(kind string, err error) (*SigningChainResult, error) {
		return nil, &SigningChainError{Kind: kind, Err: err}
	}
	if ctx == nil || options.CurrentTime.IsZero() || options.Revocation == nil {
		return invalid("configuration", errors.New("context, verification time and revocation checker are required"))
	}
	if (len(options.TrustAnchors) == 0) == (options.Roots == nil) {
		return invalid("configuration", errors.New("supply either trust anchors or a root pool"))
	}
	if len(certificates) == 0 || len(certificates) > 16 {
		return invalid("certificate", errors.New("x5c must contain between 1 and 16 certificates"))
	}
	for _, cert := range certificates {
		if cert == nil || len(cert.Raw) == 0 {
			return invalid("certificate", errors.New("x5c contains an empty certificate"))
		}
	}
	leaf := certificates[0]
	if leaf.IsCA || isSelfSigned(leaf) {
		return invalid("certificate", errors.New("signer must be a non-self-signed end-entity certificate"))
	}
	if hasKeyUsage(leaf) && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return invalid("certificate", errors.New("signer key usage does not permit digital signatures"))
	}
	chains, err := signingPaths(certificates, options)
	if err != nil {
		var unknownAuthority x509.UnknownAuthorityError
		if errors.As(err, &unknownAuthority) {
			err = fmt.Errorf("%w: %w", ErrNoTrustAnchor, err)
		}
		return invalid("path", err)
	}
	// Prefer the nearest reached anchor, without requiring certificates carried
	// above that anchor or spending their revocation-fetch budget.
	sort.SliceStable(chains, func(i, j int) bool { return len(chains[i]) < len(chains[j]) })
	var failures []error
	for _, chain := range chains {
		if err := ctx.Err(); err != nil {
			return invalid("revocation", err)
		}
		if err := validateSigningPath(chain, options.CurrentTime); err != nil {
			failures = append(failures, err)
			continue
		}
		revocation, err := options.Revocation.Check(ctx, chain, options.CurrentTime)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		fingerprints := make([]string, len(chain))
		for i, cert := range chain {
			digest := sha256.Sum256(cert.Raw)
			fingerprints[i] = hex.EncodeToString(digest[:])
		}
		return &SigningChainResult{Chain: chain, Fingerprints: fingerprints, Revocation: revocation}, nil
	}
	return invalid("path", errors.Join(failures...))
}

// SigningChainPolicy is one complete relying-party trust policy for a
// signing-certificate verification: the anchors, the optional EKU constraint,
// the CRL retrieval tuning, and the HTTP client the revocation fetches use.
//
// Revocation strictness is expressed once, through AllowUnadvertisedRevocation.
// A certificate that advertises no CRL distribution point stays on the trust
// path only when it is true; CRL.RequireStatus is derived from it and must not
// be set as well, which VerifySigningChainWithPolicy rejects as a conflict.
type SigningChainPolicy struct {
	// TrustAnchors and Roots name the trust anchors. Supply exactly one of
	// them; Roots preserves *x509.CertPool integrations.
	TrustAnchors []*x509.Certificate
	Roots        *x509.CertPool
	// KeyUsages constrains EKU when the ecosystem defines a signing purpose.
	// Empty means no additional EKU policy, not TLS server authentication.
	KeyUsages []x509.ExtKeyUsage
	// CRL tunes the revocation retrieval. Its RequireStatus is derived from
	// AllowUnadvertisedRevocation; its HTTPClient, when set, wins over
	// HTTPClient below.
	CRL CRLCheckerOptions
	// AllowUnadvertisedRevocation keeps on the trust path a certificate that
	// publishes no CRL distribution point, counted in
	// CRLCheckResult.NoMechanismCertificates instead of checked. That includes
	// a certificate that advertises only OCSP: OCSP is not consulted, so its
	// status is not established either. False requires a current CRL for
	// every certificate below the anchor.
	AllowUnadvertisedRevocation bool
	// CurrentTime is the single verification clock.
	CurrentTime time.Time
	// HTTPClient performs the CRL fetches when CRL.HTTPClient is nil.
	HTTPClient *http.Client
}

// VerifySigningChainWithPolicy builds the per-operation CRL checker from policy
// and verifies a leaf-first signing chain against it. It is the one place the
// RequireStatus derivation exists, so every in-library caller that accepts
// unadvertised revocation expresses it the same way and an integrator does not
// reproduce the rule.
func VerifySigningChainWithPolicy(ctx context.Context, certificates []*x509.Certificate, policy SigningChainPolicy) (*SigningChainResult, error) {
	if policy.CRL.RequireStatus && policy.AllowUnadvertisedRevocation {
		return nil, errors.New("conflicting revocation policies: CRL.RequireStatus and AllowUnadvertisedRevocation cannot both be set")
	}
	crlOptions := policy.CRL
	crlOptions.RequireStatus = !policy.AllowUnadvertisedRevocation
	if crlOptions.HTTPClient == nil {
		crlOptions.HTTPClient = policy.HTTPClient
	}
	checker, err := NewCRLChecker(crlOptions)
	if err != nil {
		return nil, err
	}
	return VerifySigningCertificateChain(ctx, certificates, SigningChainOptions{
		TrustAnchors: policy.TrustAnchors,
		Roots:        policy.Roots,
		CurrentTime:  policy.CurrentTime,
		KeyUsages:    policy.KeyUsages,
		Revocation:   checker,
	})
}

func signingPaths(certificates []*x509.Certificate, options SigningChainOptions) ([][]*x509.Certificate, error) {
	// Go 1.26 counts self-issued rollover CAs against pathLenConstraint. With
	// explicit anchors we can defer only that check, on private copies, until
	// after standard signature, constraints, EKU and policy validation. Original
	// certificate fields and signed DER remain untouched. A CertPool cannot be
	// enumerated, so a Roots pool keeps Go's stricter path-length behavior.
	deferPathLength := len(options.TrustAnchors) != 0
	originals := make(map[string]*x509.Certificate)
	prepare := func(cert *x509.Certificate) *x509.Certificate {
		originals[string(cert.Raw)] = cert
		if !deferPathLength {
			return cert
		}
		clone := *cert
		clone.MaxPathLen = -1
		clone.MaxPathLenZero = false
		return &clone
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certificates[1:] {
		intermediates.AddCert(prepare(cert))
	}
	roots := options.Roots
	if roots == nil {
		roots = x509.NewCertPool()
		for _, cert := range options.TrustAnchors {
			if cert == nil || len(cert.Raw) == 0 {
				return nil, errors.New("empty trust anchor")
			}
			roots.AddCert(prepare(cert))
		}
	}
	keyUsages := options.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	chains, err := prepare(certificates[0]).Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: options.CurrentTime, KeyUsages: keyUsages})
	if err != nil {
		return nil, err
	}
	for _, chain := range chains {
		for i, cert := range chain {
			if original := originals[string(cert.Raw)]; original != nil {
				chain[i] = original
			}
		}
	}
	return chains, nil
}

func validateSigningPath(path []*x509.Certificate, now time.Time) error {
	if len(path) < 2 {
		return errors.New("signing certificate must be issued below a trust anchor")
	}
	for i, cert := range path[1:] {
		if !cert.IsCA || !cert.BasicConstraintsValid || (hasKeyUsage(cert) && cert.KeyUsage&x509.KeyUsageCertSign == 0) {
			return errors.New("path issuer is not authorized to sign certificates")
		}
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return errors.New("path issuer is outside its validity period")
		}
		if err := path[i].CheckSignatureFrom(cert); err != nil {
			return err
		}
		if cert.BasicConstraintsValid && cert.MaxPathLen >= 0 {
			count := 0
			for _, below := range path[1 : i+1] {
				if !bytes.Equal(below.RawSubject, below.RawIssuer) {
					count++
				}
			}
			if count > cert.MaxPathLen {
				return x509.CertificateInvalidError{Cert: cert, Reason: x509.TooManyIntermediates}
			}
		}
	}
	return nil
}

// keyUsageOID is the key usage extension of RFC 5280 Section 4.2.1.3.
var keyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 15}

// hasKeyUsage reports whether cert carries a key usage extension; RFC 5280
// Section 6.1.4(n) and 6.3.3(f) check the bits only when it does.
func hasKeyUsage(cert *x509.Certificate) bool {
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(keyUsageOID) {
			return true
		}
	}
	return false
}
