package acceptance

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/idprof/issuerkeys"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/profile"
)

// issuerSubject is what a run knows about the issuer it authenticates.
type issuerSubject struct {
	// issuer is the credential's iss (the issuer of an ldp_vc), empty when
	// the credential names none.
	issuer string
	// credentialIssuer is Options.CredentialIssuer.
	credentialIssuer string
	// format is the issuerkeys format identifier of the credential.
	format string
}

// candidateKey is one key the issuer may have signed with and the mechanism
// that established it.
type candidateKey struct {
	key         jose.JSONWebKey
	mechanism   issuerkeys.Mechanism
	did         string
	trustAnchor string
}

// authenticateIssuer establishes the issuer key by the mechanism the
// credential's x5c header and issuer identifier select (see Policy) and
// verifies the signature under it. requireX5C (IssuerX5C.Require on an SD-JWT
// VC, HAIP 1.0 §6.1.1) makes a validated x5c chain the only way.
func (a *Acceptor) authenticateIssuer(ctx context.Context, parsed *credential.Credential, policy *Policy, header map[string]any, subject issuerSubject, now time.Time, requireX5C bool, verification *Verification) error {
	if requireX5C && policy.IssuerX509 == nil {
		return fmt.Errorf("%w: %w requires x5c issuer authentication (IssuerX509)", ErrIssuerKeyUnresolved, profile.Refused("IssuerX5C.Require"))
	}
	if x5cRaw, present := header["x5c"]; present {
		return a.authenticateX5CIssuer(ctx, parsed, policy, x5cRaw, subject.issuer, now, verification)
	}
	candidates, err := resolveIssuerKeys(ctx, policy, subject, header, now)
	if err != nil {
		return err
	}
	return a.verifySignature(parsed, candidates, subject.issuer, verification)
}

// authenticateX5CIssuer authenticates the issuer through the x5c chain alone
// (SD-JWT VC -19 §2.5, "Inline X.509 Certificates"). The chain must reach one
// of IssuerX509's anchors: a chain that does not refuses the credential, and
// no other mechanism is consulted in its place. IssuerX5C.ExcludeAnchor and
// RejectSelfSigned apply.
func (a *Acceptor) authenticateX5CIssuer(ctx context.Context, parsed *credential.Credential, policy *Policy, x5cRaw any, issuer string, now time.Time, verification *Verification) error {
	trust := policy.IssuerX509
	if trust == nil {
		return fmt.Errorf("%w: the credential carries x5c and the policy does not permit x5c issuer authentication (IssuerX509)", ErrIssuerKeyUnresolved)
	}
	certificates, err := commonX509.DecodeX5CChain(x5cRaw)
	if err != nil {
		return err
	}
	if a.x5c.RejectSelfSigned {
		// HAIP §6.1.1: "The X.509 certificate signing the request MUST NOT be
		// self-signed."
		if err := commonX509.RequireNonSelfSignedLeaf(certificates, "issuer"); err != nil {
			return fmt.Errorf("%w: %w", ErrIssuerCertificateSelfSigned, err)
		}
	}
	if a.x5c.ExcludeAnchor {
		// HAIP §6.1.1: "The X.509 certificate of the trust anchor MUST NOT be
		// included in the x5c JOSE header". Both anchor forms are consulted.
		containsAnchor, err := commonX509.ContainsTrustAnchor(certificates, trust.TrustAnchors, trust.RootCAs)
		if err != nil {
			return err
		}
		if containsAnchor {
			return fmt.Errorf("%w: %w", profile.Refused("IssuerX5C.ExcludeAnchor"), ErrIssuerX5CTrustAnchor)
		}
	}
	leaf := certificates[0]
	if issuer != "" {
		// Checked before the chain is walked: it needs no network, and a
		// certificate for another host must not cost a CRL retrieval.
		if err := bindX5CIssuer(leaf, issuer, trust); err != nil {
			return err
		}
		verification.IssuerDNSBound = true
	}
	result, err := commonX509.VerifySigningChainWithPolicy(ctx, certificates, commonX509.SigningChainPolicy{
		TrustAnchors:                trust.TrustAnchors,
		Roots:                       trust.RootCAs,
		KeyUsages:                   trust.CertificateKeyUsages,
		CRL:                         trust.CRL,
		AllowUnadvertisedRevocation: trust.AllowUnadvertisedRevocation,
		CurrentTime:                 now,
		HTTPClient:                  revocationHTTPClient(trust.HTTPClient),
	})
	if err != nil {
		return fmt.Errorf("issuer certificate chain is not trusted: %w", err)
	}
	verification.CertificateSHA256 = result.Fingerprints
	verification.RevocationChecked = result.Revocation.CheckedCertificates
	verification.RevocationUnadvertised = result.Revocation.NoMechanismCertificates
	if len(result.Fingerprints) > 0 {
		verification.IssuerKeyID = result.Fingerprints[0]
	}
	verification.IssuerCertificateSubject = certificateSubject(leaf)
	// SD-JWT VC -19 §2.5: "In this case, the Issuer of the Verifiable Digital
	// Credential is the subject of the end-entity certificate." The iss the
	// leaf was bound to is reported apart from it.
	verification.Issuer = verification.IssuerCertificateSubject.Subject
	verification.ClaimedIssuer = issuer
	candidate := candidateKey{key: jose.JSONWebKey{Key: leaf.PublicKey}, mechanism: issuerkeys.MechanismX5CTrustedChain}
	return a.verifyCandidates(parsed, []candidateKey{candidate}, verification)
}

// resolveIssuerKeys returns the candidate keys of an issuer that carries no
// x5c, from the mechanism its identifier selects and the policy permits.
func resolveIssuerKeys(ctx context.Context, policy *Policy, subject issuerSubject, header map[string]any, now time.Time) ([]candidateKey, error) {
	issuer := subject.issuer
	switch {
	case issuer == "":
		return nil, fmt.Errorf("%w: the credential names no issuer and carries no x5c", ErrIssuerKeyUnresolved)
	case strings.HasPrefix(issuer, "did:"):
		if policy.IssuerKeys == nil {
			return nil, fmt.Errorf("%w: the issuer is a DID and the policy does not permit DID resolution (IssuerKeys)", ErrIssuerKeyUnresolved)
		}
		candidates, err := resolverCandidates(ctx, policy.IssuerKeys, subject, header)
		if err != nil {
			return nil, err
		}
		return filterCandidates(candidates, header)
	case isWebIssuer(issuer, policy.IssuerKeys):
		var candidates []candidateKey
		var resolveErr error
		if policy.IssuerKeys != nil && isSDJWTVCFormat(subject.format) {
			// SD-JWT VC -19 §2.5: "When the value of the iss claim ... is an
			// HTTPS URI, the recipient obtains the public key using the keys
			// from JWT VC Issuer Metadata".
			candidates, resolveErr = resolverCandidates(ctx, policy.IssuerKeys, subject, header)
		}
		if federation := policy.Federation; federation != nil && federation.entityID == issuer && now.Before(federation.expiresAt) {
			for _, key := range federation.keys {
				candidates = append(candidates, candidateKey{key: key, mechanism: issuerkeys.MechanismOpenIDFederation, trustAnchor: federation.trustAnchor})
			}
		}
		if len(candidates) == 0 {
			if resolveErr != nil {
				return nil, resolveErr
			}
			return nil, fmt.Errorf("%w: the policy permits no mechanism for this https issuer (IssuerKeys for SD-JWT VC, or Federation for this Entity)", ErrIssuerKeyUnresolved)
		}
		return filterCandidates(candidates, header)
	default:
		return nil, fmt.Errorf("%w: the issuer is neither an https URL nor a DID and the credential carries no x5c", ErrIssuerKeyUnresolved)
	}
}

// resolverCandidates runs the issuerkeys resolver for the credential. Its
// errors keep the resolver's *issuerkeys.UnresolvedError or
// *issuerkeys.DIDOnlyTrustError, with its diagnostics, under
// ErrIssuerKeyUnresolved.
func resolverCandidates(ctx context.Context, resolver *issuerkeys.Resolver, subject issuerSubject, header map[string]any) ([]candidateKey, error) {
	kid, _ := header["kid"].(string)
	algorithm, _ := header["alg"].(string)
	resolution, err := resolver.Resolve(ctx, issuerkeys.Request{
		Issuer:           subject.issuer,
		KeyID:            kid,
		Algorithm:        algorithm,
		CredentialFormat: subject.format,
		CredentialIssuer: subject.credentialIssuer,
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrIssuerKeyUnresolved, err)
	}
	candidates := make([]candidateKey, 0, len(resolution.Candidates))
	for _, candidate := range resolution.Candidates {
		// Every candidate is attributed to the identifier it was resolved
		// for; one resolved for another identifier does not speak for iss.
		if candidate.Issuer != subject.issuer {
			continue
		}
		candidates = append(candidates, candidateKey{key: candidate.Key, mechanism: candidate.Mechanism, did: candidate.DID})
	}
	return candidates, nil
}

// isWebIssuer reports whether issuer is an https URL, or an http URL that an
// experimental resolver (Resolver.Experimental.AllowHTTP) admits.
func isWebIssuer(issuer string, resolver *issuerkeys.Resolver) bool {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Host == "" {
		return false
	}
	return parsed.Scheme == "https" || (parsed.Scheme == "http" && resolver != nil && resolver.Experimental.AllowHTTP)
}

// isSDJWTVCFormat reports whether format is an SD-JWT VC format identifier,
// the family JWT VC Issuer Metadata is defined for.
func isSDJWTVCFormat(format string) bool {
	return format == issuerkeys.FormatSDJWTVC || format == issuerkeys.FormatSDJWTVCDraft
}

// filterCandidates drops keys whose use or alg rules them out for this
// signature (RFC 7517 §4.2, §4.4) and puts the keys named by the header kid
// first. The kid orders but does not filter: the header is unauthenticated,
// and a rotated key may keep a stale kid.
func filterCandidates(candidates []candidateKey, header map[string]any) ([]candidateKey, error) {
	algorithm, _ := header["alg"].(string)
	candidates = slices.DeleteFunc(slices.Clone(candidates), func(candidate candidateKey) bool {
		key := candidate.key
		return (key.Use != "" && key.Use != "sig") || (key.Algorithm != "" && key.Algorithm != algorithm)
	})
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: no resolved issuer key is usable for signature algorithm %q", ErrIssuerKeyUnresolved, algorithm)
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return candidates, nil
	}
	ordered := make([]candidateKey, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.key.KeyID == kid {
			ordered = append(ordered, candidate)
		}
	}
	for _, candidate := range candidates {
		if candidate.key.KeyID != kid {
			ordered = append(ordered, candidate)
		}
	}
	return ordered, nil
}

// verifySignature verifies the issuer signature under the first candidate
// that verifies it and records that key, the mechanism and the issuer.
func (a *Acceptor) verifySignature(parsed *credential.Credential, candidates []candidateKey, issuer string, verification *Verification) error {
	verification.Issuer = issuer
	verification.ClaimedIssuer = issuer
	return a.verifyCandidates(parsed, candidates, verification)
}

// verifyCandidates verifies the issuer JWS under the first candidate that
// verifies it and records that candidate.
func (a *Acceptor) verifyCandidates(parsed *credential.Credential, candidates []candidateKey, verification *Verification) error {
	for i := range candidates {
		ok, err := a.verifier.Verify(parsed.Proof, &candidates[i].key)
		if err != nil || !ok {
			continue
		}
		recordCandidate(candidates[i], verification)
		return nil
	}
	return ErrIssuerSignatureInvalid
}

// recordCandidate records the candidate whose key verified the issuer
// signature.
func recordCandidate(candidate candidateKey, verification *Verification) {
	if verification.IssuerKeyID == "" {
		verification.IssuerKeyID = candidate.key.KeyID
	}
	verified := candidate.key.Public()
	verification.IssuerKey = &verified
	verification.Mechanism = candidate.mechanism
	verification.DID = candidate.did
	verification.FederationTrustAnchor = candidate.trustAnchor
}

// bindX5CIssuer binds the iss of an x5c credential to the leaf certificate
// (SD-JWT VC -19 §2.5 and §7.3). The Issuer of an x5c credential is the leaf's
// subject, so an iss beside it is accepted only when the leaf speaks for it:
//
//   - an https iss must be named by the leaf, by its host in a dNSName
//     subject alternative name (exact, no wildcard) or in a URI subject
//     alternative name of the same scheme;
//   - a DID iss is refused: a DID issuer is authenticated by its DID document
//     (OpenID4VCI 1.0 §14.4), so a credential that wants that process carries
//     no x5c, and a certificate cannot speak for a DID;
//   - any other iss is refused, except an http URL, bound like https, under
//     IssuerX509TrustOptions.Experimental.AllowHTTP.
func bindX5CIssuer(leaf *x509.Certificate, issuer string, trust *IssuerX509TrustOptions) error {
	if strings.HasPrefix(issuer, "did:") {
		return fmt.Errorf("%w: the credential names a DID issuer and carries x5c; a DID issuer is authenticated by its DID document, not by a certificate chain", ErrIssuerDNSBindingFailed)
	}
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "https" && (parsed.Scheme != "http" || !trust.Experimental.AllowHTTP)) {
		return fmt.Errorf("%w: the issuer is not an https URL, so it names no host to bind the certificate to", ErrIssuerDNSBindingFailed)
	}
	if err := commonX509.RequireLeafNamesIssuer(leaf, parsed); err != nil {
		return fmt.Errorf("%w: issuer certificate is not bound to issuer host %q: %w", ErrIssuerDNSBindingFailed, parsed.Hostname(), err)
	}
	return nil
}

// certificateSubject is the identity leaf states.
func certificateSubject(leaf *x509.Certificate) *CertificateSubject {
	subject := &CertificateSubject{
		Subject:        leaf.Subject.String(),
		DNSNames:       slices.Clone(leaf.DNSNames),
		EmailAddresses: slices.Clone(leaf.EmailAddresses),
	}
	for _, uri := range leaf.URIs {
		subject.URIs = append(subject.URIs, uri.String())
	}
	return subject
}

// revocationHTTPClient returns client, or a bounded httpfetch client. A client
// set on IssuerX509TrustOptions.CRL takes precedence inside
// commonX509.VerifySigningChainWithPolicy.
func revocationHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return httpfetch.NewClient()
}
