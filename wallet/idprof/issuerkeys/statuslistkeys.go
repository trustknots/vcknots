package issuerkeys

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"

	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/credential/statuslist"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/profile"
)

// This file adapts the Resolver to the Token Status List checker's key hook
// (statuslist.Checker.ResolveIssuerKeys).
//
// A Status List Token is bound to the credential it speaks for by its issuer's
// key (draft-ietf-oauth-status-list-21 Section 11.3): it is signed with the
// same x5c, or with a key found by the same web-based resolution, as the
// Referenced Token. The hook is therefore asked for the keys of the credential
// issuer (or of an external Status Issuer the checker accepted), and it
// resolves them by the rule the issuer identifier's form selects - the same
// rule a credential of that issuer is authenticated by (SD-JWT VC -19
// Section 2.5 and 7.3). The protected header never selects the mechanism on
// its own; it only supplies the x5c, the kid and the alg that mechanism reads.

// X5CTrust is the relying-party trust policy for an `x5c` chain on an issuer
// JWT the library verifies outside the credential acceptor - in practice a
// Token Status List token. Its fields mean what the same fields of
// commonX509.SigningChainPolicy mean.
type X5CTrust struct {
	// TrustAnchors are the certificates a chain must reach. An empty list
	// trusts no chain, which is reported like a chain that reaches no anchor.
	TrustAnchors []*x509.Certificate
	// CRL tunes the revocation retrieval.
	CRL commonX509.CRLCheckerOptions
	// AllowUnadvertisedRevocation keeps a certificate that advertises no
	// revocation mechanism on the trust path.
	AllowUnadvertisedRevocation bool
	// KeyUsages constrains the leaf's extended key usage. Empty imposes none.
	KeyUsages []x509.ExtKeyUsage
	// HTTPClient performs the CRL retrievals when CRL.HTTPClient is nil. When
	// both are nil the Resolver's HTTPClient is used, so the deployment's
	// outbound network policy applies to CRL retrieval as it does to metadata.
	HTTPClient *http.Client
	// Now is the verification clock. A nil value uses the Resolver's.
	Now func() time.Time
	// IssuerCertificate is the validated x5c leaf certificate of the
	// credential whose status is checked (the credential acceptor's leaf).
	// It is read only under profile.Options.RequireStatusListSignerBinding
	// (statuslist.KeyRequest.RequireSignerBinding); without that option the
	// leaf of a chain that reaches TrustAnchors is accepted, since
	// draft-ietf-oauth-status-list-21 Section 11.3 mandates no binding.
	// Under the option, a Status List Token with x5c must carry a leaf with the
	// same public key, the same non-empty subject, or the same issuing
	// certificate authority (the same issuer name and authority key
	// identifier), whether or not the credential carries `iss`: the token is
	// bound to the Referenced Token by its signer or by the PKI that links the
	// two (draft-ietf-oauth-status-list-21 Section 11.3), and the Issuer of an
	// x5c credential is the subject of that certificate (SD-JWT VC -19
	// Section 2.5). An empty subject identifies nobody, so when no other link
	// holds and either subject is empty only the issuer host binding can speak
	// for the leaf, and a credential without `iss` has none. It is required
	// for a credential without `iss`, which names no other identity to bind
	// the token to; set it for every credential that was accepted through its
	// x5c when the option is on.
	IssuerCertificate *x509.Certificate
}

// StatusListKeyFunc adapts the Resolver to the Token Status List checker's
// ResolveIssuerKeys hook. template carries what the token header does not -
// CredentialFormat and CredentialIssuer of the issuance the credential came
// from; trust is the policy for an `x5c` chain, nil when
// the holder trusts none. See StatusListKeys for the rules.
func (r *Resolver) StatusListKeyFunc(template Request, trust *X5CTrust) statuslist.ResolveIssuerKeysFunc {
	return func(ctx context.Context, request statuslist.KeyRequest) ([]jose.JSONWebKey, error) {
		keys, _, err := r.StatusListKeys(ctx, template, trust, request)
		return keys, err
	}
}

// StatusListKeys resolves the candidate public keys of a Token Status List
// token for request.Issuer, and returns the resolution they came from. The
// mechanism is chosen by the form of the issuer identifier and by the policy,
// never by the header alone, and a mechanism that applies but fails is the
// answer: nothing falls back to another mechanism.
//
//   - An https issuer (http only under Experimental.AllowHTTP): when the
//     header carries an x5c, the chain is the only source. It must reach one
//     of trust.TrustAnchors, its leaf must name the issuer's host - in a
//     dNSName or a URI subject alternative name, the binding the credential
//     acceptor applies to the credential's own x5c - and, when
//     trust.IssuerCertificate is set, carry that certificate's public key or
//     its subject (a leaf or an issuer certificate with an empty subject
//     rests on the host binding alone), or the token is refused
//     (MechanismX5CTrustedChain). Without
//     x5c the keys come from the issuer's JWT VC Issuer Metadata, for the
//     SD-JWT VC family whose web-based resolution that is
//     (MechanismJWTVCIssuerMetadata).
//   - A DID issuer: the DID is resolved, and its keys are used only when a DIF
//     Well Known DID Configuration served by template.CredentialIssuer's
//     origin links that origin to the DID (MechanismDIDConfigurationBinding).
//     An unbound DID is a *DIDOnlyTrustError. The rule does not depend on the
//     credential format, so an ldp_vc issued under a DID has its Status List
//     Token resolved the same way as a JWT VC.
//   - No issuer (a credential without `iss`, whose Issuer is its x5c leaf
//     subject): only an x5c chain reaching trust.TrustAnchors whose leaf
//     carries the public key of trust.IssuerCertificate, or its subject when
//     neither subject is empty.
//   - Any other identifier is not resolved.
//
// A Resolver with Experimental set is refused, with an error wrapping
// statuslist.ErrStatusListInsecureTransportForbidden, when
// request.ForbidExperimental says the Checker's profile forbids it.
//
// request.X5C carries the profile's rules (HAIP 1.0 Section 6.1): Require
// refuses every source other than the x5c chain, ExcludeAnchor a chain that
// carries a trust anchor, RejectSelfSigned a self-signed leaf. Those refusals
// wrap statuslist.ErrStatusListCertificateRejected.
//
// A chain that is not trusted - malformed, reaching no configured anchor, not
// bound to the issuer, or with no trust configured at all - is an
// *UnresolvedError whose `x5c` diagnostic says why, wrapping the chain error
// when there is one. A revoked certificate, or a revocation status that cannot
// be established, is the signer's own state and is returned as the chain
// error itself. No candidate is an *UnresolvedError with the diagnostics.
// Every returned key is a public key, and the returned Resolution's Candidates
// are exactly the returned keys, so Resolution.CandidateFor answers for the
// key that verified.
func (r *Resolver) StatusListKeys(ctx context.Context, template Request, trust *X5CTrust, request statuslist.KeyRequest) ([]jose.JSONWebKey, *Resolution, error) {
	if request.ForbidExperimental && r.Experimental != (experimental.Transport{}) {
		// HAIP 1.0 Section 4: the profile refuses the experimental transport
		// relaxation rather than resolving over it.
		return nil, nil, fmt.Errorf("%w: %w does not permit Resolver.Experimental", statuslist.ErrStatusListInsecureTransportForbidden, profile.Refused("ForbidExperimental"))
	}
	lookup := requestFromHeader(template, request.Issuer, request.Header)
	chain := x5cChain(lookup.X5C)
	resolution := &Resolution{}
	var candidates []Candidate
	var err error

	switch {
	case request.Issuer == "":
		candidates, err = r.statusListX5CRoute(ctx, resolution, trust, request.X5C, chain, x5cBinding{issuerCertificate: trustIssuerCertificate(trust), required: request.RequireSignerBinding})
	case didReference(request.Issuer) == request.Issuer:
		if request.X5C.Require {
			return nil, nil, fmt.Errorf("%w: the profile requires an x5c signing key, which a DID issuer does not use", statuslist.ErrStatusListCertificateRejected)
		}
		candidates, err = r.statusListDIDRoute(ctx, resolution, lookup)
	default:
		issuerURL, urlErr := r.allowedURL(request.Issuer)
		switch {
		case urlErr != nil:
			resolution.Diagnostics = []MechanismDiagnostic{{Mechanism: RungX5C, Failure: "issuer identifier is neither an https URL nor a DID"}}
		case len(chain) > 0:
			resolution.IssuerDNSName = issuerURL.Hostname()
			candidates, err = r.statusListX5CRoute(ctx, resolution, trust, request.X5C, chain, x5cBinding{issuer: request.Issuer, issuerURL: issuerURL, issuerCertificate: trustIssuerCertificate(trust), required: request.RequireSignerBinding})
		case request.X5C.Require:
			return nil, nil, fmt.Errorf("%w: the profile requires the signing key in an x5c header", statuslist.ErrStatusListCertificateRejected)
		default:
			lookup.X5C = nil
			var diagnostic MechanismDiagnostic
			candidates, diagnostic = r.jwtVCIssuerRung(ctx, lookup)
			candidates = issuerCandidates(candidates, request.Issuer)
			resolution.Diagnostics = []MechanismDiagnostic{{Mechanism: RungX5C, Failure: "not present"}, diagnostic}
		}
	}
	if err != nil {
		return nil, nil, err
	}
	resolution.Candidates = candidates
	if len(candidates) == 0 {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, ctxErr
		}
		return nil, nil, &UnresolvedError{Diagnostics: resolution.Diagnostics}
	}
	return candidateKeys(candidates), resolution, nil
}

// x5cBinding names what an x5c leaf must say to speak for the issuer: the
// issuer URL's host (as the credential acceptor binds a credential's leaf),
// and the subject of the credential's own issuer certificate when it is known.
type x5cBinding struct {
	// issuer is the identifier the key is attributed to (Candidate.Issuer).
	issuer string
	// issuerURL is the issuer identifier; nil for a credential without iss.
	issuerURL *url.URL
	// issuerCertificate is X5CTrust.IssuerCertificate.
	issuerCertificate *x509.Certificate
	// required is KeyRequest.RequireSignerBinding: without it the leaf of a
	// chain that reaches a trust anchor is accepted unbound.
	required bool
}

// failure says why leaf, the Status List Token's x5c leaf, is not bound to
// the Referenced Token's issuer, or returns "" when it is: it names the host
// of the issuer's https iss, and it is linked to the credential's issuer
// certificate when that is known (issuerCertificateFailure). A credential
// without iss needs the issuer certificate.
func (b x5cBinding) failure(leaf *x509.Certificate) string {
	if b.issuerURL != nil {
		if err := commonX509.RequireLeafNamesIssuer(leaf, b.issuerURL); err != nil {
			return "certificate does not name the issuer host"
		}
	}
	switch {
	case b.issuerCertificate != nil:
		return b.issuerCertificateFailure(leaf)
	case b.issuerURL == nil:
		return "credential issuer certificate is not configured"
	}
	return ""
}

// issuerCertificateFailure says why leaf, the Status List Token's x5c leaf,
// does not speak for the issuer of the credential whose certificate is
// binding.issuerCertificate, or returns "" when it does. The chain is
// validated to a configured anchor afterwards either way.
//
// draft-ietf-oauth-status-list-21 Section 11.3 "does not mandate specific
// methods for key resolution and trust management" and recommends three
// links, each of which binds the token here:
//
//   - The Status Issuer is the credential's issuer and signs with "the same
//     key that is embedded into the Referenced Token": the leaf has the issuer
//     certificate's public key.
//   - The leaf names the same issuer: it has the issuer certificate's subject,
//     because the Issuer of an x5c credential is its leaf subject (SD-JWT VC
//     -19 Section 2.5). An empty subject (no RDNs, as a certificate that names
//     its holder only in a subject alternative name has) identifies nobody,
//     and two such certificates would match each other.
//   - The Status Issuer is another entity whose key is "cryptographically
//     linked ... by a Certificate Authority through an x.509 PKI": the two
//     certificates "should be issued by the same Certificate Authority". The
//     leaf and the issuer certificate name the same issuer and the same
//     non-empty authority key identifier (RFC 5280 Section 4.2.1.1), which
//     their issuing CA signed into each.
//
// When no link holds and either subject is empty, the leaf is accepted only
// when it names the issuer URL's host (binding.issuerURL is set and
// RequireLeafNamesIssuer has already held); a credential without iss has no
// such name, and its token is refused. Section 11.3 also says the Status
// Issuer's certificate "should utilize extended key usage (Section 10)", but
// draft -21 leaves that key purpose's OID unassigned (id-kp TBD), so no
// extended key usage is required here; X5CTrust.KeyUsages lets an ecosystem
// that assigns one require it.
func (b x5cBinding) issuerCertificateFailure(leaf *x509.Certificate) string {
	if samePublicKey(leaf.PublicKey, b.issuerCertificate.PublicKey) {
		return ""
	}
	if sameIssuingAuthority(leaf, b.issuerCertificate) {
		return ""
	}
	if emptySubject(leaf) || emptySubject(b.issuerCertificate) {
		if b.issuerURL != nil {
			return ""
		}
		return "certificate subject is empty and does not identify the credential issuer"
	}
	if !bytes.Equal(leaf.RawSubject, b.issuerCertificate.RawSubject) {
		return "certificate is neither the credential issuer's nor issued by the credential issuer's certificate authority"
	}
	return ""
}

// sameIssuingAuthority reports whether a and b were issued by the same
// certificate authority: the same issuer name and the same authority key
// identifier, which must be present.
func sameIssuingAuthority(a, b *x509.Certificate) bool {
	return len(a.AuthorityKeyId) > 0 &&
		bytes.Equal(a.AuthorityKeyId, b.AuthorityKeyId) &&
		bytes.Equal(a.RawIssuer, b.RawIssuer)
}

// samePublicKey reports whether a and b are the same public key.
func samePublicKey(a, b crypto.PublicKey) bool {
	key, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && b != nil && key.Equal(b)
}

// emptySubject reports whether certificate's subject has no RDN. A subject
// that does not parse is treated as empty: it identifies nobody either.
func emptySubject(certificate *x509.Certificate) bool {
	var rdns pkix.RDNSequence
	rest, err := asn1.Unmarshal(certificate.RawSubject, &rdns)
	return err != nil || len(rest) != 0 || len(rdns) == 0
}

func trustIssuerCertificate(trust *X5CTrust) *x509.Certificate {
	if trust == nil {
		return nil
	}
	return trust.IssuerCertificate
}

// statusListX5CRoute validates the token's x5c chain and returns its leaf key
// as the only candidate. A chain that is not trusted records the reason on the
// `x5c` diagnostic and returns no candidate (StatusListKeys turns that into an
// *UnresolvedError, wrapping chainErr when there is one); a profile refusal
// or a revocation refusal is returned as the error.
func (r *Resolver) statusListX5CRoute(ctx context.Context, resolution *Resolution, trust *X5CTrust, rules profile.X5CRules, chain []string, binding x5cBinding) ([]Candidate, error) {
	diagnostic := MechanismDiagnostic{Mechanism: RungX5C}
	untrusted := func(failure string, chainErr error) ([]Candidate, error) {
		diagnostic.Failure = failure
		resolution.Diagnostics = append(resolution.Diagnostics, diagnostic)
		if chainErr == nil {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %w", &UnresolvedError{Diagnostics: resolution.Diagnostics}, chainErr)
	}
	switch {
	case len(chain) == 0:
		return untrusted("not present", nil)
	case !r.Mechanisms.X5C:
		diagnostic.DisabledBy = []string{SwitchX5C}
		return untrusted(failureDisabled, nil)
	case trust == nil || len(trust.TrustAnchors) == 0:
		return untrusted(failureChainUntrusted, nil)
	}
	diagnostic.Attempted = true

	certificates, err := commonX509.DecodeX5CChain(chain)
	if err != nil {
		return untrusted("certificate chain is malformed", err)
	}
	if rules.RejectSelfSigned {
		// HAIP 1.0 Section 6.1: "The X.509 certificate signing the request
		// MUST NOT be self-signed."
		if err := commonX509.RequireNonSelfSignedLeaf(certificates, "status list token"); err != nil {
			return nil, fmt.Errorf("%w: %w", statuslist.ErrStatusListCertificateRejected, err)
		}
	}
	if rules.ExcludeAnchor {
		// HAIP 1.0 Section 6.1: "The X.509 certificate of the trust anchor
		// MUST NOT be included in the x5c JOSE header of the Status List
		// Token."
		containsAnchor, err := commonX509.ContainsTrustAnchor(certificates, trust.TrustAnchors, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", statuslist.ErrStatusListCertificateRejected, err)
		}
		if containsAnchor {
			return nil, fmt.Errorf("%w: the x5c header includes a trust anchor certificate", statuslist.ErrStatusListCertificateRejected)
		}
	}
	// draft-ietf-oauth-status-list-21 Section 11.3 "does not mandate
	// specific methods for key resolution and trust management", so the leaf
	// of a chain that reaches a trust anchor is accepted unless the profile
	// asks for the binding it recommends (RequireStatusListSignerBinding).
	// The binding is checked before the path is walked: it needs no network,
	// and a chain for another issuer must not cost a CRL retrieval.
	if binding.required {
		if failure := binding.failure(certificates[0]); failure != "" {
			return untrusted(failure, nil)
		}
	}

	now := r.now
	if trust.Now != nil {
		now = trust.Now
	}
	crlClient := trust.HTTPClient
	if crlClient == nil {
		crlClient = r.HTTPClient
	}
	if crlClient == nil {
		crlClient = defaultHTTPClient
	}
	result, err := commonX509.VerifySigningChainWithPolicy(ctx, certificates, commonX509.SigningChainPolicy{
		TrustAnchors:                trust.TrustAnchors,
		KeyUsages:                   trust.KeyUsages,
		CRL:                         trust.CRL,
		AllowUnadvertisedRevocation: trust.AllowUnadvertisedRevocation,
		CurrentTime:                 now(),
		HTTPClient:                  crlClient,
	})
	if err != nil {
		if errors.Is(err, commonX509.ErrNoTrustAnchor) {
			return untrusted(failureChainUntrusted, err)
		}
		return nil, err
	}
	leaf, ok := publicKey(jose.JSONWebKey{Key: certificates[0].PublicKey})
	if !ok {
		return untrusted("certificate key is not usable", nil)
	}
	diagnostic.CandidateCount = 1
	resolution.Diagnostics = append(resolution.Diagnostics, diagnostic)
	return []Candidate{{
		Key:               leaf,
		Issuer:            binding.issuer,
		Mechanism:         MechanismX5CTrustedChain,
		CertificateSHA256: result.Fingerprints,
	}}, nil
}

// statusListDIDRoute resolves a DID issuer's keys and binds them to the
// Credential Issuer through a DIF Well Known DID Configuration (OpenID4VCI 1.0
// Section 14.4, item 1), whatever the credential's format.
func (r *Resolver) statusListDIDRoute(ctx context.Context, resolution *Resolution, lookup Request) ([]Candidate, error) {
	diagnostic := MechanismDiagnostic{Mechanism: RungDID}
	finish := func(failure string) ([]Candidate, error) {
		diagnostic.Failure = failure
		resolution.Diagnostics = append(resolution.Diagnostics, diagnostic)
		return nil, nil
	}
	didValue := lookup.Issuer
	if kidDID := didReference(lookup.KeyID); kidDID != "" && kidDID != didValue {
		return finish("kid names a DID other than the issuer")
	}
	switchName, supported := didMethodSwitch(didValue)
	if !supported {
		return finish("DID method is not supported")
	}
	if !r.didMethodAllowed(didValue) {
		diagnostic.DisabledBy = []string{switchName}
		return finish(failureDisabled)
	}
	diagnostic.Attempted = true
	keys, err := r.resolveDIDKeys(ctx, didValue, lookup.KeyID, lookup.CredentialIssuer)
	if err != nil {
		return finish(failureReason(err))
	}
	const unbound = "DID is not bound to the credential issuer by a DID Configuration"
	if !r.Mechanisms.DIDConfiguration {
		diagnostic.Failure = unbound
		diagnostic.DisabledBy = []string{SwitchDIDConfiguration}
		resolution.Diagnostics = append(resolution.Diagnostics, diagnostic)
		return nil, &DIDOnlyTrustError{Diagnostics: resolution.Diagnostics}
	}
	// A DID Configuration that cannot be retrieved or does not verify simply
	// does not bind; the caller is told the DID was unbound, which is the
	// accurate statement either way.
	if bound, _ := r.didConfigurationBinds(ctx, didValue, lookup); !bound {
		diagnostic.Failure = unbound
		resolution.Diagnostics = append(resolution.Diagnostics, diagnostic)
		return nil, &DIDOnlyTrustError{Diagnostics: resolution.Diagnostics}
	}
	candidates := make([]Candidate, 0, len(keys))
	for _, key := range keys {
		candidates = append(candidates, Candidate{
			Key:       key,
			Issuer:    didValue,
			Mechanism: MechanismDIDConfigurationBinding,
			DID:       didValue,
		})
	}
	diagnostic.CandidateCount = len(candidates)
	resolution.Diagnostics = append(resolution.Diagnostics, diagnostic)
	return candidates, nil
}
