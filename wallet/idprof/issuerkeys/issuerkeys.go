// Package issuerkeys resolves the public keys a credential issuer may have
// signed a credential with, by the key discovery and validation mechanisms the
// specifications define for the credential's issuer identifier.
//
// SD-JWT VC -19 §2.5 requires the recipient to "determine and validate the
// public verification key ... using a supported key discovery and validation
// mechanism that is permitted for the given Issuer according to policy", and
// §7.3 requires that "for any given iss value, an attacker cannot influence
// the type of verification process used". So the mechanism follows from the
// form of `iss`, never from a fall-through between mechanisms:
//
//   - an https `iss` of an SD-JWT VC resolves through JWT VC Issuer Metadata
//     at /.well-known/jwt-vc-issuer (SD-JWT VC -19 §4);
//   - a DID `iss` resolves through its DID document (W3C DID Core), and the
//     key is accepted only when a DIF Well Known DID Configuration served by
//     the Credential Issuer's origin links that origin to the DID (OpenID4VCI
//     1.0 §14.4).
//
// An `x5c` certification path (SD-JWT VC -19 §2.5, "Inline X.509
// Certificates") is not resolved here: the credential acceptor
// (wallet/acceptance) validates it against its trust anchors. The `x5c` rung
// of this package only reports the DNS name such a path must be bound to;
// Resolver.StatusListKeys walks the path of a Status List Token itself
// (statuslistkeys.go). OpenID Federation keys come from a Trust
// Chain and are handled by the acceptor too (acceptance.FederationIssuerKeys).
//
// A caller reads Resolution.Candidates front to back and stops at the first key
// that verifies the signature. Every candidate is attributed to the credential's
// `iss` (Candidate.Issuer equals Request.Issuer), and no key whose JWK `use` is
// other than "sig" is a candidate.
//
// Nothing here verifies a signature, walks a certification path, or decides
// whether an issuer is acceptable. It answers one question - which keys is it
// worth trying - and reports, for each key, which mechanism produced it, so the
// caller can decide what that mechanism is worth.
package issuerkeys

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/experimental"
)

// Credential formats this package knows how to resolve keys for. They decide
// which rungs apply: /.well-known/jwt-vc-issuer is defined for the SD-JWT VC
// family only.
const (
	// FormatSDJWTVC is the SD-JWT VC media type OpenID4VCI 1.0 issues with.
	FormatSDJWTVC = "dc+sd-jwt"
	// FormatSDJWTVCDraft is the SD-JWT VC format identifier of OpenID4VCI
	// Draft 13, whose issuers still use it.
	FormatSDJWTVCDraft = "vc+sd-jwt"
	// FormatJWTVCJSON is the W3C Verifiable Credential secured as a JWT.
	FormatJWTVCJSON = "jwt_vc_json"
	// FormatLDPVC is the W3C Verifiable Credential secured with Data Integrity.
	FormatLDPVC = "ldp_vc"
)

// Mechanism names how a candidate key was obtained. It travels with the key so
// that a caller which accepts, records or displays a verified credential can
// say what the issuer's identity rests on.
type Mechanism string

const (
	// MechanismJWTVCIssuerMetadata: the key came from the JWT VC Issuer
	// Metadata document the IETF SD-JWT VC specification places at
	// /.well-known/jwt-vc-issuer under the Issuer identifier (-19 §4).
	MechanismJWTVCIssuerMetadata Mechanism = "jwt_vc_issuer_metadata_jwks"
	// MechanismDIDConfigurationBinding: the key came from a DID document, and a
	// DIF Well Known DID Configuration served by the Credential Issuer's origin
	// links that origin to the DID (OpenID4VCI 1.0 §14.4).
	MechanismDIDConfigurationBinding Mechanism = "did_configuration_binding"
	// MechanismX5CTrustedChain: the key is the public key of the `x5c` leaf
	// certificate, and the certification path reached one of the caller's trust
	// anchors (SD-JWT VC -19 §2.5). Resolve never produces it - it does not
	// walk certification paths - but Resolver.StatusListKeys does, and the
	// credential acceptor reports the same name for the same evidence.
	MechanismX5CTrustedChain Mechanism = "x5c_trusted_chain"
	// MechanismOpenIDFederation: the key is in the jwks of the Entity Type
	// metadata derived from an OpenID Federation Trust Chain (OpenID
	// Federation 1.0 §5.2.1, §6.1.4). Resolve never produces it; the credential
	// acceptor reports it for acceptance.FederationIssuerKeys.
	MechanismOpenIDFederation Mechanism = "openid_federation_entity_jwks"
)

// Candidate is one public key the issuer may have signed with.
type Candidate struct {
	// Key is the public key to try.
	Key jose.JSONWebKey
	// Issuer is the identifier the signature's `iss` must equal for this key to
	// be the right one: the DID for a key a DID document produced, the https
	// Issuer identifier for a key JWT VC Issuer Metadata produced.
	Issuer string
	// Mechanism names how this key was obtained.
	Mechanism Mechanism
	// DID is the decentralized identifier the key came from, empty for a key
	// that came from anywhere else.
	DID string
	// CertificateSHA256 holds the hex SHA-256 fingerprints of the validated
	// certification path, leaf first and ending at the trust anchor it reached.
	// It is set only for MechanismX5CTrustedChain.
	CertificateSHA256 []string
}

// MechanismDiagnostic reports what one rung of the ladder did.
//
// Every rung produces one, including the rungs that were not applicable and the
// rungs a configuration switched off, so a caller can explain a failed
// resolution without reconstructing which mechanisms would have applied.
type MechanismDiagnostic struct {
	// Mechanism is the rung's name: RungX5C, RungJWTVCIssuerMetadata or
	// RungDID.
	Mechanism string
	// Attempted reports whether the rung did any work, as opposed to being
	// inapplicable or switched off.
	Attempted bool
	// CandidateCount is the number of candidates the rung produced. The `x5c`
	// rung reports 1 when it produced a usable chain, though it contributes no
	// candidate key.
	CandidateCount int
	// Failure is a short description of why the rung produced nothing, empty
	// when it produced candidates. It is authored by this package from a fixed
	// vocabulary and never carries key material, a response body or a URL.
	Failure string
	// DisabledBy names the Mechanisms fields (the Switch constants) whose false
	// value kept this rung, a DID method inside it, or a binding it needed from
	// doing its work, so a caller can tell a switched-off mechanism from one
	// the credential gave nothing to work with. It is empty when no switch was
	// involved.
	DisabledBy []string
}

// Rung names, as they appear in MechanismDiagnostic.Mechanism.
const (
	// RungX5C is the `x5c` header rung.
	RungX5C = "x5c header"
	// RungJWTVCIssuerMetadata is the /.well-known/jwt-vc-issuer rung.
	RungJWTVCIssuerMetadata = "jwt-vc-issuer metadata"
	// RungDID is the DID document rung.
	RungDID = "DID"
)

// Switch names, as they appear in MechanismDiagnostic.DisabledBy. Each is the
// name of the Mechanisms field it reports.
const (
	SwitchX5C                 = "X5C"
	SwitchJWTVCIssuerMetadata = "JWTVCIssuerMetadata"
	SwitchRemoteJWKS          = "RemoteJWKS"
	SwitchDIDKey              = "DIDKey"
	SwitchDIDJWK              = "DIDJWK"
	SwitchDIDWeb              = "DIDWeb"
	SwitchDIDConfiguration    = "DIDConfiguration"
)

// failureDisabled is the Failure a rung records when a switch kept it from
// doing its work. DisabledBy says which switch.
const failureDisabled = "disabled by configuration"

// Request describes the credential whose issuer key is being resolved.
type Request struct {
	// Issuer is the credential JWT `iss`.
	Issuer string
	// KeyID is the credential JWT `kid`, empty when the header carries none.
	KeyID string
	// Algorithm is the credential JWT `alg`.
	Algorithm string
	// X5C is the credential JWT `x5c`: base64-encoded DER certificates, the
	// leaf first (RFC 7515 section 4.1.6).
	X5C []string
	// CredentialFormat is the format the credential was issued in, one of
	// FormatSDJWTVC, FormatSDJWTVCDraft, FormatJWTVCJSON or FormatLDPVC.
	CredentialFormat string
	// CredentialIssuer is the OpenID4VCI 1.0 Credential Issuer identifier of
	// the issuance this credential came from. A DID Configuration binds a DID
	// to its origin.
	CredentialIssuer string
}

// Resolution is the outcome of one ladder run.
type Resolution struct {
	// Candidates are the keys to try, in ladder order: the mechanism carrying
	// the most evidence first.
	Candidates []Candidate
	// Diagnostics reports one entry per rung, in ladder order.
	Diagnostics []MechanismDiagnostic
	// IssuerDNSName is the host a trusted x5c chain must be bound to, empty
	// when the credential carries no usable x5c or no URL issuer.
	IssuerDNSName string
}

// Mechanisms is the set of key-resolution mechanisms a Resolver may consult.
//
// The zero value enables none. That is the point: each of these mechanisms
// puts a different amount of trust in a different party, and several of them
// cause an outbound request that tells a third party a credential is being
// verified. A deployment that refuses one says so here, in one place, rather
// than by omitting a call somewhere in its own code. A switch only narrows:
// which mechanism applies to a credential follows from its `iss`, and turning
// a switch on never makes a mechanism apply to an `iss` it is not defined for.
type Mechanisms struct {
	// X5C allows the `x5c` header rung to report the DNS name a certification
	// path must be bound to, and Resolver.StatusListKeys to take a Status List
	// Token's key from its x5c chain.
	X5C bool
	// JWTVCIssuerMetadata allows the IETF SD-JWT VC key resolution mechanism at
	// /.well-known/jwt-vc-issuer.
	JWTVCIssuerMetadata bool
	// RemoteJWKS allows a `jwks_uri` in JWT VC Issuer Metadata to be followed.
	// It is separate from JWTVCIssuerMetadata because following it is a second
	// request, to a location the first document chose.
	RemoteJWKS bool
	// DIDKey allows did:key identifiers to be resolved.
	DIDKey bool
	// DIDJWK allows did:jwk identifiers to be resolved.
	DIDJWK bool
	// DIDWeb allows did:web identifiers to be resolved, which means retrieving
	// a DID document over the network.
	DIDWeb bool
	// DIDConfiguration allows a DIF Well Known DID Configuration served by the
	// Credential Issuer's origin to bind a DID to that origin. It is the only
	// binding a DID key is accepted with, so a DID method switch without it
	// resolves keys that are then refused (*DIDOnlyTrustError).
	DIDConfiguration bool
}

// DIDResolver resolves a DID to its verification keys.
//
// An implementation is not asked whether the DID may be trusted for a
// particular issuer: that is the Resolver's decision, and it is made after
// resolution, from the bindings the ladder can check.
type DIDResolver interface {
	// Resolve returns the verification keys of did, retrieving whatever the
	// method requires within ctx. Each key should carry its verification
	// method identifier as its KeyID, and for a method whose document names
	// verification relationships, only the `assertionMethod` keys should be
	// returned.
	Resolve(ctx context.Context, did string) (*jose.JSONWebKeySet, error)
}

// Resolver resolves issuer keys. Every mechanism it may consult is switched on
// explicitly, so a deployment that refuses one of them says so in one place.
//
// A Resolver holds no per-credential state and is safe for concurrent use as
// long as the HTTPClient and DIDResolver it was given are.
type Resolver struct {
	// HTTPClient retrieves metadata documents. A nil value uses a client with a
	// 30 second timeout. The client's redirect policy is never used: the
	// resolver refuses redirects.
	HTTPClient *http.Client
	// MaxDocumentBytes bounds every retrieved document. A value of zero or less
	// uses 64 KiB.
	MaxDocumentBytes int64
	// Experimental.AllowHTTP admits plain http metadata URLs for a local test
	// origin (package experimental). The zero value conforms: SD-JWT VC -19
	// §3 says "All URLs dereferenced according to this specification MUST use
	// the HTTPS scheme". A profile with
	// profile.Options.ForbidExperimental (HAIP) refuses a Resolver that
	// sets it: the credential acceptor (acceptance.NewAcceptor) and
	// StatusListKeys under a Status List checker of such a profile fail
	// instead of resolving.
	//
	// The resolver checks the scheme and the shape of every URL it requests,
	// not where the host resolves to: which networks an outbound request may
	// reach (public addresses only, say) is a property of the deployment and
	// belongs in HTTPClient's dialer.
	Experimental experimental.Transport
	// Now reports the current time, for the validity window of a DID
	// Configuration's Domain Linkage Credential. A nil value uses time.Now.
	Now func() time.Time
	// Mechanisms selects which rungs may be attempted. The zero value attempts
	// none, so a caller names what it accepts.
	Mechanisms Mechanisms
	// DID resolves DID documents. A nil value uses a dispatcher configured with
	// the library's did:key, did:jwk and did:web plugins.
	DID DIDResolver
}

// Resolve runs the mechanisms for request.
//
// It returns an error only for a condition that must stop the caller rather
// than merely narrow its options:
//
//   - a *DIDOnlyTrustError (errors.Is(err, ErrDIDOnlyTrustUnsupported)), when
//     a DID resolved to a key but no DID Configuration binds that DID to the
//     Credential Issuer. The credential is signed by someone who controls a
//     DID and claims to be this issuer, which is a different situation from
//     "no key was found".
//   - an *UnresolvedError (errors.Is(err, ErrNoIssuerKeyResolved)) carrying
//     the diagnostics, when no mechanism produced a candidate.
//   - ctx's error, when ctx ended before a candidate was produced.
//
// Every other failure belongs to one rung and is recorded in that rung's
// diagnostic.
func (r *Resolver) Resolve(ctx context.Context, request Request) (*Resolution, error) {
	resolution, err := r.resolve(ctx, request)
	if err != nil {
		return nil, err
	}
	if len(resolution.Candidates) == 0 {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, &UnresolvedError{Diagnostics: resolution.Diagnostics}
	}
	return resolution, nil
}

// resolve runs every rung and returns what they produced, including a
// resolution with no candidate, which Resolve turns into an *UnresolvedError.
// The empty resolution still carries what the `x5c` rung contributes - a DNS
// name rather than a key - and a caller that walks the chain may still end up
// with a key when the rungs produced none.
//
// At most one of the key rungs applies to a given `iss`: the JWT VC Issuer
// Metadata rung to an https URL, the DID rung to a DID.
func (r *Resolver) resolve(ctx context.Context, request Request) (*Resolution, error) {
	resolution := &Resolution{}
	chain := x5cChain(request.X5C)

	issuerDNSName, x5cDiagnostic := r.x5cRung(request, chain)
	resolution.IssuerDNSName = issuerDNSName
	resolution.Diagnostics = append(resolution.Diagnostics, x5cDiagnostic)

	jwtVCCandidates, jwtVCDiagnostic := r.jwtVCIssuerRung(ctx, request)
	resolution.Candidates = append(resolution.Candidates, jwtVCCandidates...)
	resolution.Diagnostics = append(resolution.Diagnostics, jwtVCDiagnostic)

	didCandidates, didDiagnostic, err := r.didRung(ctx, request)
	resolution.Diagnostics = append(resolution.Diagnostics, didDiagnostic)
	if err != nil {
		return resolution, &DIDOnlyTrustError{Diagnostics: slices.Clone(resolution.Diagnostics)}
	}
	resolution.Candidates = append(resolution.Candidates, didCandidates...)
	return resolution, nil
}

// isSDJWTVC reports whether format is one of the SD-JWT VC format
// identifiers: dc+sd-jwt, or vc+sd-jwt of OpenID4VCI Draft 13.
func isSDJWTVC(format string) bool {
	return format == FormatSDJWTVC || format == FormatSDJWTVCDraft
}

// x5cRung is rung 1. It produces no candidate key: the certification path is
// the answer, and validating it against trust anchors is the caller's.
//
// What it contributes is the DNS name the path must be bound to: the host of
// an https Issuer identifier. W3C JWT VC has no such rule of its own, so the
// binding this rung can check is that the signer claims to be the Credential
// Issuer.
func (r *Resolver) x5cRung(request Request, chain []string) (string, MechanismDiagnostic) {
	diagnostic := MechanismDiagnostic{Mechanism: RungX5C}
	switch {
	case !isSDJWTVC(request.CredentialFormat) && request.CredentialFormat != FormatJWTVCJSON:
		diagnostic.Failure = "not applicable for this credential format"
	case !r.Mechanisms.X5C:
		diagnostic.Failure = failureDisabled
		diagnostic.DisabledBy = []string{SwitchX5C}
	case len(chain) == 0:
		diagnostic.Failure = "not present"
	case request.Issuer == "":
		diagnostic.Failure = "x5c issuer proof requires an issuer"
	case request.CredentialFormat == FormatJWTVCJSON && request.Issuer != request.CredentialIssuer:
		diagnostic.Failure = "issuer must match credential issuer metadata"
	default:
		issuerURL, err := r.allowedURL(request.Issuer)
		if err != nil {
			diagnostic.Failure = failureReason(err)
			return "", diagnostic
		}
		diagnostic.Attempted = true
		diagnostic.CandidateCount = 1
		return issuerURL.Hostname(), diagnostic
	}
	return "", diagnostic
}

// didReference reports the DID a `kid` or an `iss` names, or the empty string
// when it names none. A DID URL's fragment identifies a verification method
// within the document, so the DID is everything before the first "#".
func didReference(value string) string {
	did, _, _ := strings.Cut(value, "#")
	if !strings.HasPrefix(did, "did:") {
		return ""
	}
	return did
}
