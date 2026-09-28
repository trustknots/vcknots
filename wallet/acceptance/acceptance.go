// Package acceptance decides whether a received credential may be stored: it
// authenticates the issuer key by a mechanism the specifications define for
// the credential's issuer identifier, verifies the issuer signature (for an
// ldp_vc, its eddsa-rdfc-2022 Data Integrity proof), checks the cnf holder
// binding, the validity period and SD-JWT disclosure integrity. It needs no
// wallet or credential store.
package acceptance

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credential/dataintegrity"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/idprof/issuerkeys"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// Policy decides how the issuer of a credential is authenticated and which
// further checks apply.
//
// The issuer key is established by the mechanism that the credential's
// issuer identifier and its x5c header select (SD-JWT VC -19 §2.5 and §7.3:
// "for any given iss value, an attacker cannot influence the type of
// verification process used"). The policy only says which of those
// mechanisms it permits; a mechanism it does not permit refuses the
// credential, and no other mechanism is tried in its place:
//
//   - An x5c header is authenticated by the certificate chain alone
//     (IssuerX509). A chain that is not trusted refuses the credential. The
//     Issuer is the subject of the leaf certificate (SD-JWT VC -19 §2.5). An
//     iss beside the x5c must be an https URL whose host the leaf names in a
//     dNSName or URI subject alternative name; a DID iss is refused (a DID
//     issuer is authenticated by its DID document, so its credential carries
//     no x5c), as is any other iss.
//   - Otherwise an https iss is authenticated by JWT VC Issuer Metadata
//     (SD-JWT VC -19 §4, SD-JWT VC only; IssuerKeys) or by the keys of an
//     OpenID Federation Trust Chain for that Entity (Federation).
//   - Otherwise a DID iss is authenticated by its DID document, bound to the
//     Credential Issuer's origin by a DIF Well Known DID Configuration
//     (OpenID4VCI 1.0 §14.4; IssuerKeys).
//   - A credential with neither an x5c nor an https or DID iss is refused.
//
// Under a profile with IssuerX5C.Require (HAIP 1.0 §6.1.1) an SD-JWT VC must
// carry x5c.
type Policy struct {
	// IssuerX509 permits the x5c mechanism (SD-JWT VC -19 §2.5, "Inline X.509
	// Certificates") and says which chains are trusted. Nil refuses every
	// credential that carries x5c.
	IssuerX509 *IssuerX509TrustOptions
	// IssuerKeys permits the JWT VC Issuer Metadata and DID mechanisms that its
	// Mechanisms switch on. The acceptor fills the issuerkeys.Request itself:
	// Issuer, KeyID and Algorithm from the credential, CredentialFormat from
	// the serialization, CredentialIssuer from Options.CredentialIssuer. Nil
	// permits neither.
	IssuerKeys *issuerkeys.Resolver
	// Federation permits OpenID Federation for an https iss equal to its
	// Entity Identifier: the keys of the openid_credential_issuer metadata a
	// validated Trust Chain derives. Build it with NewFederationIssuerKeys.
	Federation *FederationIssuerKeys
	// RequireHolderBinding refuses a credential without cnf, and one with cnf
	// when no holder key is supplied to compare it with.
	RequireHolderBinding bool
	// SigningAlgorithms lists the JWS algs an issuer may use. Empty means
	// DefaultSigningAlgorithms(). A verifier plugin must also implement the
	// algorithm. An ldp_vc is verified with eddsa-rdfc-2022 only.
	SigningAlgorithms []jose.SignatureAlgorithm
	// DataIntegrityContexts pins the JSON-LD contexts an ldp_vc may name;
	// verifying its Data Integrity proof needs them, and none is fetched (see
	// package credential/dataintegrity).
	DataIntegrityContexts dataintegrity.PinnedContexts
	// ExpectedSDJWTVCType, when set, is the vct the credential must carry.
	ExpectedSDJWTVCType string
	// Now is the verification clock; nil means time.Now.
	Now func() time.Time
	// ClockSkew is the tolerance applied to exp and nbf.
	ClockSkew time.Duration
}

// IssuerX509TrustOptions configures how an issuer x5c chain is validated.
type IssuerX509TrustOptions struct {
	TrustAnchors                []*x509.Certificate
	RootCAs                     *x509.CertPool     // exactly one of TrustAnchors / RootCAs
	CertificateKeyUsages        []x509.ExtKeyUsage // optional ecosystem EKU policy
	CRL                         commonX509.CRLCheckerOptions
	AllowUnadvertisedRevocation bool         // see commonX509.SigningChainPolicy.AllowUnadvertisedRevocation
	HTTPClient                  *http.Client // CRL fetches; nil uses a bounded default
	// Experimental.AllowHTTP binds an http iss to the leaf certificate by its
	// host, as an https iss is, for a local test issuer. Without it an x5c
	// credential whose iss is not an https URL is refused. A profile with
	// ForbidExperimental (HAIP) refuses it. Not
	// specification-conforming; for testing only.
	Experimental experimental.Transport
}

// Options are the per-call inputs of Acceptor.Verify and Acceptor.Parse.
type Options struct {
	// Flavor is the serialization of the raw credential. Empty infers SD-JWT
	// VC from a "~" separator and JWT VC otherwise.
	Flavor credential.SupportedSerializationFlavor
	// HolderKey is compared with cnf.jwk. Without it a cnf cannot be checked,
	// so Policy.RequireHolderBinding refuses the credential.
	HolderKey *jose.JSONWebKey
	// CredentialIssuer is the OpenID4VCI Credential Issuer Identifier of the
	// issuance the credential came from. The DID mechanism binds a DID iss to
	// its origin through a DID Configuration (OpenID4VCI 1.0 §14.4), so a DID
	// issuer is refused without it. The wallet sets it from the issuance.
	CredentialIssuer string
}

// Verification records what was verified.
type Verification struct {
	IssuerKeyID            string   // kid of the key used, or the leaf certificate SHA-256 fingerprint
	CertificateSHA256      []string // x5c path fingerprints, leaf first; nil when no x5c
	RevocationChecked      int
	RevocationUnadvertised int
	HolderBound            bool // cnf present and matched the holder key
	// IssuerKey is the public key the signature verified under; nil when no
	// issuer was authenticated (Parse).
	IssuerKey *jose.JSONWebKey
	// Issuer is the authenticated Issuer of the credential. For the x5c
	// mechanism it is always the subject distinguished name of the leaf
	// certificate (SD-JWT VC -19 §2.5: "the Issuer of the Verifiable Digital
	// Credential is the subject of the end-entity certificate"), whatever iss
	// says; for every other mechanism it is the iss (the issuer of an ldp_vc)
	// the key was established for. Empty after Parse.
	Issuer string
	// ClaimedIssuer is the iss the credential carries (the issuer of an
	// ldp_vc), empty when it carries none. For the x5c mechanism it is what
	// the leaf certificate was bound to (IssuerDNSBound), not the
	// authenticated identity itself; for every other mechanism it equals
	// Issuer. Empty after Parse.
	ClaimedIssuer string
	// Mechanism names how the issuer key was established:
	// issuerkeys.MechanismX5CTrustedChain, MechanismJWTVCIssuerMetadata,
	// MechanismDIDConfigurationBinding or MechanismOpenIDFederation. Empty
	// after Parse.
	Mechanism issuerkeys.Mechanism
	// IssuerCertificateSubject is the leaf certificate's subject and subject
	// alternative names for the x5c mechanism; nil otherwise.
	IssuerCertificateSubject *CertificateSubject
	// IssuerDNSBound reports that the credential carries an iss and the leaf
	// certificate names its host in a dNSName or URI subject alternative name.
	// An x5c credential with an iss is accepted only then; false for an x5c
	// credential without iss and for every other mechanism.
	IssuerDNSBound bool
	// DID is the DID the issuer key came from, for the DID mechanism.
	DID string
	// FederationTrustAnchor is the Entity Identifier of the Trust Anchor the
	// Trust Chain ended at, for the OpenID Federation mechanism.
	FederationTrustAnchor string
}

// CertificateSubject is the identity an X.509 certificate states.
type CertificateSubject struct {
	// Subject is the subject distinguished name in RFC 4514 form.
	Subject string
	// DNSNames, URIs and EmailAddresses are the subject alternative names.
	DNSNames       []string
	URIs           []string
	EmailAddresses []string
}

// DefaultSigningAlgorithms returns the issuer algorithms accepted when
// Policy.SigningAlgorithms is empty: ES256, which HAIP §7 requires every
// wallet to support. The result is a fresh copy.
func DefaultSigningAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}

// AcceptedSDAlgorithms returns the accepted SD-JWT _sd_alg values (SD-JWT
// §4.1.1 hash names). "sha-256" applies when _sd_alg is absent. The result is
// a fresh copy.
func AcceptedSDAlgorithms() []string {
	return []string{"sha-256", "sha-384", "sha-512"}
}

// Acceptor runs the acceptance checks. It is safe for concurrent use.
type Acceptor struct {
	x5c profile.X5CRules
	// draft13 admits the SD-JWT VC typ of OpenID4VCI Draft 13, vc+sd-jwt.
	draft13 bool
	// forbidInsecure refuses an IssuerKeys resolver with Experimental set
	// (profile.Options.ForbidExperimental).
	forbidInsecure bool
	serializer     *serializer.SerializationDispatcher
	verifier       *verifier.VerificationDispatcher
}

// NewAcceptor builds an Acceptor that applies the credential rules of p, the
// profile the credential is issued under: the Options of an OpenID4VCI 1.0
// profile (IssuerX5C, HAIP 1.0 §6.1.1), and for profile.Draft13 the SD-JWT VC
// typ vc+sd-jwt that Draft 13 issuers use. Under every other profile an
// SD-JWT VC must carry typ dc+sd-jwt (SD-JWT VC -19 §2.2.1). The serializer
// and verifier are required.
func NewAcceptor(p profile.Profile, s *serializer.SerializationDispatcher, v *verifier.VerificationDispatcher) (*Acceptor, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: acceptance requires a serialization dispatcher", common.ErrInvalidInput)
	}
	if v == nil {
		return nil, fmt.Errorf("%w: acceptance requires a verification dispatcher", common.ErrInvalidInput)
	}
	options := p.Options()
	return &Acceptor{
		x5c:            options.IssuerX5C,
		draft13:        p == profile.Draft13(),
		forbidInsecure: options.ForbidExperimental,
		serializer:     s,
		verifier:       v,
	}, nil
}

// Verify applies policy to raw and returns the parsed credential and what was
// verified. It stores nothing. ctx bounds CRL retrieval. Failures wrap the
// sentinels of this package.
func (a *Acceptor) Verify(ctx context.Context, raw []byte, policy Policy, opts Options) (*credential.Credential, *Verification, error) {
	if a.forbidInsecure && policy.IssuerKeys != nil && policy.IssuerKeys.Experimental != (experimental.Transport{}) {
		// SD-JWT VC -19 §3 and HAIP 1.0 §4: key material over TLS only.
		return nil, nil, fmt.Errorf("%w: the profile forbids an issuer key resolver with Experimental.Transport", common.ErrInvalidInput)
	}
	if a.forbidInsecure && policy.IssuerX509 != nil && policy.IssuerX509.Experimental != (experimental.Transport{}) {
		return nil, nil, fmt.Errorf("%w: the profile forbids IssuerX509.Experimental", common.ErrInvalidInput)
	}
	return a.run(ctx, raw, opts, &policy)
}

// Parse deserializes raw and applies only the checks that need no policy: the
// issuer JWT header (typ, alg, HAIP x5c presence) and, when opts.HolderKey is
// set, the cnf binding. It authenticates no issuer and checks neither exp/nbf
// nor disclosure integrity; use Verify before storing a credential.
func (a *Acceptor) Parse(raw []byte, opts Options) (*credential.Credential, *Verification, error) {
	return a.run(context.Background(), raw, opts, nil)
}

// run is Verify with a nil policy meaning Parse.
func (a *Acceptor) run(ctx context.Context, raw []byte, opts Options, policy *Policy) (*credential.Credential, *Verification, error) {
	flavor := opts.Flavor
	if flavor == "" {
		flavor = inferredFlavor(raw)
	}
	if flavor == credential.LdpVc {
		return a.runDataIntegrity(ctx, raw, opts, policy)
	}
	header, err := IssuerSignedJOSEHeader(flavor, raw)
	if err != nil {
		return nil, nil, err
	}
	jwtParts := strings.Split(issuerSignedJWT(flavor, raw), ".")
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: issuer JWT payload is not base64url: %w", ErrCredentialParse, err)
	}
	payload := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, nil, fmt.Errorf("%w: issuer JWT payload is not JSON: %w", ErrCredentialParse, err)
	}

	if flavor == credential.SDJwtVC {
		if err := a.checkSDJWTVCType(header, payload); err != nil {
			return nil, nil, err
		}
	}
	if policy != nil && policy.ExpectedSDJWTVCType != "" {
		vct, _ := payload["vct"].(string)
		if vct != policy.ExpectedSDJWTVCType {
			return nil, nil, fmt.Errorf("%w: SD-JWT VC vct %q is not the expected type %q", ErrCredentialTypInvalid, vct, policy.ExpectedSDJWTVCType)
		}
	}

	// HAIP §6.1.1: "The SD-JWT VC MUST contain the credential issuer's signing
	// certificate along with a trust chain in the x5c JOSE header".
	requireX5C := a.x5c.Require && flavor == credential.SDJwtVC
	if requireX5C {
		if _, present := header["x5c"]; !present {
			return nil, nil, fmt.Errorf("%w: %w", profile.Refused("IssuerX5C.Require"), ErrIssuerX5CRequired)
		}
	}

	// The header decides before the body is deserialized, so an unacceptable
	// alg is reported as such rather than as a parse failure.
	algorithm, _ := header["alg"].(string)
	if algorithm == "" || strings.EqualFold(algorithm, "none") {
		return nil, nil, fmt.Errorf("%w: issuer JWT alg header is missing or none", ErrCredentialAlgUnsupported)
	}
	if !slices.Contains(policy.signingAlgorithms(), jose.SignatureAlgorithm(algorithm)) {
		return nil, nil, fmt.Errorf("%w: issuer JWT alg %q is not listed by the credential acceptance policy", ErrCredentialAlgUnsupported, algorithm)
	}
	if !slices.Contains(a.verifier.GetSupportedAlgorithms(), jose.SignatureAlgorithm(algorithm)) {
		return nil, nil, fmt.Errorf("%w: issuer JWT alg %q is not supported by the verifier", ErrCredentialAlgUnsupported, algorithm)
	}

	if flavor == credential.SDJwtVC {
		// Checked before the serializer, which refuses an unknown _sd_alg as
		// a parse failure, so the refusal keeps its own sentinel.
		if _, err := sdAlgorithm(payload); err != nil {
			return nil, nil, err
		}
	}
	parsed, err := a.serializer.DeserializeCredential(flavor, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrCredentialParse, err)
	}

	verification := &Verification{}
	requireBinding := policy != nil && policy.RequireHolderBinding
	if err := checkHolderBinding(payload, opts.HolderKey, requireBinding, verification); err != nil {
		return nil, nil, err
	}
	if policy == nil {
		return parsed, verification, nil
	}

	now := time.Now()
	if policy.Now != nil {
		now = policy.Now()
	}
	issuer, _ := payload["iss"].(string)
	subject := issuerSubject{issuer: issuer, credentialIssuer: opts.CredentialIssuer, format: a.issuerKeyFormat(flavor, header)}
	if err := a.authenticateIssuer(ctx, parsed, policy, header, subject, now, requireX5C, verification); err != nil {
		return nil, nil, err
	}
	if err := checkValidity(payload, now, policy.ClockSkew); err != nil {
		return nil, nil, err
	}
	if flavor == credential.SDJwtVC {
		if err := checkDisclosureIntegrity(payload, parsed); err != nil {
			return nil, nil, err
		}
	}
	return parsed, verification, nil
}

// checkSDJWTVCType applies the SD-JWT VC typ header (-19 §2.2.1: "The typ
// value MUST use dc+sd-jwt"; Draft 13 issuers use the earlier vc+sd-jwt) and
// the vct claim (§2.2.2.3: "vct: REQUIRED", a string).
func (a *Acceptor) checkSDJWTVCType(header, payload map[string]any) error {
	typ, _ := header["typ"].(string)
	switch {
	case strings.EqualFold(typ, "dc+sd-jwt"):
	case a.draft13 && strings.EqualFold(typ, "vc+sd-jwt"):
	case a.draft13:
		return fmt.Errorf("%w: SD-JWT VC typ header must be dc+sd-jwt or vc+sd-jwt, got %q", ErrCredentialTypInvalid, typ)
	default:
		return fmt.Errorf("%w: SD-JWT VC typ header must be dc+sd-jwt, got %q", ErrCredentialTypInvalid, typ)
	}
	if vct, ok := payload["vct"].(string); !ok || vct == "" {
		return fmt.Errorf("%w: SD-JWT VC vct claim is required", ErrCredentialTypInvalid)
	}
	return nil
}

// issuerKeyFormat is the issuerkeys format identifier of a serialization.
func (a *Acceptor) issuerKeyFormat(flavor credential.SupportedSerializationFlavor, header map[string]any) string {
	switch flavor {
	case credential.SDJwtVC:
		if typ, _ := header["typ"].(string); a.draft13 && strings.EqualFold(typ, "vc+sd-jwt") {
			return issuerkeys.FormatSDJWTVCDraft
		}
		return issuerkeys.FormatSDJWTVC
	case credential.LdpVc:
		return issuerkeys.FormatLDPVC
	default:
		return issuerkeys.FormatJWTVCJSON
	}
}

// signingAlgorithms resolves the issuer algorithms one run accepts.
func (p *Policy) signingAlgorithms() []jose.SignatureAlgorithm {
	if p == nil || len(p.SigningAlgorithms) == 0 {
		return DefaultSigningAlgorithms()
	}
	return p.SigningAlgorithms
}

// checkHolderBinding compares cnf.jwk with holderKey (RFC 7800). Only cnf.jwk
// is supported: cnf.kid or cnf."x5t#S256" name a key the wallet would have to
// resolve out of band before it could sign a Key Binding JWT.
func checkHolderBinding(payload map[string]any, holderKey *jose.JSONWebKey, require bool, verification *Verification) error {
	cnfRaw, present := payload["cnf"]
	if !present {
		if require {
			return ErrHolderBindingMissing
		}
		return nil
	}
	cnf, ok := cnfRaw.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: cnf claim must be a JSON object", ErrCredentialParse)
	}
	jwkRaw, ok := cnf["jwk"]
	if !ok {
		return fmt.Errorf("%w (cnf members: %s)", ErrHolderBindingConfirmationUnsupported, strings.Join(sortedMemberNames(cnf), ", "))
	}
	if holderKey == nil {
		// Accepting an unchecked cnf under RequireHolderBinding would store,
		// as bound, a credential issued to somebody else's key.
		if require {
			return fmt.Errorf("%w: the credential carries a cnf confirmation key but no holder key was supplied to prove the binding", ErrHolderBindingMissing)
		}
		return nil
	}
	claimed, err := jsonWebKeyFromValue(jwkRaw)
	if err != nil {
		return fmt.Errorf("%w: cnf jwk is invalid: %w", ErrCredentialParse, err)
	}
	claimedThumbprint, err := claimed.Thumbprint(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("%w: cnf jwk thumbprint failed: %w", ErrCredentialParse, err)
	}
	holderThumbprint, err := holderKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return fmt.Errorf("%w: holder key thumbprint failed: %w", common.ErrInvalidInput, err)
	}
	if !bytes.Equal(claimedThumbprint, holderThumbprint) {
		return ErrHolderBindingMismatch
	}
	verification.HolderBound = true
	return nil
}

// IssuerSignedJOSEHeader decodes the protected header of a credential's
// issuer-signed JWT without verifying it. For an SD-JWT VC that JWT is the part
// before the first "~". Failures wrap ErrCredentialParse.
func IssuerSignedJOSEHeader(flavor credential.SupportedSerializationFlavor, raw []byte) (map[string]any, error) {
	jwtParts := strings.Split(issuerSignedJWT(flavor, raw), ".")
	if len(jwtParts) != 3 {
		return nil, fmt.Errorf("%w: issuer JWT must have exactly three parts", ErrCredentialParse)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(jwtParts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: issuer JWT header is not base64url: %w", ErrCredentialParse, err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: issuer JWT header is not JSON: %w", ErrCredentialParse, err)
	}
	return header, nil
}

// inferredFlavor reports SD-JWT VC when raw contains "~", which neither
// base64url nor a compact JWS contains, and JWT VC otherwise.
func inferredFlavor(raw []byte) credential.SupportedSerializationFlavor {
	if bytes.IndexByte(raw, '~') >= 0 {
		return credential.SDJwtVC
	}
	return credential.JwtVc
}

func issuerSignedJWT(flavor credential.SupportedSerializationFlavor, raw []byte) string {
	if flavor == credential.SDJwtVC {
		if index := bytes.IndexByte(raw, '~'); index >= 0 {
			return string(raw[:index])
		}
	}
	return string(raw)
}

func jsonWebKeyFromValue(value any) (jose.JSONWebKey, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(raw); err != nil {
		return jose.JSONWebKey{}, err
	}
	return key, nil
}

// sortedMemberNames lists an object's members in a stable order for errors.
func sortedMemberNames(object map[string]any) []string {
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
