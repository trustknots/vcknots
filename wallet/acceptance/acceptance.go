// Package acceptance decides whether a received credential may be stored: it
// authenticates the issuer key (X.509 x5c chain or a caller-supplied resolver),
// verifies the issuer signature (for an ldp_vc, its eddsa-rdfc-2022 Data
// Integrity proof), checks the cnf holder binding, the validity period and
// SD-JWT disclosure integrity. It needs no wallet or credential store.
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
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// Policy decides how the issuer of a credential is authenticated and which
// further checks apply. A deployment that accepts unauthenticated issuers says
// so with UnverifiedIssuer.
type Policy struct {
	// IssuerX509 authenticates the issuer key from the credential's x5c
	// header. HAIP requires it for SD-JWT VC (HAIP §6.1.1).
	IssuerX509 *IssuerX509TrustOptions
	// ResolveIssuerKeys returns candidate issuer keys (JWKS, DID or a static
	// registry). header is the unauthenticated issuer JWT header. It is not
	// called when x5c is present and IssuerX509 is set, unless
	// ResolveIssuerKeysWhenX5CUntrusted applies. Keys whose use is not "sig"
	// or whose alg differs from the JWS alg are ignored.
	ResolveIssuerKeys func(issuer string, header map[string]any) ([]jose.JSONWebKey, error)
	// ResolveIssuerKeysFromClaims replaces ResolveIssuerKeys when set, for a
	// resolver that also reads the (unauthenticated) payload, such as the JWT
	// VC vc.issuer member. For an ldp_vc, header holds the proof's
	// verificationMethod as kid and "EdDSA" as alg, and claims is the
	// credential document.
	ResolveIssuerKeysFromClaims func(issuer string, header map[string]any, claims map[string]any) ([]jose.JSONWebKey, error)
	// ResolveIssuerKeysWhenX5CUntrusted lets the resolver establish the key
	// when the x5c chain reaches none of IssuerX509's anchors
	// (commonX509.ErrNoTrustAnchor). Every other chain failure still refuses
	// the credential. It never applies to an SD-JWT VC under HAIP.
	ResolveIssuerKeysWhenX5CUntrusted bool
	// RequireHolderBinding refuses a credential without cnf, and one with cnf
	// when no holder key is supplied to compare it with.
	RequireHolderBinding bool
	// UnverifiedIssuer accepts the credential without authenticating the
	// issuer. It applies only when neither IssuerX509 nor a resolver is set;
	// the other checks still run. Under HAIP an SD-JWT VC is refused instead.
	UnverifiedIssuer bool
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
	AllowUnadvertisedRevocation bool // see commonX509.SigningChainPolicy.AllowUnadvertisedRevocation
	// RequireIssuerDNSBinding is ecosystem policy, not an SD-JWT VC rule: an
	// https iss must equal a dNSName SAN of the leaf certificate.
	RequireIssuerDNSBinding bool
	HTTPClient              *http.Client // CRL fetches; nil uses a bounded default
}

// Options are the per-call inputs of Acceptor.Verify and Acceptor.Parse.
type Options struct {
	// Flavor is the serialization of the raw credential. Empty infers SD-JWT
	// VC from a "~" separator and JWT VC otherwise.
	Flavor credential.SupportedSerializationFlavor
	// HolderKey is compared with cnf.jwk. Without it a cnf cannot be checked,
	// so Policy.RequireHolderBinding refuses the credential.
	HolderKey *jose.JSONWebKey
}

// Verification records what was verified.
type Verification struct {
	IssuerKeyID            string   // kid of the key used, or the leaf certificate SHA-256 fingerprint
	CertificateSHA256      []string // x5c path fingerprints, leaf first; nil when no x5c
	RevocationChecked      int
	RevocationUnadvertised int
	HolderBound            bool // cnf present and matched the holder key
	// IssuerKey is the public key the signature verified under; nil when no
	// issuer was authenticated (UnverifiedIssuer, Parse).
	IssuerKey *jose.JSONWebKey
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
	profile    profile.Profile
	serializer *serializer.SerializationDispatcher
	verifier   *verifier.VerificationDispatcher
}

// NewAcceptor builds an Acceptor for profile p. The profile is normalized, so
// an unknown value is an error. The serializer and verifier are required.
func NewAcceptor(p profile.Profile, s *serializer.SerializationDispatcher, v *verifier.VerificationDispatcher) (*Acceptor, error) {
	normalized, err := p.Normalize()
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("%w: acceptance requires a serialization dispatcher", common.ErrInvalidInput)
	}
	if v == nil {
		return nil, fmt.Errorf("%w: acceptance requires a verification dispatcher", common.ErrInvalidInput)
	}
	return &Acceptor{profile: normalized, serializer: s, verifier: v}, nil
}

// Verify applies policy to raw and returns the parsed credential and what was
// verified. It stores nothing. ctx bounds CRL retrieval. Failures wrap the
// sentinels of this package.
func (a *Acceptor) Verify(ctx context.Context, raw []byte, policy Policy, opts Options) (*credential.Credential, *Verification, error) {
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
		return a.runDataIntegrity(raw, opts, policy)
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
		typ, _ := header["typ"].(string)
		if !strings.EqualFold(typ, "dc+sd-jwt") && !strings.EqualFold(typ, "vc+sd-jwt") {
			return nil, nil, fmt.Errorf("%w: SD-JWT VC typ header must be dc+sd-jwt or vc+sd-jwt, got %q", ErrCredentialTypInvalid, typ)
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
	haipX5C := a.profile.IsHAIP() && flavor == credential.SDJwtVC
	if haipX5C {
		if _, present := header["x5c"]; !present {
			return nil, nil, ErrHAIPX5CRequired
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
	if err := a.authenticateIssuer(ctx, parsed, policy, header, payload, issuer, now, haipX5C, verification); err != nil {
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
