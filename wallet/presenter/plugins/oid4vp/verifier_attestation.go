package oid4vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/trustknots/vcknots/wallet/common"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
)

// Sentinel errors the verifier_attestation Request Object authentication path
// returns. They name the condition that made the Wallet refuse the request, so
// an integrator branches on it with errors.Is instead of matching message text.
var (
	// ErrVerifierAttestationInvalid reports that the Verifier Attestation JWT
	// carried in the `jwt` JOSE header of the Request Object is absent,
	// unreadable, carries the wrong `typ`, is missing a required claim, or does
	// not authenticate the Request Object's signing key (OpenID4VP 1.0
	// Section "Verifier Attestation JWT").
	ErrVerifierAttestationInvalid = common.NewCodedError("verifier_attestation_invalid", "verifier attestation JWT is not usable")
	// ErrVerifierAttestationUntrusted reports that the `iss` of the Verifier
	// Attestation JWT is not a party this Wallet trusts for issuing them.
	// OpenID4VP 1.0 Section 5.9.3: "The `iss` claim value of the Verifier
	// Attestation JWT MUST identify a party the Wallet trusts for issuing
	// Verifier Attestation JWTs. If the Wallet cannot establish trust, it MUST
	// refuse the request."
	ErrVerifierAttestationUntrusted = common.NewCodedError("verifier_attestation_untrusted", "verifier attestation issuer is not trusted by this wallet")
	// ErrVerifierAttestationExpired reports that the Verifier Attestation JWT
	// is outside its exp/nbf validity. OpenID4VP 1.0: "The Wallet MUST reject
	// any Verifier Attestation JWT with an expiration time that has passed,
	// subject to allowable clock skew between systems."
	ErrVerifierAttestationExpired = common.NewCodedError("verifier_attestation_expired", "verifier attestation JWT is outside its validity")
	// ErrRequestObjectClientAuthUnsupported reports that the Client Identifier
	// Prefix of a signed Request Object names no authentication method this
	// library implements. It is the one refusal that says the Wallet cannot
	// authenticate this kind of Verifier at all, rather than that a particular
	// authentication failed.
	ErrRequestObjectClientAuthUnsupported = common.NewCodedError("request_object_client_auth_unsupported", "signed request object client identifier prefix has no configured authentication method")
)

// verifierAttestationTyp is the media type a Verifier Attestation JWT sets in
// its `typ` JOSE header (OpenID4VP 1.0: "A Verifier Attestation JWT MUST set
// the `typ` JOSE header to `verifier-attestation+jwt`").
const verifierAttestationTyp = "verifier-attestation+jwt"

// maxVerifierAttestationJWTLength bounds the Verifier Attestation JWT read out
// of a Request Object header, for the same reason the Request Object itself is
// bounded: the value arrives from the party being authenticated.
const maxVerifierAttestationJWTLength = 1 << 20

// VerifierAttestationIssuer is one party this Wallet trusts for issuing
// Verifier Attestation JWTs, and the keys that party signs them with.
//
// OpenID4VP 1.0 leaves how the trust is established, and how the issuer's
// public key is obtained, out of scope: "How the trust is established between
// Wallet and Issuer and how the public key is obtained for validating the
// attestation's signature is out of scope of this specification." This library
// therefore takes the decision as configuration rather than resolving it, so a
// Wallet names the attesters it accepts in one place.
type VerifierAttestationIssuer struct {
	// EntityID is the exact `iss` claim value of the attestations this entry
	// authenticates. The comparison is a byte equality, never a normalization
	// of the two identifiers.
	EntityID string
	// JWKS holds the public keys the attester signs with. An entry with no key
	// authenticates nothing and is refused when it is selected.
	JWKS jose.JSONWebKeySet
	// SigningAlgorithms bounds the JWS "alg" values this attester's
	// attestations may be signed with. An empty list means
	// DefaultVerifierAttestationSigningAlgorithms.
	SigningAlgorithms []jose.SignatureAlgorithm
}

// DefaultVerifierAttestationSigningAlgorithms is the attestation signature
// policy applied when a VerifierAttestationIssuer leaves SigningAlgorithms
// empty. It is the asymmetric subset of the algorithms this wallet verifies:
// the MAC algorithms and "none" never authenticate an attester to a Wallet
// holding only public keys. Callers must not modify the slice.
var DefaultVerifierAttestationSigningAlgorithms = commonJOSE.AcceptedSignatureAlgorithms()

// VerifierAttestationEvidence records the authentication a Verifier Attestation
// performed. No request parameter can populate it: every field is read from the
// attestation whose signature this library verified against a configured
// attester key.
type VerifierAttestationEvidence struct {
	// IssuerEntityID is the `iss` of the attestation, which is also the
	// EntityID of the configured attester that authenticated it.
	IssuerEntityID string
	// Subject is the `sub` of the attestation, which equals the original
	// Client Identifier (the part after "verifier_attestation:").
	Subject string
	// ExpiresAt is the `exp` of the attestation in UTC.
	ExpiresAt time.Time
	// RedirectURIs is the `redirect_uris` claim the attester constrained the
	// Verifier with, empty when the attestation carried none.
	RedirectURIs []string
}

// verifierAttestationClaims is the decoded Verifier Attestation JWT body. Only
// the claims OpenID4VP gives meaning to are read; the specification requires
// that "The Wallet MUST ignore any unrecognized claims".
type verifierAttestationClaims struct {
	issuer       string
	subject      string
	expiry       time.Time
	confirmation jose.JSONWebKey
	redirectURIs []string
}

// authenticateRequestObjectByClientIdentifier routes one signed Request Object
// to the authentication method its Client Identifier Prefix names, so every
// prefix an integrator can send reaches the same library entry point and the
// same registered-claim policy. OpenID4VP 1.0 Section 5.9.3 defines a different
// way to authenticate the request for each prefix; this is where that choice is
// made, once.
func (b *requestBuilder) authenticateRequestObjectByClientIdentifier(obj string, parsed *jwt.JSONWebToken, options RequestObjectValidationOptions) error {
	clientID, err := b.parseClientID(b.req.ClientID)
	if err != nil {
		return err
	}
	switch clientID.prefix {
	case OID4VPClientIDPrefixX509SanDNS, OID4VPClientIDPrefixX509Hash:
		return b.authenticateX509RequestObject(obj, parsed, options, true)
	case OID4VPClientIDPrefixVerifierAttestation:
		return b.authenticateVerifierAttestationRequestObject(parsed, clientID, options)
	case OID4VPClientIDPrefixOIDFederation:
		return b.authenticateFederationRequestObject(obj, parsed, clientID, options)
	case OID4VPClientIDPrefixPreRegistered:
		return b.authenticatePreRegisteredRequestObject(parsed, options)
	default:
		// Final 5.1: client_metadata keys are never request-signature keys, so
		// a prefix with no other authentication method cannot be authenticated
		// from the request itself.
		return fmt.Errorf("%w: %q", ErrRequestObjectClientAuthUnsupported, clientID.prefix)
	}
}

// authenticateVerifierAttestationRequestObject implements the
// verifier_attestation Client Identifier Prefix of OpenID4VP 1.0 Section 5.9.3:
// the Request Object carries a Verifier Attestation JWT in its `jwt` JOSE
// header, the Wallet validates that attestation against an attester it trusts,
// and the Request Object must be signed with the private key matching the
// attestation's `cnf` JWK, "which serves as proof of possession".
func (b *requestCore) authenticateVerifierAttestationRequestObject(
	parsed *jwt.JSONWebToken,
	clientID *OID4VPClientID,
	options RequestObjectValidationOptions,
) error {
	attestationJWT, err := verifierAttestationFromRequestObjectHeader(parsed)
	if err != nil {
		return err
	}
	now := requestObjectNow(options)
	attestation, err := verifyVerifierAttestation(attestationJWT, clientID.original, options, now)
	if err != nil {
		return err
	}

	verified := make(commonJOSE.Claims)
	if err := parsed.Claims(attestation.confirmation, &verified); err != nil {
		return fmt.Errorf("request object is not signed by the verifier attestation confirmation key: %w: %w", err, ErrRequestObjectSignatureInvalid)
	}
	if err := b.requireWalletNonceEcho(verified); err != nil {
		return err
	}
	if err := validateRequestObjectClaims(verified, b.resolveClaimPolicy(options, now)); err != nil {
		return fmt.Errorf("JWT standard claims validation failed: %w", err)
	}
	if err := requireVerifierAttestationResponseEndpoint(attestation.redirectURIs, b.req); err != nil {
		return err
	}

	b.req.RequestObjectVerification = &RequestObjectVerification{
		ClientID:    b.req.ClientID,
		WalletNonce: b.sentWalletNonce,
		ExpiresAt:   requestObjectExpiry(verified),
		VerifierAttestation: &VerifierAttestationEvidence{
			IssuerEntityID: attestation.issuer,
			Subject:        attestation.subject,
			ExpiresAt:      attestation.expiry,
			RedirectURIs:   slices.Clone(attestation.redirectURIs),
		},
	}
	return nil
}

// verifierAttestationFromRequestObjectHeader reads the `jwt` JOSE header
// OpenID4VP 1.0 introduces for conveying a Verifier Attestation JWT: "The
// Verifier attestation JWT MUST be added to the `jwt` JOSE Header of the
// request object."
func verifierAttestationFromRequestObjectHeader(parsed *jwt.JSONWebToken) (string, error) {
	if len(parsed.Headers) != 1 {
		return "", fmt.Errorf("request object JWT must have one protected header: %w", ErrRequestObjectTypInvalid)
	}
	raw, present := parsed.Headers[0].ExtraHeaders["jwt"]
	if !present {
		return "", fmt.Errorf("%w: request object has no jwt header carrying the verifier attestation", ErrVerifierAttestationInvalid)
	}
	attestation, ok := raw.(string)
	if !ok || attestation == "" {
		return "", fmt.Errorf("%w: request object jwt header is not a JWT", ErrVerifierAttestationInvalid)
	}
	if len(attestation) > maxVerifierAttestationJWTLength || strings.Count(attestation, ".") != 2 {
		return "", fmt.Errorf("%w: request object jwt header is not a bounded compact signed JWT", ErrVerifierAttestationInvalid)
	}
	return attestation, nil
}

// verifyVerifierAttestation authenticates one Verifier Attestation JWT against
// the attesters this Wallet trusts and returns the claims OpenID4VP gives
// meaning to. subject is the original Client Identifier the attestation's `sub`
// must equal (Section 5.9.3: "the original Client Identifier ... MUST equal the
// `sub` claim value in the Verifier attestation JWT").
func verifyVerifierAttestation(
	attestationJWT string,
	subject string,
	options RequestObjectValidationOptions,
	now time.Time,
) (*verifierAttestationClaims, error) {
	if len(options.VerifierAttestationIssuers) == 0 {
		return nil, fmt.Errorf("%w: no verifier attestation issuer is configured", ErrVerifierAttestationUntrusted)
	}
	// The attestation's own header is read before any signature is checked, so
	// a document of the wrong media type is refused as such rather than as a
	// signature failure.
	unverified, err := jwt.ParseSigned(attestationJWT, commonJOSE.AcceptedSignatureAlgorithms())
	if err != nil {
		return nil, fmt.Errorf("%w: verifier attestation is not a signed JWT: %w", ErrVerifierAttestationInvalid, err)
	}
	if len(unverified.Headers) != 1 {
		return nil, fmt.Errorf("%w: verifier attestation must have one protected header", ErrVerifierAttestationInvalid)
	}
	if typ, _ := unverified.Headers[0].ExtraHeaders["typ"].(string); typ != verifierAttestationTyp {
		return nil, fmt.Errorf("%w: verifier attestation typ header must be %q", ErrVerifierAttestationInvalid, verifierAttestationTyp)
	}
	unverifiedClaims := make(commonJOSE.Claims)
	if err := unverified.UnsafeClaimsWithoutVerification(&unverifiedClaims); err != nil {
		return nil, fmt.Errorf("%w: verifier attestation claims are unreadable: %w", ErrVerifierAttestationInvalid, err)
	}
	issuer, _ := unverifiedClaims["iss"].(string)
	attester, err := selectVerifierAttestationIssuer(options.VerifierAttestationIssuers, issuer)
	if err != nil {
		return nil, err
	}
	algorithms := attester.SigningAlgorithms
	if len(algorithms) == 0 {
		algorithms = DefaultVerifierAttestationSigningAlgorithms
	}
	if !slices.Contains(algorithms, jose.SignatureAlgorithm(unverified.Headers[0].Algorithm)) {
		return nil, fmt.Errorf("%w: verifier attestation alg %q is not accepted for issuer %q",
			ErrVerifierAttestationInvalid, unverified.Headers[0].Algorithm, attester.EntityID)
	}

	verified, err := verifyVerifierAttestationSignature(unverified, attester, unverified.Headers[0].KeyID)
	if err != nil {
		return nil, err
	}
	return readVerifierAttestationClaims(verified, attester.EntityID, subject, options, now)
}

// selectVerifierAttestationIssuer finds the configured attester an attestation
// names in its `iss` claim.
func selectVerifierAttestationIssuer(issuers []VerifierAttestationIssuer, issuer string) (VerifierAttestationIssuer, error) {
	if issuer == "" {
		return VerifierAttestationIssuer{}, fmt.Errorf("%w: verifier attestation has no iss claim", ErrVerifierAttestationInvalid)
	}
	for _, candidate := range issuers {
		if candidate.EntityID == issuer {
			if len(candidate.JWKS.Keys) == 0 {
				return VerifierAttestationIssuer{}, fmt.Errorf("%w: trusted verifier attestation issuer %q has no key", ErrVerifierAttestationUntrusted, issuer)
			}
			return candidate, nil
		}
	}
	return VerifierAttestationIssuer{}, fmt.Errorf("%w: %q", ErrVerifierAttestationUntrusted, issuer)
}

// verifyVerifierAttestationSignature verifies the attestation against the
// attester's keys. A `kid` narrows the candidates as a hint; when it names no
// configured key every key of the attester is still tried, so an attester that
// rotated a key without republishing its identifier does not become untrusted.
func verifyVerifierAttestationSignature(
	parsed *jwt.JSONWebToken,
	attester VerifierAttestationIssuer,
	keyID string,
) (commonJOSE.Claims, error) {
	candidates := attester.JWKS.Keys
	if keyID != "" {
		if narrowed := attester.JWKS.Key(keyID); len(narrowed) != 0 {
			candidates = narrowed
		}
	}
	for i := range candidates {
		claims := make(commonJOSE.Claims)
		if err := parsed.Claims(candidates[i], &claims); err == nil {
			return claims, nil
		}
	}
	return nil, fmt.Errorf("%w: verifier attestation signature does not verify with any key of issuer %q",
		ErrVerifierAttestationInvalid, attester.EntityID)
}

// readVerifierAttestationClaims applies the claim rules OpenID4VP 1.0 states
// for a Verifier Attestation JWT to an already signature-verified body.
func readVerifierAttestationClaims(
	claims commonJOSE.Claims,
	issuer string,
	subject string,
	options RequestObjectValidationOptions,
	now time.Time,
) (*verifierAttestationClaims, error) {
	// sub: REQUIRED, and Section 5.9.3 binds it to the original Client
	// Identifier.
	claimedSubject, _ := claims["sub"].(string)
	if claimedSubject == "" || claimedSubject != subject {
		return nil, fmt.Errorf("%w: verifier attestation sub does not equal the original client identifier", ErrVerifierAttestationInvalid)
	}
	// exp: REQUIRED. nbf and iat are OPTIONAL; nbf is honoured when present.
	expiry, err := verifierAttestationNumericDate(claims, "exp")
	if err != nil || expiry == nil {
		return nil, fmt.Errorf("%w: verifier attestation exp is required", ErrVerifierAttestationInvalid)
	}
	if requestObjectInstant(now.Add(-options.ClockSkew)).Cmp(expiry) >= 0 {
		return nil, fmt.Errorf("%w: verifier attestation exp has passed", ErrVerifierAttestationExpired)
	}
	notBefore, err := verifierAttestationNumericDate(claims, "nbf")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerifierAttestationInvalid, err)
	}
	if notBefore != nil && requestObjectInstant(now.Add(options.ClockSkew)).Cmp(notBefore) < 0 {
		return nil, fmt.Errorf("%w: verifier attestation is not yet valid", ErrVerifierAttestationExpired)
	}
	confirmation, err := verifierAttestationConfirmationKey(claims)
	if err != nil {
		return nil, err
	}
	redirectURIs, err := verifierAttestationRedirectURIs(claims)
	if err != nil {
		return nil, err
	}
	seconds, _ := expiry.Float64()
	return &verifierAttestationClaims{
		issuer:       issuer,
		subject:      claimedSubject,
		expiry:       time.Unix(0, int64(seconds*float64(time.Second))).UTC(),
		confirmation: *confirmation,
		redirectURIs: redirectURIs,
	}, nil
}

// verifierAttestationConfirmationKey reads the `cnf` claim OpenID4VP 1.0
// requires: "It MUST contain a JSON Web Key [@!RFC7517] as defined in Section
// 3.2 of [@!RFC7800]." A confirmation carrying anything other than a public JWK
// authenticates no proof of possession and is refused.
func verifierAttestationConfirmationKey(claims commonJOSE.Claims) (*jose.JSONWebKey, error) {
	confirmation, ok := claims["cnf"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: verifier attestation cnf claim is required", ErrVerifierAttestationInvalid)
	}
	raw, ok := confirmation["jwk"]
	if !ok {
		return nil, fmt.Errorf("%w: verifier attestation cnf.jwk is required", ErrVerifierAttestationInvalid)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: verifier attestation cnf.jwk is unreadable: %w", ErrVerifierAttestationInvalid, err)
	}
	key := &jose.JSONWebKey{}
	if err := key.UnmarshalJSON(encoded); err != nil {
		return nil, fmt.Errorf("%w: verifier attestation cnf.jwk is not a JWK: %w", ErrVerifierAttestationInvalid, err)
	}
	if !key.Valid() || !key.IsPublic() {
		return nil, fmt.Errorf("%w: verifier attestation cnf.jwk must be a public JWK", ErrVerifierAttestationInvalid)
	}
	return key, nil
}

// requireVerifierAttestationResponseEndpoint holds the response endpoint to
// the attestation's redirect_uris, exactly (OID4VP 1.0 §5.9.3). Under
// direct_post the endpoint is response_uri. An attestation without the claim
// constrains nothing.
func requireVerifierAttestationResponseEndpoint(redirectURIs []string, request *CredentialPresentationRequest) error {
	if len(redirectURIs) == 0 {
		return nil
	}
	bound := request.responseEndpoint()
	if bound == "" || !slices.Contains(redirectURIs, bound) {
		return fmt.Errorf("%w: the response endpoint %q is not one of the verifier attestation redirect_uris",
			ErrVerifierAttestationInvalid, bound)
	}
	if _, err := url.Parse(bound); err != nil {
		return fmt.Errorf("%w: the response endpoint is not a URI: %w", ErrVerifierAttestationInvalid, err)
	}
	return nil
}

// verifierAttestationRedirectURIs reads the optional redirect_uris claim. A
// claim that is present must be a non-empty array of non-empty strings: an
// attester that tried to constrain the endpoint must not lose the constraint
// to a malformed value.
func verifierAttestationRedirectURIs(claims commonJOSE.Claims) ([]string, error) {
	value, present := claims["redirect_uris"]
	if !present {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return nil, fmt.Errorf("%w: verifier attestation redirect_uris must be a non-empty array of strings", ErrVerifierAttestationInvalid)
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, fmt.Errorf("%w: verifier attestation redirect_uris must be a non-empty array of strings", ErrVerifierAttestationInvalid)
		}
		values = append(values, text)
	}
	return values, nil
}

// verifierAttestationNumericDate reads one optional NumericDate claim of a
// Verifier Attestation exactly, with the precision rules the Request Object
// claims are read with.
func verifierAttestationNumericDate(claims commonJOSE.Claims, name string) (*big.Rat, error) {
	value, err := requestObjectNumericDate(claims, name)
	if err != nil {
		return nil, errors.New("verifier attestation " + name + " is not a NumericDate")
	}
	return value, nil
}
