package oid4vp

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
)

// RequestObjectValidationOptions is relying-party configuration, never data
// obtained from client_metadata in the request being authenticated.
type RequestObjectValidationOptions struct {
	TrustAnchors []*x509.Certificate
	RootCAs      *x509.CertPool
	// CertificateKeyUsages is an optional ecosystem EKU constraint. A signing
	// certificate need not be a TLS server certificate in general OpenID4VP.
	CertificateKeyUsages []x509.ExtKeyUsage
	CRL                  commonX509.CRLCheckerOptions
	// AllowUnadvertisedRevocation explicitly retains ecosystems which accept
	// certificates without any published CRL/OCSP information. Such certificates
	// are reported separately, never as positively checked for revocation.
	// The default requires positive status for every certificate below the anchor.
	AllowUnadvertisedRevocation bool
	// WalletAudience defaults to the static OpenID4VP identifier. Dynamic
	// discovery integrations supply their Wallet issuer identifier instead.
	WalletAudience []string
	Now            func() time.Time
	ClockSkew      time.Duration
	// SigningAlgorithms defaults to ES256 and RS256. This is independent of
	// encryption keys and algorithms carried in client_metadata.
	SigningAlgorithms []jose.SignatureAlgorithm
	// RequireExpiry rejects a Request Object without exp. Neither OpenID4VP
	// 1.0 nor HAIP requires exp, so it is off by default in every profile.
	RequireExpiry bool
	// MaxAge bounds the lifetime of a Request Object, measured as exp - iat,
	// or as exp - now when iat is absent. Zero means unbounded. The HAIP
	// profile substitutes haipRequestObjectMaxAge when the caller left it
	// zero, and honours a caller-supplied value as given.
	MaxAge time.Duration
	// VerifierAttestationIssuers are the parties this Wallet trusts for issuing
	// Verifier Attestation JWTs (OID4VP 1.0 §5.9.3). An empty list refuses
	// every verifier_attestation Client Identifier, because the profile makes
	// establishing that trust a precondition of accepting the request.
	VerifierAttestationIssuers []VerifierAttestationIssuer
	// Federation is the OpenID Federation trust policy applied to an
	// openid_federation Client Identifier. A nil value refuses every such
	// Client Identifier.
	Federation *FederationTrustOptions
}

// haipRequestObjectMaxAge is the Request Object lifetime the HAIP profile
// applies when the caller configured no MaxAge.
const haipRequestObjectMaxAge = 10 * time.Minute

// RequestObjectVerification records the authentication performed by this
// library. No request parameter can populate this field.
type RequestObjectVerification struct {
	ClientID               string
	CertificateSHA256      []string
	RevocationChecked      int
	RevocationUnadvertised int
	// WalletNonce is the wallet_nonce sent with a Final request_uri POST and
	// echoed by the authenticated Request Object. It is empty for GET and when
	// no nonce was sent (OID4VP 1.0 §5.10.1).
	WalletNonce string
	// Delivery records how this library observed the Request Object arrive:
	// "reference" (request_uri), "value" (request=), or "query" (plain query
	// parameters). It is empty when the library did not observe one of those
	// paths.
	Delivery string
	// DeliveryAttested is true when the caller's
	// RequestObjectSource.DeliveredByReference was accepted for the HAIP
	// delivery check, letting a Request Object passed by value satisfy the
	// request_uri requirement.
	DeliveryAttested bool
	// ExpiresAt is the exp claim of the authenticated Request Object, in UTC.
	// It is the zero value when the Request Object carried no exp, which the
	// RequireExpiry policy decides whether to accept. A Wallet that has to show
	// or store how long the Verifier's request stays valid reads it here rather
	// than decoding the Request Object a second time.
	ExpiresAt time.Time
	// Certificate describes the leaf certificate that signed an X.509 Request
	// Object, so a Wallet showing the Verifier's identity does not decode the
	// same certificate a second time to read what this library already parsed
	// while authenticating it. It is nil for every other Client Identifier
	// Prefix.
	Certificate *RequestObjectCertificate
	// VerifierAttestation is the attestation that authenticated a
	// verifier_attestation Client Identifier, nil for every other prefix.
	VerifierAttestation *VerifierAttestationEvidence
	// Federation is the Trust Chain that authenticated an openid_federation
	// Client Identifier, nil for every other prefix.
	Federation *FederationEvidence
}

// RequestObjectCertificate is what a Wallet shows about the certificate that
// signed a Request Object. It carries identity, not trust: the chain, its
// revocation status and the Client Identifier binding were decided while the
// Request Object was authenticated, and a certificate is only described here
// once that succeeded.
type RequestObjectCertificate struct {
	// Subject and Issuer are RFC 2253 distinguished names.
	Subject string
	Issuer  string
	// DNSNames are the dNSName Subject Alternative Names of the leaf, read
	// from the certificate extension rather than from a rendered string.
	DNSNames []string
	// NotBefore and NotAfter are the leaf validity window, in UTC.
	NotBefore time.Time
	NotAfter  time.Time
	// SerialNumber is the leaf serial as a decimal string.
	SerialNumber string
}

// requestObjectExpiry reads the exp claim of already validated Request Object
// claims as a UTC time, or the zero time when it is absent or unusable.
func requestObjectExpiry(claims commonJOSE.Claims) time.Time {
	value, err := requestObjectNumericDate(claims, "exp")
	if err != nil || value == nil {
		return time.Time{}
	}
	seconds, _ := value.Float64()
	return time.Unix(0, int64(seconds*float64(time.Second))).UTC()
}

// WithRequestObjectValidation configures the public builder before loading a
// Request Object. The presenter configures it once for each parse operation.
func (b *requestBuilder) WithRequestObjectValidation(options RequestObjectValidationOptions) *requestBuilder {
	b.setRequestObjectValidation(options)
	return b
}

// setRequestObjectValidation stores a copy of options for this parse.
func (c *requestCore) setRequestObjectValidation(options RequestObjectValidationOptions) {
	options.TrustAnchors = append([]*x509.Certificate(nil), options.TrustAnchors...)
	options.CertificateKeyUsages = append([]x509.ExtKeyUsage(nil), options.CertificateKeyUsages...)
	options.WalletAudience = append([]string(nil), options.WalletAudience...)
	options.SigningAlgorithms = append([]jose.SignatureAlgorithm(nil), options.SigningAlgorithms...)
	c.requestObjectValidation = &options
}

// WithExpectedClientID supplies the outer Authorization Request client_id that
// a Request Object's client_id claim must equal.
func (b *requestBuilder) WithExpectedClientID(clientID string) *requestBuilder {
	b.expectedClientID = strings.TrimSpace(clientID)
	return b
}

// WithRequestObject authenticates a Request Object passed by value.
func (b *requestBuilder) WithRequestObject(obj string) *requestBuilder {
	b.requestSource = sourceValue
	return b.withRequestObject(obj)
}

// withRequestObject authenticates a Request Object delivered as b.requestSource
// records.
func (b *requestBuilder) withRequestObject(obj string) *requestBuilder {
	if b.errValidation != nil {
		return b
	}
	b.requestObject = obj
	b.errorResponseAllowed = false
	if b.insecureSkipX509Verify {
		b.errValidation = errors.New("final Request Object authentication cannot skip X.509 verification")
		return b
	}
	if err := b.authenticateFinalRequestObject(obj); err != nil {
		b.errValidation = err
	}
	return b
}

// resolveRequestObjectAlgorithms returns the signature algorithms a Request
// Object may be signed with, defaulting to ES256 and RS256.
func resolveRequestObjectAlgorithms(options RequestObjectValidationOptions) []jose.SignatureAlgorithm {
	if len(options.SigningAlgorithms) != 0 {
		return options.SigningAlgorithms
	}
	return []jose.SignatureAlgorithm{jose.ES256, jose.RS256}
}

// requestObjectNow is the verification time of one Request Object. Every check
// of one authentication run reads it once, so a chain, a revocation list and a
// registered claim are never judged against different clocks.
func requestObjectNow(options RequestObjectValidationOptions) time.Time {
	if options.Now != nil {
		return options.Now()
	}
	return time.Now()
}

// requestObjectClaimPolicy is the resolved registered-claim policy applied to
// one authenticated Request Object.
type requestObjectClaimPolicy struct {
	Audiences []string
	// AudienceOptional skips the aud check (the Draft 24 contract).
	AudienceOptional bool
	Now              time.Time
	ClockSkew        time.Duration
	RequireExpiry    bool
	MaxAge           time.Duration
}

// authenticateFinalRequestObject authenticates an OpenID4VP 1.0 Request
// Object (OID4VP 1.0 §5.10.1, RFC 9101) and loads its claims.
func (b *requestBuilder) authenticateFinalRequestObject(obj string) error {
	if b.expectedClientID == "" && !b.expectedClientIDAbsent {
		return errors.New("client_id Authorization Request parameter is required with a Request Object")
	}
	options, err := b.requestObjectValidationOptions()
	if err != nil {
		return err
	}
	b.adoptCallerWalletNonce()
	parsed, claims, err := decodeRequestObject(obj, resolveRequestObjectAlgorithms(options))
	if err != nil {
		return err
	}
	if _, present := claims["request"]; present {
		return errors.New("request object must not contain request or request_uri")
	}
	if _, present := claims["request_uri"]; present {
		return errors.New("request object must not contain request or request_uri")
	}
	b.setParamsWithAnyMap(claims)
	if err := b.validate(); err != nil {
		return err
	}
	return b.authenticateRequestObjectByClientIdentifier(obj, parsed, options)
}

// describeRequestObjectCertificate reports the identity of the leaf that
// signed an authenticated Request Object. The dNSName Subject Alternative
// Names come from the parsed extension, so a name containing a comma cannot be
// split into two by a consumer reading a rendered string instead.
func describeRequestObjectCertificate(leaf *x509.Certificate) *RequestObjectCertificate {
	if leaf == nil {
		return nil
	}
	return &RequestObjectCertificate{
		Subject:      leaf.Subject.String(),
		Issuer:       leaf.Issuer.String(),
		DNSNames:     slices.Clone(leaf.DNSNames),
		NotBefore:    leaf.NotBefore.UTC(),
		NotAfter:     leaf.NotAfter.UTC(),
		SerialNumber: leaf.SerialNumber.String(),
	}
}

// validateRequestObjectClaims applies the registered-claim policy to the claims
// of an already signature-verified Request Object.
func validateRequestObjectClaims(claims commonJOSE.Claims, policy requestObjectClaimPolicy) error {
	if policy.Now.IsZero() {
		return errors.New("verification time is required")
	}
	if err := validateRequestObjectAudience(claims, policy); err != nil {
		return err
	}
	dates := map[string]*big.Rat{}
	for _, name := range []string{"exp", "nbf", "iat"} {
		value, err := requestObjectNumericDate(claims, name)
		if err != nil {
			return err
		}
		if value != nil {
			dates[name] = value
		}
	}
	if dates["exp"] == nil && policy.RequireExpiry {
		return fmt.Errorf("request object is missing exp: %w", ErrRequestObjectExpired)
	}
	// NumericDate permits fractions; compare exactly, without truncating or
	// losing precision through float64. An iat in the future is refused, so
	// MaxAge, measured from iat, bounds the real remaining lifetime.
	if issuedAt := dates["iat"]; issuedAt != nil {
		if requestObjectInstant(policy.Now.Add(policy.ClockSkew)).Cmp(issuedAt) < 0 {
			return fmt.Errorf("request object is issued in the future: %w", ErrRequestObjectExpired)
		}
	}
	if expiry := dates["exp"]; expiry != nil {
		if requestObjectInstant(policy.Now.Add(-policy.ClockSkew)).Cmp(expiry) >= 0 {
			return fmt.Errorf("request object is outside its exp validity: %w", ErrRequestObjectExpired)
		}
		if err := validateRequestObjectMaxAge(expiry, dates["iat"], policy); err != nil {
			return err
		}
	}
	if notBefore := dates["nbf"]; notBefore != nil {
		if requestObjectInstant(policy.Now.Add(policy.ClockSkew)).Cmp(notBefore) < 0 {
			return fmt.Errorf("request object is outside its nbf validity: %w", ErrRequestObjectExpired)
		}
	}
	// iss is ignored, including its type, as required by Final section 5.
	return nil
}

// validateRequestObjectAudience requires the Request Object to identify this
// Wallet. An absent policy audience means the static OpenID4VP identifier,
// unless the wire contract makes the claim optional.
func validateRequestObjectAudience(claims commonJOSE.Claims, policy requestObjectClaimPolicy) error {
	audiences := policy.Audiences
	if len(audiences) == 0 {
		if policy.AudienceOptional {
			return nil
		}
		audiences = []string{"https://self-issued.me/v2"}
	}
	var actual []string
	switch aud := claims["aud"].(type) {
	case string:
		actual = []string{aud}
	case []any:
		for _, value := range aud {
			text, ok := value.(string)
			if !ok || text == "" {
				return fmt.Errorf("invalid audience claim: %w", ErrRequestObjectAudienceMismatch)
			}
			actual = append(actual, text)
		}
	default:
		return fmt.Errorf("request object audience is required: %w", ErrRequestObjectAudienceMismatch)
	}
	for _, expected := range audiences {
		for _, value := range actual {
			if expected != "" && expected == value {
				return nil
			}
		}
	}
	return fmt.Errorf("request object audience does not identify this Wallet: %w", ErrRequestObjectAudienceMismatch)
}

// validateRequestObjectMaxAge bounds the lifetime a Request Object claims for
// itself: exp - iat, or exp - now when the issuing time is absent.
func validateRequestObjectMaxAge(expiry, issuedAt *big.Rat, policy requestObjectClaimPolicy) error {
	if policy.MaxAge <= 0 {
		return nil
	}
	from := issuedAt
	if from == nil {
		from = requestObjectInstant(policy.Now)
	}
	lifetime := new(big.Rat).Sub(expiry, from)
	maximum := new(big.Rat).SetFrac64(int64(policy.MaxAge), int64(time.Second))
	if lifetime.Cmp(maximum) <= 0 {
		return nil
	}
	seconds, _ := lifetime.Float64()
	return fmt.Errorf("request object exp is %s in the future, exceeding the configured maximum of %s: %w",
		(time.Duration(seconds * float64(time.Second))).Round(time.Second), policy.MaxAge, ErrRequestObjectExpired)
}

// requestObjectNumericDate reads one optional NumericDate claim exactly,
// rejecting a precision or exponent no relying party needs to represent.
func requestObjectNumericDate(claims commonJOSE.Claims, name string) (*big.Rat, error) {
	value, present := claims[name]
	if !present {
		return nil, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return nil, fmt.Errorf("%s must be a NumericDate", name)
	}
	text := number.String()
	if len(text) > 128 {
		return nil, fmt.Errorf("%s NumericDate exceeds supported precision", name)
	}
	if exponentIndex := strings.IndexAny(text, "eE"); exponentIndex >= 0 {
		exponent, err := strconv.Atoi(text[exponentIndex+1:])
		if err != nil || exponent < -1024 || exponent > 1024 {
			return nil, fmt.Errorf("%s NumericDate exceeds supported exponent range", name)
		}
	}
	timestamp, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil, fmt.Errorf("invalid %s NumericDate", name)
	}
	return timestamp, nil
}

// requestObjectInstant renders a wall-clock instant as the exact rational
// number of seconds a NumericDate is compared against.
func requestObjectInstant(at time.Time) *big.Rat {
	instant := new(big.Rat).SetInt64(at.Unix())
	return instant.Add(instant, new(big.Rat).SetFrac64(int64(at.Nanosecond()), 1e9))
}
