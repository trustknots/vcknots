package statuslist

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	commonjose "github.com/trustknots/vcknots/wallet/common/jose"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/profile"
)

// tokenClaims is the verified payload of a Status List Token, reduced to the
// members draft-ietf-oauth-status-list Section 5.1 defines and this package
// acts on.
type tokenClaims struct {
	issuer      string
	subject     string
	issuedAt    time.Time
	expiresAt   time.Time // zero when the token carries no `exp`
	notBefore   time.Time // zero when the token carries no `nbf`
	ttlSeconds  float64   // zero when the token carries no `ttl`
	bits        int
	encodedList string
}

// integerValue reports value as an int64 when it is an integer that a JSON
// number represents exactly: a json.Number, a float64 with an integral value,
// an int or an int64, whose magnitude is at most 2^53 - 1. Which of those a
// decoded credential carries depends on how its JSON was decoded, and every one
// of them is accepted so the verdict does not depend on the decoder. Anything
// else — a string, a fraction, a non-finite float, an integer past 2^53 - 1 —
// reports false. The sign is left to the caller.
func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		if integer, err := strconv.ParseInt(typed.String(), 10, 64); err == nil {
			return exactInteger(integer)
		}
		// A JSON number spelled with a fraction or an exponent ("1.0", "1e3")
		// still names an integer when its value is integral.
		float, err := strconv.ParseFloat(typed.String(), 64)
		if err != nil {
			return 0, false
		}
		return integralFloat(float)
	case float64:
		return integralFloat(typed)
	case int:
		return exactInteger(int64(typed))
	case int64:
		return exactInteger(typed)
	default:
		return 0, false
	}
}

func exactInteger(integer int64) (int64, bool) {
	if integer > maxExactInteger || integer < -maxExactInteger {
		return 0, false
	}
	return integer, true
}

func integralFloat(float float64) (int64, bool) {
	if math.IsNaN(float) || math.IsInf(float, 0) || float != math.Trunc(float) {
		return 0, false
	}
	if float > maxExactInteger || float < -maxExactInteger {
		return 0, false
	}
	return int64(float), true
}

// finiteNumber reports value as a float64 when it is a finite JSON number,
// decoded either as a json.Number or as a float64.
func finiteNumber(value any) (float64, bool) {
	var float float64
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseFloat(typed.String(), 64)
		if err != nil {
			return 0, false
		}
		float = parsed
	case float64:
		float = typed
	default:
		return 0, false
	}
	if math.IsNaN(float) || math.IsInf(float, 0) {
		return 0, false
	}
	return float, true
}

// decodeProtectedHeader reads the protected header of a compact JWS
// (RFC 7515 Section 7.1) without verifying anything. It is what lets `typ` and
// `alg` be judged before a key is resolved or a signature checked.
//
// The header is decoded with encoding/json's defaults, so JSON numbers appear
// as float64, which is what ResolveIssuerKeysFunc documents. A header that
// names critical extensions (RFC 7515 Section 4.1.11) is refused: this checker
// implements none, and a recipient that does not understand a critical
// extension must reject the JWS. The unencoded payload option of RFC 7797 is
// refused for the same reason and because a JWT never uses it
// (RFC 7797 Section 7).
func decodeProtectedHeader(token string) (map[string]any, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("%w: token is not a compact JWS: expected 3 segments, got %d", ErrStatusListTokenInvalid, len(segments))
	}
	raw, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return nil, fmt.Errorf("%w: protected header is not unpadded base64url: %w", ErrStatusListTokenInvalid, err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("%w: protected header is not a JSON object: %w", ErrStatusListTokenInvalid, err)
	}
	if header == nil {
		return nil, fmt.Errorf("%w: protected header is not a JSON object", ErrStatusListTokenInvalid)
	}
	if _, present := header["crit"]; present {
		return nil, fmt.Errorf("%w: protected header names critical extensions this checker does not implement", ErrStatusListTokenInvalid)
	}
	if _, present := header["b64"]; present {
		return nil, fmt.Errorf("%w: protected header carries b64, which a JWT does not use", ErrStatusListTokenInvalid)
	}
	return header, nil
}

// decodePayloadObject decodes a JWT payload as a JSON object, keeping numbers
// as json.Number so an integer claim is read exactly rather than through a
// float64.
func decodePayloadObject(payload []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims map[string]any
	if err := decoder.Decode(&claims); err != nil {
		return nil, fmt.Errorf("%w: payload is not a JSON object: %w", ErrStatusListTokenInvalid, err)
	}
	if claims == nil {
		return nil, fmt.Errorf("%w: payload is not a JSON object", ErrStatusListTokenInvalid)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: payload carries data after the JSON object", ErrStatusListTokenInvalid)
	}
	return claims, nil
}

// unverifiedIssuer reads the optional `iss` from a payload whose signature has
// not been checked yet, returning the empty string when the token carries
// none. The value only selects an external Status Issuer for
// Checker.AcceptStatusIssuer to judge; parseTokenClaims reads `iss` again from
// the verified payload.
func unverifiedIssuer(signed *jose.JSONWebSignature) (string, error) {
	claims, err := decodePayloadObject(signed.UnsafePayloadWithoutVerification())
	if err != nil {
		return "", err
	}
	return optionalIssuer(claims)
}

// optionalIssuer reads `iss`. draft-ietf-oauth-status-list-21 Section 5.1
// defines no `iss` for a Status List Token, so its absence is not an error;
// when present it is the RFC 7519 Section 4.1.1 StringOrURI, and a value of
// another type, or an empty string, is refused rather than treated as absent.
func optionalIssuer(claims map[string]any) (string, error) {
	raw, present := claims["iss"]
	if !present {
		return "", nil
	}
	issuer, isString := raw.(string)
	if !isString || issuer == "" {
		return "", fmt.Errorf("%w: iss, when present, must be a non-empty string", ErrStatusListTokenInvalid)
	}
	return issuer, nil
}

// resolveIssuerKeys asks the integrator's hook for the issuer's candidate keys
// and checks that the answer is usable: at least one key, and every key a valid
// public key. A private or symmetric key in the answer is refused rather than
// used: a private key means the hook is handing out material it should never
// hold in this path, and a symmetric key would turn the signature check into a
// MAC check that proves nothing about the issuer. Both describe the caller's
// configuration, so they are reported as ErrStatusListIssuerKeyUnresolved.
func (c *Checker) resolveIssuerKeys(ctx context.Context, request KeyRequest) ([]jose.JSONWebKey, error) {
	issuer := request.Issuer
	if c.ResolveIssuerKeys == nil {
		return nil, fmt.Errorf("%w: no issuer key resolver is configured", ErrStatusListIssuerKeyUnresolved)
	}
	keys, err := c.ResolveIssuerKeys(ctx, request)
	if errors.Is(err, ErrStatusListInsecureTransportForbidden) {
		return nil, fmt.Errorf("%w: issuer %q: %w", ErrStatusListInsecureTransportForbidden, issuer, err)
	}
	if errors.Is(err, ErrStatusListCertificateRejected) {
		return nil, fmt.Errorf("%w: issuer %q: %w", ErrStatusListCertificateRejected, issuer, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: resolving keys for issuer %q: %w", ErrStatusListIssuerKeyUnresolved, issuer, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no key resolved for issuer %q", ErrStatusListIssuerKeyUnresolved, issuer)
	}
	for position := range keys {
		key := &keys[position]
		if !key.IsPublic() || !key.Valid() {
			return nil, fmt.Errorf("%w: resolved key %d (kid %q) for issuer %q is not a valid public key", ErrStatusListIssuerKeyUnresolved, position, key.KeyID, issuer)
		}
	}
	return keys, nil
}

// verifySignature verifies signed under one of keys and returns the verified
// payload together with the `kid` of the key that verified it.
//
// headerKeyID is the token's `kid` header. It is unauthenticated, so it only
// orders the candidates: the keys it names are tried first and every other key
// after them. A key
// whose `use` says it is not for signatures, or whose `alg` names another
// algorithm than the token's (RFC 7517 Sections 4.2 and 4.4), is not a
// candidate. The verified key ID is read from the key, never from the header.
func verifySignature(signed *jose.JSONWebSignature, keys []jose.JSONWebKey, headerKeyID string) ([]byte, string, error) {
	if len(signed.Signatures) != 1 {
		return nil, "", fmt.Errorf("%w: token carries %d signatures, expected 1", ErrStatusListTokenInvalid, len(signed.Signatures))
	}
	algorithm := signed.Signatures[0].Protected.Algorithm

	usable := make([]jose.JSONWebKey, 0, len(keys))
	for _, key := range keys {
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if key.Algorithm != "" && key.Algorithm != algorithm {
			continue
		}
		usable = append(usable, key)
	}
	// The kid orders the candidates rather than filtering them: it is read
	// from a header nothing has authenticated yet, and an issuer that rotated
	// a key without renaming it must not be refused because a stale
	// identifier matched first.
	candidates := usable
	if headerKeyID != "" {
		candidates = make([]jose.JSONWebKey, 0, len(usable))
		for _, key := range usable {
			if key.KeyID == headerKeyID {
				candidates = append(candidates, key)
			}
		}
		for _, key := range usable {
			if key.KeyID != headerKeyID {
				candidates = append(candidates, key)
			}
		}
	}
	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("%w: none of the %d resolved keys is usable for alg %s", ErrStatusListSignatureInvalid, len(keys), algorithm)
	}
	// A key RFC 7518 forbids for the token's algorithm (an RSA modulus under
	// 2048 bits) is refused rather than tried, and the refusal is kept on the
	// error so the caller sees why the signature did not count.
	var weakKey error
	for _, key := range candidates {
		payload, err := commonjose.VerifySignature(signed, key.Key)
		if err == nil {
			return payload, key.KeyID, nil
		}
		if errors.Is(err, commonjose.ErrVerificationKeyTooWeak) {
			weakKey = err
		}
	}
	if weakKey != nil {
		return nil, "", fmt.Errorf("%w: none of %d candidate keys verified the token: %w", ErrStatusListSignatureInvalid, len(candidates), weakKey)
	}
	return nil, "", fmt.Errorf("%w: none of %d candidate keys verified the token", ErrStatusListSignatureInvalid, len(candidates))
}

// parseTokenClaims reads the claims draft-ietf-oauth-status-list Section 5.1
// defines out of a verified Status List Token payload.
//
// `iss` is optional and, when present, a non-empty string; `sub` must equal
// expectedSubject exactly,
// `iat` is REQUIRED and numeric, `exp` and `nbf` are optional and numeric,
// `ttl` is optional and a positive finite number (not necessarily an integer),
// and `status_list` must be an object carrying `bits` (1, 2, 4 or 8) and a
// non-empty string `lst`. A claim that is present with the wrong type — a null
// included — is refused rather than treated as absent. The validity window is
// not judged here; the caller compares it against its clock.
func parseTokenClaims(payload []byte, expectedSubject string) (*tokenClaims, error) {
	claims, err := decodePayloadObject(payload)
	if err != nil {
		return nil, err
	}
	issuer, err := optionalIssuer(claims)
	if err != nil {
		return nil, err
	}
	subject, isString := claims["sub"].(string)
	if !isString || subject != expectedSubject {
		return nil, fmt.Errorf("%w: sub %q does not equal the status list uri %q", ErrStatusListTokenInvalid, claims["sub"], expectedSubject)
	}

	issuedAt, present, err := numericDateClaim(claims, "iat")
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, fmt.Errorf("%w: iat is required", ErrStatusListTokenInvalid)
	}
	expiresAt, _, err := numericDateClaim(claims, "exp")
	if err != nil {
		return nil, err
	}
	notBefore, _, err := numericDateClaim(claims, "nbf")
	if err != nil {
		return nil, err
	}

	var ttlSeconds float64
	if raw, present := claims["ttl"]; present {
		ttl, isNumber := finiteNumber(raw)
		if !isNumber || ttl <= 0 {
			return nil, fmt.Errorf("%w: ttl must be a positive number, got %v", ErrStatusListTokenInvalid, raw)
		}
		ttlSeconds = ttl
	}

	statusList, isObject := claims["status_list"].(map[string]any)
	if !isObject || statusList == nil {
		return nil, fmt.Errorf("%w: status_list must be a JSON object", ErrStatusListTokenInvalid)
	}
	bits, isInteger := integerValue(statusList["bits"])
	if !isInteger {
		return nil, fmt.Errorf("%w: status_list bits must be 1, 2, 4 or 8, got %v", ErrStatusListTokenInvalid, statusList["bits"])
	}
	if err := validateBits(int(bits)); err != nil {
		return nil, err
	}
	encodedList, isString := statusList["lst"].(string)
	if !isString || encodedList == "" {
		return nil, fmt.Errorf("%w: status_list lst must be a non-empty string", ErrStatusListTokenInvalid)
	}

	return &tokenClaims{
		issuer:      issuer,
		subject:     subject,
		issuedAt:    issuedAt,
		expiresAt:   expiresAt,
		notBefore:   notBefore,
		ttlSeconds:  ttlSeconds,
		bits:        int(bits),
		encodedList: encodedList,
	}, nil
}

// numericDateClaim reads an optional NumericDate claim (RFC 7519 Section 2).
func numericDateClaim(claims map[string]any, name string) (time.Time, bool, error) {
	at, present, err := commonjose.NumericDateClaim(claims, name)
	if err != nil {
		return time.Time{}, true, fmt.Errorf("%w: %w", ErrStatusListTokenInvalid, err)
	}
	return at, present, nil
}

// checkX5CRules applies the profile's Status List Token x5c rules that need no
// trust anchor (HAIP 1.0 Section 6.1) to the unauthenticated header, before
// any key is resolved, and returns the decoded leaf certificate when the
// header carries an x5c. Require refuses a token without x5c; RejectSelfSigned
// a self-signed leaf. A malformed x5c is refused whenever a rule applies. With
// no rule, x5c is left to the key resolution hook.
func checkX5CRules(header map[string]any, rules profile.X5CRules) (*x509.Certificate, error) {
	if rules == (profile.X5CRules{}) {
		return nil, nil
	}
	raw, present := header["x5c"]
	if !present {
		if rules.Require {
			return nil, fmt.Errorf("%w: the profile requires the signing key in an x5c header", ErrStatusListCertificateRejected)
		}
		return nil, nil
	}
	chain, err := commonX509.DecodeX5CChain(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStatusListCertificateRejected, err)
	}
	if rules.RejectSelfSigned {
		if err := commonX509.RequireNonSelfSignedLeaf(chain, "status list token"); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrStatusListCertificateRejected, err)
		}
	}
	return chain[0], nil
}

// leafKeysOnly keeps the keys that are the x5c leaf's public key, for a
// profile that requires "the public key used to validate the signature" to be
// "included in the x5c JOSE header" (HAIP 1.0 Section 6.1). A hook that
// returns any other key has not resolved the key from the x5c header.
func leafKeysOnly(keys []jose.JSONWebKey, leaf *x509.Certificate) ([]jose.JSONWebKey, error) {
	if leaf == nil {
		return nil, fmt.Errorf("%w: the profile requires the signing key in an x5c header", ErrStatusListCertificateRejected)
	}
	leafKey := jose.JSONWebKey{Key: leaf.PublicKey}
	var matching []jose.JSONWebKey
	for _, key := range keys {
		if equal, err := commonjose.EqualPublicKey(key, leafKey); err == nil && equal {
			matching = append(matching, key)
		}
	}
	if len(matching) == 0 {
		return nil, fmt.Errorf("%w: no resolved key is the x5c leaf certificate's key", ErrStatusListCertificateRejected)
	}
	return matching, nil
}
