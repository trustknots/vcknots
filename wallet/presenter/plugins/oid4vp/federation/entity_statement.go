package federation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
)

// entityStatementTyp is the `typ` JOSE header every Entity Statement carries
// (OpenID Federation 1.0 Section 3: "Entity Statements ... MUST be explicitly
// typed by using the typ header parameter ... value entity-statement+jwt").
// The HTTP media type application/entity-statement+jwt is not an accepted
// spelling of it.
const entityStatementTyp = "entity-statement+jwt"

// standardEntityStatementClaims are the claims OpenID Federation 1.0 Section
// 3.1 defines. The same section forbids listing any of them in `crit`.
var standardEntityStatementClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "iat": {}, "exp": {}, "jwks": {}, "metadata": {},
	"crit": {}, "authority_hints": {}, "trust_anchor_hints": {}, "trust_marks": {},
	"trust_mark_issuers": {}, "trust_mark_owners": {}, "constraints": {},
	"metadata_policy": {}, "metadata_policy_crit": {}, "source_endpoint": {},
	"aud": {}, "trust_anchor": {},
}

// EntityStatement is one signature-verified Entity Statement of a Trust Chain
// (OpenID Federation 1.0 Section 3). An Entity Configuration is the statement
// an Entity issues about itself (Issuer equals Subject); a Subordinate
// Statement is issued by a superior about its subordinate.
type EntityStatement struct {
	// Issuer and Subject are the `iss` and `sub` Entity Identifiers.
	Issuer, Subject string
	// IssuedAt and ExpiresAt are `iat` and `exp`, in UTC.
	IssuedAt, ExpiresAt time.Time
	// JWKS is the `jwks` claim: the Federation Entity Keys of the subject.
	// Keys this library cannot parse are left out.
	JWKS jose.JSONWebKeySet
	// Metadata is the `metadata` claim, keyed by Entity Type, or nil.
	Metadata map[string]any
	// MetadataPolicy is the `metadata_policy` claim of a Subordinate
	// Statement, keyed by Entity Type, or nil.
	MetadataPolicy map[string]any
	// Constraints is the `constraints` claim of a Subordinate Statement, or
	// nil.
	Constraints map[string]any
}

// isSubordinate reports whether the statement is issued about another Entity.
func (s *EntityStatement) isSubordinate() bool { return s.Issuer != s.Subject }

// decodedStatement is an Entity Statement whose claims have been read but whose
// signature has not been verified yet.
type decodedStatement struct {
	raw string
	EntityStatement
	issuedAtSeconds  int64
	expiresAtSeconds int64
}

// decodeEntityStatement reads and checks the claims of one Entity Statement
// without verifying its signature (OpenID Federation 1.0 Sections 3.1 and
// 10.2). The signature is verified once the chain says which keys must have
// produced it.
func decodeEntityStatement(raw string) (*decodedStatement, error) {
	payload, err := unverifiedJWTPayload(raw)
	if err != nil {
		return nil, failure(ErrTrustChainInvalid, "entity statement is not a JWT")
	}
	statement := &decodedStatement{raw: raw}
	if statement.Issuer, err = requiredStringClaim(payload, "iss"); err != nil {
		return nil, err
	}
	if statement.Subject, err = requiredStringClaim(payload, "sub"); err != nil {
		return nil, err
	}
	if statement.issuedAtSeconds, err = requiredTimeClaim(payload, "iat"); err != nil {
		return nil, err
	}
	if statement.expiresAtSeconds, err = requiredTimeClaim(payload, "exp"); err != nil {
		return nil, err
	}
	if statement.expiresAtSeconds <= statement.issuedAtSeconds {
		return nil, failure(ErrTrustChainInvalid, "entity statement expiration is invalid")
	}
	statement.IssuedAt = time.Unix(statement.issuedAtSeconds, 0).UTC()
	statement.ExpiresAt = time.Unix(statement.expiresAtSeconds, 0).UTC()
	if err := checkCritClaim(payload); err != nil {
		return nil, err
	}
	if err := checkSubordinateOnlyClaims(payload, statement.isSubordinate()); err != nil {
		return nil, err
	}
	if statement.JWKS, err = jwksClaim(payload["jwks"]); err != nil {
		return nil, err
	}
	if statement.Metadata, err = optionalObjectClaim(payload, "metadata"); err != nil {
		return nil, err
	}
	if statement.MetadataPolicy, err = optionalObjectClaim(payload, "metadata_policy"); err != nil {
		return nil, err
	}
	if statement.Constraints, err = optionalObjectClaim(payload, "constraints"); err != nil {
		return nil, err
	}
	return statement, nil
}

// unverifiedJWTPayload decodes the payload of a compact JWS as a JSON object.
func unverifiedJWTPayload(raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errNotCompactJWS
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	return decodeJSONObject(payload)
}

var errNotCompactJWS = errors.New("not a compact JWS")

// checkSubordinateOnlyClaims applies OpenID Federation 1.0 Section 3.1:
// metadata_policy, constraints and metadata_policy_crit "MUST NOT" appear in an
// Entity Configuration; they are claims of a Subordinate Statement only.
func checkSubordinateOnlyClaims(payload map[string]any, subordinate bool) error {
	for _, name := range []string{"metadata_policy", "constraints"} {
		if _, present := payload[name]; present && !subordinate {
			return failure(ErrTrustChainInvalid, "entity statement %s claim is only allowed in subordinate statements", name)
		}
	}
	value, present := payload["metadata_policy_crit"]
	if !present {
		return nil
	}
	if !subordinate {
		return failure(ErrTrustChainInvalid, "entity statement metadata_policy_crit claim is only allowed in subordinate statements")
	}
	operators, err := nonEmptyStringArrayClaim(value, "metadata_policy_crit")
	if err != nil {
		return err
	}
	// Section 6.1: a critical operator the Resolver does not understand
	// makes the statement unusable. Every operator this library understands is
	// a standard one, which Section 3.1 forbids listing here.
	// Only the first listed operator is ever examined, since it alone already
	// decides the refusal.
	if isStandardPolicyOperator(operators[0]) {
		return failure(ErrTrustChainInvalid, "entity statement metadata_policy_crit claim must not include standard metadata policy operators")
	}
	return failure(ErrTrustChainInvalid, "metadata_policy_crit operator %q is unsupported", operators[0])
}

// checkCritClaim applies the `crit` claim of OpenID Federation 1.0 Section
// 3.1: it lists extension claims that "MUST be understood and processed". This
// library understands no extension claim, so any listed claim makes the
// statement unusable.
func checkCritClaim(payload map[string]any) error {
	value, present := payload["crit"]
	if !present {
		return nil
	}
	claims, err := nonEmptyStringArrayClaim(value, "crit")
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(claims))
	for _, claim := range claims {
		if _, duplicate := seen[claim]; duplicate {
			return failure(ErrTrustChainInvalid, "entity statement crit claim must not contain duplicates")
		}
		seen[claim] = struct{}{}
	}
	// Only the first listed claim is ever examined, since it alone already
	// decides the refusal.
	claim := claims[0]
	if _, standard := standardEntityStatementClaims[claim]; standard {
		return failure(ErrTrustChainInvalid, "entity statement crit claim must not include standard claims")
	}
	if _, present := payload[claim]; !present {
		return failure(ErrTrustChainInvalid, "entity statement critical claim %q is not present", claim)
	}
	return failure(ErrTrustChainInvalid, "entity statement critical claim %q is unsupported", claim)
}

func nonEmptyStringArrayClaim(value any, name string) ([]string, error) {
	values, ok := asNonEmptyStringArray(value)
	if !ok || len(values) == 0 {
		return nil, failure(ErrTrustChainInvalid, "entity statement %s claim must be a non-empty string array", name)
	}
	return values, nil
}

func requiredStringClaim(payload map[string]any, name string) (string, error) {
	value, _ := payload[name].(string)
	if value == "" {
		return "", failure(ErrTrustChainInvalid, "entity statement %s claim is required", name)
	}
	return value, nil
}

// requiredTimeClaim reads a positive integer NumericDate claim.
func requiredTimeClaim(payload map[string]any, name string) (int64, error) {
	value, ok := jsonInteger(payload[name])
	if !ok || value <= 0 {
		return 0, failure(ErrTrustChainInvalid, "entity statement %s claim is required", name)
	}
	return value, nil
}

func optionalObjectClaim(payload map[string]any, name string) (map[string]any, error) {
	value, present := payload[name]
	if !present {
		return nil, nil
	}
	object, ok := asObject(value)
	if !ok {
		return nil, failure(ErrTrustChainInvalid, "entity statement %s claim must be an object", name)
	}
	return object, nil
}

// jwksClaim reads the REQUIRED `jwks` claim (OpenID Federation 1.0 Section
// 3.1). A key this library cannot parse is left out rather than refusing the
// statement, since it cannot verify anything either way; only the public part
// of a key is ever kept.
func jwksClaim(value any) (jose.JSONWebKeySet, error) {
	object, ok := asObject(value)
	keys, isArray := asArray(object["keys"])
	if !ok || !isArray || len(keys) == 0 {
		return jose.JSONWebKeySet{}, failure(ErrTrustChainInvalid, "entity statement jwks claim is required")
	}
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(keys))}
	for _, raw := range keys {
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(encoded); err != nil || !key.Valid() {
			continue
		}
		public := key.Public()
		if !public.Valid() {
			continue
		}
		set.Keys = append(set.Keys, public)
	}
	return set, nil
}

// verifyStatementSignature verifies one Entity Statement with the keys the
// chain designates for it (OpenID Federation 1.0 Section 10.2). The protected
// header must type the JWT as an Entity Statement and name, in kid, a key of
// that set; the key is then selected the way a JWKS verifier does, by kid,
// by alg and use when the key states them.
func verifyStatementSignature(raw string, jwks jose.JSONWebKeySet) error {
	signed, err := jose.ParseSigned(raw, commonJOSE.AcceptedSignatureAlgorithms())
	if err != nil || len(signed.Signatures) != 1 {
		return failure(ErrTrustChainInvalid, "entity statement header is invalid")
	}
	header := signed.Signatures[0].Protected
	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != entityStatementTyp {
		return failure(ErrTrustChainInvalid, "entity statement typ is invalid")
	}
	if header.Algorithm == "" {
		return failure(ErrTrustChainInvalid, "entity statement alg is required")
	}
	if header.KeyID == "" {
		return failure(ErrTrustChainInvalid, "entity statement kid is required")
	}
	candidates := jwks.Key(header.KeyID)
	if len(candidates) == 0 {
		return failure(ErrTrustChainInvalid, "entity statement kid is not in JWKS")
	}
	for _, key := range candidates {
		if key.Algorithm != "" && key.Algorithm != header.Algorithm {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if _, err := signed.Verify(key); err == nil {
			return nil
		}
	}
	return failure(ErrTrustChainInvalid, "entity statement signature is invalid")
}
