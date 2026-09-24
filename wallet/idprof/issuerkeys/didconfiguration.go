package issuerkeys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	commonjose "github.com/trustknots/vcknots/wallet/common/jose"
)

// didConfigurationPath is the well-known location DIF Well Known DID
// Configuration gives the document that links an origin to its DIDs.
const didConfigurationPath = "/.well-known/did-configuration.json"

// domainLinkageCredentialType is the credential type a Domain Linkage
// Credential must declare.
const domainLinkageCredentialType = "DomainLinkageCredential"

// domainLinkageAlgorithms are the JWS signature algorithms a Domain Linkage
// Credential may be signed with: the library's accepted asymmetric algorithms,
// never a MAC or "none".
var domainLinkageAlgorithms = commonjose.AcceptedSignatureAlgorithms()

// didConfigurationBinds reports whether the Credential Issuer's origin claims
// the DID through a DIF Well Known DID Configuration.
//
// The document is served by the origin and each entry of its `linked_dids` is
// signed by the DID it names, so a verified entry is a statement both parties
// made: the origin published it, and the DID controller signed it. One is not
// enough - a DID controller could sign a linkage to an origin it does not
// control, and an origin could list a DID that never agreed - which is why the
// signature is checked with key material resolved from the DID itself rather
// than with anything the document supplies.
func (r *Resolver) didConfigurationBinds(ctx context.Context, didValue string, request Request) (bool, error) {
	issuerURL, err := r.allowedURL(request.CredentialIssuer)
	if err != nil {
		return false, err
	}
	origin := originOf(issuerURL)
	configurationURL, err := url.Parse(origin + didConfigurationPath)
	if err != nil {
		return false, newMechanismError(ErrIssuerURLNotAllowed, "credential issuer origin does not form a URL")
	}

	document, err := r.fetchJSONObject(ctx, configurationURL)
	if err != nil {
		return false, err
	}
	var configuration struct {
		LinkedDIDs []json.RawMessage `json:"linked_dids"`
	}
	if err := json.Unmarshal(document, &configuration); err != nil {
		return false, newMechanismError(ErrIssuerMetadataInvalid, "did-configuration linked_dids is not an array")
	}

	for _, entry := range configuration.LinkedDIDs {
		var token string
		if err := json.Unmarshal(entry, &token); err != nil {
			// The specification also allows a linked DID in Data Integrity
			// form, which this library does not verify. Skipping it leaves the
			// JWT-encoded entries of the same document usable.
			continue
		}
		if r.domainLinkageBinds(ctx, token, didValue, origin, request) {
			return true, nil
		}
	}
	return false, nil
}

// domainLinkageBinds reports whether one `linked_dids` entry is a Domain
// Linkage Credential that links didValue to origin.
func (r *Resolver) domainLinkageBinds(ctx context.Context, token, didValue, origin string, request Request) bool {
	header, claims, err := decodeJWTSegments(token)
	if err != nil {
		return false
	}
	// A JWT-encoded Domain Linkage Credential declares `alg` and `kid` and no
	// media type. A `typ` means the token is some other kind of JWT that
	// happened to be listed here, and verifying it as a linkage would let a
	// token minted for another purpose stand in for one.
	if _, present := header["typ"]; present {
		return false
	}
	if _, ok := header["alg"].(string); !ok {
		return false
	}
	keyID, ok := header["kid"].(string)
	if !ok {
		return false
	}
	// The credential is about the DID and is issued by it: a self-issued
	// statement, which is exactly what the origin's half of the linkage is
	// paired with.
	if claims["iss"] != didValue || claims["sub"] != didValue {
		return false
	}

	// The linkage is the DID's own statement, so it must be signed with one
	// of that DID's keys. A `kid` naming a verification method of another DID
	// would let a second DID controller vouch for the first.
	if linkageDID := didReference(keyID); linkageDID != "" && linkageDID != didValue {
		return false
	}
	keys, err := r.resolveDIDKeys(ctx, didValue, keyID, request.CredentialIssuer)
	if err != nil {
		return false
	}

	signature, err := jose.ParseSigned(token, domainLinkageAlgorithms)
	if err != nil {
		return false
	}
	for _, key := range keys {
		if _, err := signature.Verify(key); err != nil {
			continue
		}
		if !withinJWTValidity(claims, r.now()) {
			continue
		}
		if domainLinkageClaimsMatch(claims, didValue, origin, r.now()) {
			return true
		}
	}
	return false
}

// decodeJWTSegments returns the protected header and the claims of a JWS
// compact serialization, without verifying anything.
//
// The header is read here rather than through a JOSE library because the checks
// this package makes are about which members are present at all - a `typ` that
// must be absent, an `alg` and a `kid` that must be strings - and a library
// that normalises a header into a struct cannot answer that.
func decodeJWTSegments(token string) (header, claims map[string]any, err error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, nil, newMechanismError(ErrIssuerMetadataInvalid, "linked DID is not a compact JWS")
	}
	header, err = decodeJWTSegment(segments[0])
	if err != nil {
		return nil, nil, err
	}
	claims, err = decodeJWTSegment(segments[1])
	if err != nil {
		return nil, nil, err
	}
	return header, claims, nil
}

// decodeJWTSegment decodes one base64url JWS segment into a JSON object.
func decodeJWTSegment(segment string) (map[string]any, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, newMechanismError(ErrIssuerMetadataInvalid, "linked DID segment is not base64url")
	}
	var object map[string]any
	if err := json.Unmarshal(decoded, &object); err != nil || object == nil {
		return nil, newMechanismError(ErrIssuerMetadataInvalid, "linked DID segment is not a JSON object")
	}
	return object, nil
}

// withinJWTValidity reports whether the registered `exp` and `nbf` claims of
// RFC 7519 section 4.1 admit now. A Domain Linkage Credential that carries
// neither is timeless, which the specification allows; one that carries either
// as something other than a NumericDate is not valid.
func withinJWTValidity(claims map[string]any, now time.Time) bool {
	expiry, present, err := commonjose.NumericDateClaim(claims, "exp")
	if err != nil || (present && !now.Before(expiry)) {
		return false
	}
	notBefore, present, err := commonjose.NumericDateClaim(claims, "nbf")
	if err != nil || (present && now.Before(notBefore)) {
		return false
	}
	return true
}

// domainLinkageClaimsMatch reports whether the credential inside a verified
// Domain Linkage Credential says what the linkage needs it to say: that this
// DID is linked to this origin, now.
//
// The `origin` comparison is an exact string match against the Credential
// Issuer's origin. A linkage is to an origin, not to a host: a credential that
// names another scheme or another port names another origin, and matching
// loosely would let a linkage published for one be read as a linkage for the
// other.
func domainLinkageClaimsMatch(claims map[string]any, didValue, origin string, now time.Time) bool {
	credential, ok := claims["vc"].(map[string]any)
	if !ok {
		return false
	}
	types, ok := credential["type"].([]any)
	if !ok {
		return false
	}
	declared := false
	for _, entry := range types {
		if entry == domainLinkageCredentialType {
			declared = true
			break
		}
	}
	if !declared {
		return false
	}
	subject, ok := credential["credentialSubject"].(map[string]any)
	if !ok || subject["id"] != didValue || subject["origin"] != origin {
		return false
	}
	// `issuer` is optional in the JWT encoding, because `iss` already carries
	// it; when it is present it must not disagree with the DID.
	if issuer, present := credential["issuer"]; present && issuer != didValue {
		return false
	}
	return credentialDateReached(credential["issuanceDate"], now) &&
		credentialDateNotPassed(credential["expirationDate"], now)
}

// credentialDateReached reports whether an `issuanceDate` is absent or already
// in the past. A value that is a string but not a timestamp fails: a date the
// verifier cannot read is not a date it may ignore.
func credentialDateReached(value any, now time.Time) bool {
	text, ok := value.(string)
	if !ok {
		return true
	}
	parsed, ok := parseCredentialDate(text)
	return ok && !parsed.After(now)
}

// credentialDateNotPassed reports whether an `expirationDate` is absent or
// still in the future, with an unreadable value failing for the same reason.
func credentialDateNotPassed(value any, now time.Time) bool {
	text, ok := value.(string)
	if !ok {
		return true
	}
	parsed, ok := parseCredentialDate(text)
	return ok && !parsed.Before(now)
}

// credentialDateLayouts are the forms a W3C VC Data Model 1.1 date is written
// in: an XML Schema dateTime, which is RFC 3339 with an optional offset, and a
// bare date, which the DID Configuration examples use.
var credentialDateLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"}

// parseCredentialDate reads a VC Data Model date. A dateTime without an offset
// is read as UTC.
func parseCredentialDate(text string) (time.Time, bool) {
	for _, layout := range credentialDateLayouts {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
