package oid4vp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/trustknots/vcknots/wallet/credential"
)

// DcqlQuery represents the dcql_query Authorization Request parameter
// defined in OID4VP 1.0 Section 6 (Digital Credentials Query Language).
type DcqlQuery struct {
	Credentials    []CredentialQuery    `json:"credentials"`               // required, non-empty array
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"` // optional, non-empty array when present
}

// TrustedAuthority is one entry of the DCQL trusted_authorities query
// (OID4VP 1.0 Section 6.1.1). Each entry identifies expected Issuers or trust
// frameworks by type. This wallet evaluates the "aki" (Authority Key
// Identifier) type, which HAIP 1.0 section 5 requires to be supported, and
// "openid_federation"; an entry of another type matches no credential.
type TrustedAuthority struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

// CredentialQuery represents a request for a presentation of one or more
// matching Credentials (OID4VP 1.0 Section 6.1).
type CredentialQuery struct {
	ID     string         `json:"id"`     // required, alphanumeric, underscore and hyphen only
	Format string         `json:"format"` // required, Credential Format Identifier
	Meta   map[string]any `json:"meta"`   // required; Appendix B defines the members each format requires
	// Multiple indicates whether multiple Credentials can be returned for this
	// Credential Query. Defaults to false when omitted.
	Multiple  bool             `json:"multiple,omitempty"`
	Claims    []DCQLClaimQuery `json:"claims,omitempty"`
	ClaimSets [][]string       `json:"claim_sets,omitempty"`
	// TrustedAuthorities optionally constrains the Issuers or trust frameworks
	// the Verifier accepts (OID4VP 1.0 Section 6.1.1).
	TrustedAuthorities []TrustedAuthority `json:"trusted_authorities,omitempty"`
	// RequireCryptographicHolderBinding defaults to true when omitted (OID4VP
	// 1.0 section 6.1). A pointer preserves an explicitly permitted unbound VC.
	RequireCryptographicHolderBinding *bool `json:"require_cryptographic_holder_binding,omitempty"`
}

// RequiresHolderBinding reports the effective Credential Query requirement.
func (q CredentialQuery) RequiresHolderBinding() bool {
	return q.RequireCryptographicHolderBinding == nil || *q.RequireCryptographicHolderBinding
}

// CredentialSetQuery represents a request for one or more Credential Queries
// to be satisfied (OID4VP 1.0 Section 6.2).
type CredentialSetQuery struct {
	Options  [][]string `json:"options,omitempty"`
	Required *bool      `json:"required,omitempty"`
}

// IsRequired reports the OID4VP 1.0 Section 6.2 default for this Credential Set
// Query: "If omitted, the default value is true", so a set that names no
// `required` member must be answered. Callers read the default here instead of
// re-deriving it, which is what makes a Wallet's own selection screen agree
// with ValidateDCQLMatches about which sets it may leave
// unanswered.
func (s CredentialSetQuery) IsRequired() bool {
	return s.Required == nil || *s.Required
}

// AuthorizationRequestError is a validation failure of an OID4VP Authorization
// Request. It carries the OAuth 2.0 / OID4VP error code that should be sent
// back to the Verifier in the authorization error response.
type AuthorizationRequestError struct {
	Code OAuthAuthzError
	Err  error
	// response is set when the refused request names a Response URI the
	// Wallet may answer (see ResponseURI in errors.go).
	response *errorResponseTarget
}

// Error implements error.
func (e *AuthorizationRequestError) Error() string {
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

// ErrorCode names the outcome: the Wallet terminated request processing and
// answered the Verifier with an OAuth 2.0 Authorization Error Response. Code
// carries the OID4VP error the Verifier is told; this names what happened.
func (e *AuthorizationRequestError) ErrorCode() string {
	return "oid4vp_request_rejected"
}

// Unwrap returns the wrapped error.
func (e *AuthorizationRequestError) Unwrap() error {
	return e.Err
}

func newAuthorizationRequestError(code OAuthAuthzError, format string, args ...any) *AuthorizationRequestError {
	return &AuthorizationRequestError{Code: code, Err: fmt.Errorf(format, args...)}
}

// supportedCredentialFormats are the OID4VP Credential Format Identifiers this
// wallet can serialize presentations for, derived from
// credential.SupportedSerializationFlavor.OID4VPFormatIdentifier (the mock
// flavor is excluded as it is for testing only).
var supportedCredentialFormats = func() map[string]bool {
	formats := make(map[string]bool)
	for _, flavor := range []credential.SupportedSerializationFlavor{credential.JwtVc, credential.SDJwtVC} {
		vcFormat, _, err := flavor.OID4VPFormatIdentifier()
		if err == nil {
			formats[vcFormat] = true
		}
	}
	return formats
}()

// credentialQueryIDPattern is the allowed syntax for Credential Query ids:
// a non-empty string consisting of alphanumeric, underscore and hyphen characters.
var credentialQueryIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// haipCredentialFormats are the only DCQL Credential Format Identifiers HAIP
// 1.0 permits: SD-JWT VC is dc+sd-jwt and ISO mdoc is mso_mdoc (HAIP §5.3.2,
// §6.1). Other Final formats are valid for OpenID4VP but not for HAIP.
var haipCredentialFormats = map[string]bool{
	"dc+sd-jwt": true,
	"mso_mdoc":  true,
}

// parseDcqlQuery validates the dcql_query Authorization Request parameter and
// returns the typed query for the Final profile.
func parseDcqlQuery(raw any) (*DcqlQuery, error) {
	return parseDcqlQueryWithHAIP(raw, false)
}

// parseDcqlQueryWithHAIP validates the dcql_query Authorization Request
// parameter and returns the typed query. raw may be a JSON string (query
// parameter) or an already-decoded JSON object (Request Object claim). When
// haip is true the accepted Credential Format Identifiers are restricted to
// HAIP 1.0's dc+sd-jwt and mso_mdoc.
//
// Validation failures are returned as *AuthorizationRequestError:
//   - invalid_request for syntactically malformed queries
//   - vp_formats_not_supported when a requested Credential format is not supported
func parseDcqlQueryWithHAIP(raw any, haip bool) (*DcqlQuery, error) {
	queryMap, err := decodeDcqlQueryObject(raw)
	if err != nil {
		return nil, err
	}

	credentials, exists := queryMap["credentials"]
	if !exists {
		return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials is required")
	}
	credentialsArray, ok := credentials.([]any)
	if !ok || len(credentialsArray) == 0 {
		return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials must be a non-empty array")
	}

	seenIDs := make(map[string]bool, len(credentialsArray))
	for i, item := range credentialsArray {
		credentialQuery, ok := item.(map[string]any)
		if !ok {
			return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d] must be a JSON object", i)
		}
		if err := validateCredentialQuery(i, credentialQuery, seenIDs, haip); err != nil {
			return nil, err
		}
	}

	if credentialSets, exists := queryMap["credential_sets"]; exists {
		setsArray, ok := credentialSets.([]any)
		if !ok || len(setsArray) == 0 {
			return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query.credential_sets must be a non-empty array when present")
		}
		for i, item := range setsArray {
			set, ok := item.(map[string]any)
			if !ok {
				return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query.credential_sets[%d] must be a JSON object", i)
			}
			if err := validateDCQLSetOptions(set["options"], fmt.Sprintf("credential_sets[%d].options", i), seenIDs, false); err != nil {
				return nil, err
			}
			if required, exists := set["required"]; exists {
				if _, ok := required.(bool); !ok {
					return nil, newAuthorizationRequestError(InvalidRequestError, "credential_sets[%d].required must be a boolean", i)
				}
			}
		}
	}

	return dcqlQueryFromObject(queryMap)
}

func dcqlQueryFromObject(queryMap map[string]any) (*DcqlQuery, error) {
	// Re-encode the validated generic representation into the typed struct.
	jsonBytes, err := json.Marshal(queryMap)
	if err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "failed to re-encode dcql_query: %v", err)
	}
	var query DcqlQuery
	decoder := json.NewDecoder(bytes.NewReader(jsonBytes))
	decoder.UseNumber()
	if err := decoder.Decode(&query); err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "invalid dcql_query: %v", err)
	}

	return &query, nil
}

// decodeDcqlQueryObject normalizes the raw dcql_query parameter value into a
// generic JSON object representation.
func decodeDcqlQueryObject(raw any) (map[string]any, error) {
	switch v := raw.(type) {
	case string:
		var decoded any
		// Preserve integer precision for claims[].values, including values beyond
		// float64's exact integer range. Reject trailing JSON as Unmarshal did.
		if !json.Valid([]byte(v)) {
			return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query must be valid JSON")
		}
		decoder := json.NewDecoder(strings.NewReader(v))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query must be valid JSON: %v", err)
		}
		queryMap, ok := decoded.(map[string]any)
		if !ok {
			return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query must be a JSON object")
		}
		return queryMap, nil
	case map[string]any:
		return v, nil
	default:
		return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query must be a JSON object")
	}
}

// validateCredentialQuery validates a single Credential Query object as per
// OID4VP 1.0 Section 6.1, recording its id in seenIDs for duplicate detection.
func validateCredentialQuery(index int, credentialQuery map[string]any, seenIDs map[string]bool, haip bool) error {
	rawID, exists := credentialQuery["id"]
	if !exists {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].id is required", index)
	}
	id, ok := rawID.(string)
	if !ok || !credentialQueryIDPattern.MatchString(id) {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].id must be a non-empty string of alphanumeric, underscore or hyphen characters", index)
	}
	if seenIDs[id] {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].id %q is duplicated within the request", index, id)
	}
	seenIDs[id] = true

	rawFormat, exists := credentialQuery["format"]
	if !exists {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].format is required", index)
	}
	format, ok := rawFormat.(string)
	if !ok || format == "" {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].format must be a non-empty string", index)
	}
	if haip && !haipCredentialFormats[format] {
		// HAIP §5.3.2 / §6.1: HAIP only uses the dc+sd-jwt and mso_mdoc
		// Credential Format Identifiers. A Final format such as jwt_vc_json is
		// invalid rather than merely unsupported under this profile.
		return newAuthorizationRequestError(InvalidRequestError, "HAIP profile only permits the dc+sd-jwt and mso_mdoc credential formats, got %q", format)
	}
	if !supportedCredentialFormats[format] {
		return newAuthorizationRequestError(VPFormatsNotSupportedError, "dcql_query.credentials[%d].format %q is not supported by this wallet", index, format)
	}

	rawMeta, exists := credentialQuery["meta"]
	if !exists {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].meta is required", index)
	}
	// An empty meta object means no additional constraints on the metadata or
	// validity of the requested Credential.
	meta, ok := rawMeta.(map[string]any)
	if !ok {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].meta must be a JSON object", index)
	}
	if err := validateCredentialQueryMeta(index, format, meta); err != nil {
		return err
	}

	// multiple is optional and defaults to false; when present it must be a boolean.
	if rawMultiple, exists := credentialQuery["multiple"]; exists {
		if _, ok := rawMultiple.(bool); !ok {
			return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].multiple must be a boolean", index)
		}
	}
	if rawBinding, exists := credentialQuery["require_cryptographic_holder_binding"]; exists {
		if _, ok := rawBinding.(bool); !ok {
			return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].require_cryptographic_holder_binding must be a boolean", index)
		}
	}
	if rawAuthorities, exists := credentialQuery["trusted_authorities"]; exists {
		if err := validateTrustedAuthorities(index, rawAuthorities); err != nil {
			return err
		}
	}

	return validateDCQLClaimQueries(credentialQuery)
}

// validateTrustedAuthorities enforces the OID4VP 1.0 Section 6.1.1 shape:
// a non-empty array of objects whose type is a non-empty string and whose
// values is a non-empty array of non-empty strings.
func validateTrustedAuthorities(index int, raw any) error {
	authorities, ok := raw.([]any)
	if !ok || len(authorities) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].trusted_authorities must be a non-empty array", index)
	}
	for i, rawAuthority := range authorities {
		authority, ok := rawAuthority.(map[string]any)
		if !ok {
			return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].trusted_authorities[%d] must be an object", index, i)
		}
		authorityType, ok := authority["type"].(string)
		if !ok || authorityType == "" {
			return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].trusted_authorities[%d].type must be a non-empty string", index, i)
		}
		values, ok := authority["values"].([]any)
		if !ok || len(values) == 0 {
			return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].trusted_authorities[%d].values must be a non-empty array of strings", index, i)
		}
		for _, rawValue := range values {
			if value, ok := rawValue.(string); !ok || value == "" {
				return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].trusted_authorities[%d].values must contain only non-empty strings", index, i)
			}
		}
	}
	return nil
}

// validateCredentialQueryMeta enforces the format-specific members of the
// Credential Query meta object that OID4VP 1.0 Appendix B makes REQUIRED:
// type_values for W3C VCs (B.1.1), doctype_value for mdoc (B.2.3) and
// vct_values for SD-JWT VC (B.3.5). Meta keys of other formats stay
// unconstrained beyond being a JSON object.
func validateCredentialQueryMeta(index int, format string, meta map[string]any) error {
	switch format {
	case "dc+sd-jwt":
		values, ok := meta["vct_values"].([]any)
		if !ok || len(values) == 0 || !allNonEmptyStrings(values) {
			return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].meta.vct_values must be a non-empty array of non-empty strings", index)
		}
	case "jwt_vc_json", "ldp_vc":
		alternatives, ok := meta["type_values"].([]any)
		if !ok || len(alternatives) == 0 {
			return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].meta.type_values must be a non-empty array of string arrays", index)
		}
		for _, rawAlternative := range alternatives {
			types, ok := rawAlternative.([]any)
			if !ok || len(types) == 0 || !allNonEmptyStrings(types) {
				return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].meta.type_values must contain only non-empty arrays of non-empty strings", index)
			}
		}
	case "mso_mdoc":
		if doctype, ok := meta["doctype_value"].(string); !ok || doctype == "" {
			return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].meta.doctype_value must be a non-empty string", index)
		}
	}
	return nil
}

func allNonEmptyStrings(values []any) bool {
	for _, value := range values {
		if text, ok := value.(string); !ok || text == "" {
			return false
		}
	}
	return true
}

func validateDCQLClaimQueries(query map[string]any) error {
	rawClaims, hasClaims := query["claims"]
	rawSets, hasSets := query["claim_sets"]
	if !hasClaims {
		if hasSets {
			return newAuthorizationRequestError(InvalidRequestError, "claim_sets requires claims")
		}
		return nil
	}
	claims, ok := rawClaims.([]any)
	if !ok || len(claims) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "claims must be a non-empty array")
	}
	ids := map[string]bool{}
	for i, rawClaim := range claims {
		claim, ok := rawClaim.(map[string]any)
		if !ok {
			return newAuthorizationRequestError(InvalidRequestError, "claims[%d] must be an object", i)
		}
		if rawID, exists := claim["id"]; exists || hasSets {
			id, ok := rawID.(string)
			if !ok || !credentialQueryIDPattern.MatchString(id) || ids[id] {
				return newAuthorizationRequestError(InvalidRequestError, "claims[%d].id must be a unique non-empty alphanumeric, underscore or hyphen identifier", i)
			}
			ids[id] = true
		}
		path, ok := claim["path"].([]any)
		if !ok || len(path) == 0 {
			return newAuthorizationRequestError(InvalidRequestError, "claims[%d].path must be a non-empty array", i)
		}
		// OID4VP 1.0 Section 7: a claims path pointer is an array of strings,
		// nulls and non-negative integers.
		for _, segment := range path {
			switch segment.(type) {
			case string, nil:
				continue
			default:
				if _, ok := dcqlPathIndex(segment); !ok {
					return newAuthorizationRequestError(InvalidRequestError, "claims[%d].path uses an unsupported non-string component", i)
				}
			}
		}
		if rawValues, exists := claim["values"]; exists {
			values, ok := rawValues.([]any)
			if !ok || len(values) == 0 {
				return newAuthorizationRequestError(InvalidRequestError, "claims[%d].values must be a non-empty array", i)
			}
			for _, value := range values {
				if !isDCQLClaimValue(value) {
					return newAuthorizationRequestError(InvalidRequestError, "claims[%d].values must contain only strings, integers or booleans", i)
				}
			}
		}
	}
	if hasSets {
		return validateDCQLSetOptions(rawSets, "claim_sets", ids, true)
	}
	return nil
}

func validateDCQLSetOptions(raw any, name string, ids map[string]bool, allowEmptyOption bool) error {
	options, ok := raw.([]any)
	if !ok || len(options) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "%s must be a non-empty array of identifier arrays", name)
	}
	for _, rawOption := range options {
		option, ok := rawOption.([]any)
		if !ok || option == nil {
			return newAuthorizationRequestError(InvalidRequestError, "%s options must be identifier arrays", name)
		}
		if !allowEmptyOption && len(option) == 0 {
			return newAuthorizationRequestError(InvalidRequestError, "%s options must not be empty", name)
		}
		for _, rawID := range option {
			id, ok := rawID.(string)
			if !ok || !ids[id] {
				return newAuthorizationRequestError(InvalidRequestError, "%s references an undefined identifier", name)
			}
		}
	}
	return nil
}

// DCQLClaimQuery preserves the DCQL claims path pointer. A path component is a
// string (object key), null (all array elements) or a non-negative integer
// (array index), per OID4VP 1.0 Section 7.
type DCQLClaimQuery struct {
	ID     string `json:"id,omitempty"`
	Path   []any  `json:"path,omitempty"`
	Values []any  `json:"values,omitempty"`
}
