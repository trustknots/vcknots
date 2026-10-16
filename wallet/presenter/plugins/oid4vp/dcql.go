package oid4vp

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"

	"github.com/trustknots/vcknots/wallet/credential"
)

// DcqlQuery represents the dcql_query Authorization Request parameter
// defined in OID4VP 1.0 Section 6 (Digital Credentials Query Language).
type DcqlQuery struct {
	Credentials    []CredentialQuery    `json:"credentials"`               // required, non-empty array
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"` // optional, non-empty array when present
}

// CredentialQuery represents a request for a presentation of one or more
// matching Credentials (OID4VP 1.0 Section 6.1).
type CredentialQuery struct {
	ID     string         `json:"id"`     // required, alphanumeric, underscore and hyphen only
	Format string         `json:"format"` // required, Credential Format Identifier
	Meta   map[string]any `json:"meta"`   // required, an empty object means no additional constraints
	// Multiple indicates whether multiple Credentials can be returned for this
	// Credential Query. Defaults to false when omitted.
	Multiple bool `json:"multiple,omitempty"`
	// Claims lists the claims requested from the Credential. It is nil when the
	// Verifier requests no selectively disclosable claims (Section 6.4.1).
	Claims []ClaimQuery `json:"claims,omitempty"`
	// ClaimSets lists alternative combinations of Claims ids.
	ClaimSets [][]string `json:"claim_sets,omitempty"`
}

// ClaimQuery is one entry of a Credential Query's claims (OID4VP 1.0 Section 6.3).
type ClaimQuery struct {
	ID string `json:"id,omitempty"`
	// Path is a claims path pointer (Section 7): strings, nulls and non-negative integers.
	Path []any `json:"path"`
}

// CredentialSetQuery represents a request for one or more Credential Queries
// to be satisfied (OID4VP 1.0 Section 6.2).
type CredentialSetQuery struct {
	Options  [][]string `json:"options,omitempty"`
	Required *bool      `json:"required,omitempty"`
}

// Matches reports whether a held Credential with the given Credential Format
// Identifier satisfies the format and meta constraints of the Credential Query
// (Section 6.1, Appendix B). Its claims are checked when the presentation is
// serialized.
func (q *CredentialQuery) Matches(format string, cred *credential.Credential) bool {
	if q.Format != format || cred == nil {
		return false
	}
	// Only the dc+sd-jwt meta (vct_values, Appendix B.3.5) is applied; other formats
	// match on format alone. Add type_values when jwt_vc_json needs it.
	if format == "dc+sd-jwt" {
		return matchVctValues(q.Meta, cred.Types)
	}
	return true
}

// matchVctValues requires the SD-JWT VC type (vct) to be one of vct_values. Type
// inheritance is not resolved. Without vct_values nothing is constrained.
func matchVctValues(meta map[string]any, credentialTypes []string) bool {
	raw, present := meta["vct_values"]
	if !present {
		return true
	}
	values, ok := raw.([]any)
	if !ok {
		return false
	}
	for _, v := range values {
		if vct, ok := v.(string); ok && slices.Contains(credentialTypes, vct) {
			return true
		}
	}
	return false
}

// SelectCredentialQuery returns the Credential Query the wallet answers (OID4VP 1.0
// Section 6.4.2). held reports whether the wallet holds a Credential matching a
// Credential Query. It fails with access_denied when a required Credential is not
// held. Optional Credential Set Queries are answered only when nothing is required.
func (d *DcqlQuery) SelectCredentialQuery(held func(*CredentialQuery) bool) (*CredentialQuery, error) {
	byID := make(map[string]*CredentialQuery, len(d.Credentials))
	for i := range d.Credentials {
		byID[d.Credentials[i].ID] = &d.Credentials[i]
	}
	satisfiable := func(ids []string) bool {
		for _, id := range ids {
			q, ok := byID[id]
			if !ok || !held(q) {
				return false
			}
		}
		return true
	}
	// firstSatisfiable returns the first option the wallet can satisfy, preferring one
	// that keeps the answer at a single Credential; Section 6.4.3 leaves the choice
	// among options to the Wallet.
	firstSatisfiable := func(options [][]string, required []string) []string {
		var first []string
		for _, option := range options {
			if !satisfiable(option) {
				continue
			}
			if first == nil {
				first = option
			}
			ids := map[string]bool{}
			for _, id := range append(slices.Clone(required), option...) {
				ids[id] = true
			}
			if len(ids) == 1 {
				return option
			}
		}
		return first
	}

	var required []string
	if len(d.CredentialSets) == 0 {
		for _, q := range d.Credentials {
			required = append(required, q.ID)
		}
		if !satisfiable(required) {
			return nil, newAuthorizationRequestError(AccessDeniedError, "the wallet does not hold every requested Credential")
		}
	} else {
		for i, set := range d.CredentialSets {
			if set.Required != nil && !*set.Required {
				continue
			}
			option := firstSatisfiable(set.Options, required)
			if option == nil {
				return nil, newAuthorizationRequestError(AccessDeniedError, "the wallet cannot satisfy dcql_query.credential_sets[%d]", i)
			}
			required = append(required, option...)
		}
		if len(required) == 0 {
			for _, set := range d.CredentialSets {
				if option := firstSatisfiable(set.Options, nil); option != nil {
					required = option
					break
				}
			}
			if required == nil {
				return nil, newAuthorizationRequestError(AccessDeniedError, "the wallet cannot satisfy any dcql_query.credential_sets entry")
			}
		}
	}

	slices.Sort(required)
	required = slices.Compact(required)
	// One Credential per response for now: a request that needs more is refused
	// rather than half answered, since Section 6.4.2 forbids partial answers.
	if len(required) != 1 {
		return nil, fmt.Errorf("presenting %d Credentials in one response is not supported", len(required))
	}
	return byID[required[0]], nil
}

// AuthorizationRequestError is a validation failure of an OID4VP Authorization
// Request. It carries the OAuth 2.0 / OID4VP error code that should be sent
// back to the Verifier in the authorization error response.
type AuthorizationRequestError struct {
	Code OAuthAuthzError
	Err  error
}

func (e *AuthorizationRequestError) Error() string {
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

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

// parseDcqlQuery validates the dcql_query Authorization Request parameter and
// returns the typed query. raw may be a JSON string (query parameter) or an
// already-decoded JSON object (Request Object claim).
//
// Validation failures are returned as *AuthorizationRequestError:
//   - invalid_request for syntactically malformed queries
//   - vp_formats_not_supported when a requested Credential format is not supported
func parseDcqlQuery(raw any) (*DcqlQuery, error) {
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
		if err := validateCredentialQuery(i, credentialQuery, seenIDs); err != nil {
			return nil, err
		}
	}

	if credentialSets, exists := queryMap["credential_sets"]; exists {
		setsArray, ok := credentialSets.([]any)
		if !ok || len(setsArray) == 0 {
			return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query.credential_sets must be a non-empty array when present")
		}
		for i, item := range setsArray {
			if _, ok := item.(map[string]any); !ok {
				return nil, newAuthorizationRequestError(InvalidRequestError, "dcql_query.credential_sets[%d] must be a JSON object", i)
			}
		}
	}

	// Re-encode the validated generic representation into the typed struct.
	jsonBytes, err := json.Marshal(queryMap)
	if err != nil {
		return nil, newAuthorizationRequestError(InvalidRequestError, "failed to re-encode dcql_query: %v", err)
	}
	var query DcqlQuery
	if err := json.Unmarshal(jsonBytes, &query); err != nil {
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
		if err := json.Unmarshal([]byte(v), &decoded); err != nil {
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
func validateCredentialQuery(index int, credentialQuery map[string]any, seenIDs map[string]bool) error {
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
	if !supportedCredentialFormats[format] {
		return newAuthorizationRequestError(VPFormatsNotSupportedError, "dcql_query.credentials[%d].format %q is not supported by this wallet", index, format)
	}

	rawMeta, exists := credentialQuery["meta"]
	if !exists {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].meta is required", index)
	}
	// An empty meta object means no additional constraints on the metadata or
	// validity of the requested Credential.
	if _, ok := rawMeta.(map[string]any); !ok {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].meta must be a JSON object", index)
	}

	// multiple is optional and defaults to false; when present it must be a boolean.
	if rawMultiple, exists := credentialQuery["multiple"]; exists {
		if _, ok := rawMultiple.(bool); !ok {
			return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].multiple must be a boolean", index)
		}
	}

	return validateClaims(index, credentialQuery)
}

// validateClaims validates the claims and claim_sets of a Credential Query as per
// OID4VP 1.0 Sections 6.1, 6.3 and 7.
func validateClaims(index int, credentialQuery map[string]any) error {
	rawClaims, hasClaims := credentialQuery["claims"]
	claimIDs := make(map[string]bool)
	claimCount := 0
	if hasClaims {
		claims, ok := rawClaims.([]any)
		if !ok || len(claims) == 0 {
			return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].claims must be a non-empty array", index)
		}
		claimCount = len(claims)
		for j, rawClaim := range claims {
			claim, ok := rawClaim.(map[string]any)
			if !ok {
				return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].claims[%d] must be a JSON object", index, j)
			}
			if !isClaimsPathPointer(claim["path"]) {
				return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].claims[%d].path must be a non-empty array of strings, nulls and non-negative integers", index, j)
			}
			if rawID, exists := claim["id"]; exists {
				id, ok := rawID.(string)
				if !ok || !credentialQueryIDPattern.MatchString(id) || claimIDs[id] {
					return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].claims[%d].id must be a unique non-empty string of alphanumeric, underscore or hyphen characters", index, j)
				}
				claimIDs[id] = true
			}
		}
	}

	rawClaimSets, exists := credentialQuery["claim_sets"]
	if !exists {
		return nil
	}
	// claim_sets refers to claims by id, so every claim needs one (Section 6.3).
	if !hasClaims || len(claimIDs) != claimCount {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].claim_sets requires claims that all have an id", index)
	}
	if !isIDArrays(rawClaimSets, claimIDs) {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query.credentials[%d].claim_sets must be a non-empty array of non-empty arrays of claim ids", index)
	}
	return nil
}

// isClaimsPathPointer reports whether raw is a claims path pointer (Section 7).
func isClaimsPathPointer(raw any) bool {
	path, ok := raw.([]any)
	if !ok || len(path) == 0 {
		return false
	}
	for _, component := range path {
		switch c := component.(type) {
		case string, nil:
		case float64:
			if c < 0 || c != math.Trunc(c) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// isIDArrays reports whether raw is a non-empty array of non-empty arrays of ids
// that are all in known.
func isIDArrays(raw any, known map[string]bool) bool {
	arrays, ok := raw.([]any)
	if !ok || len(arrays) == 0 {
		return false
	}
	for _, rawArray := range arrays {
		ids, ok := rawArray.([]any)
		if !ok || len(ids) == 0 {
			return false
		}
		for _, rawID := range ids {
			if id, ok := rawID.(string); !ok || !known[id] {
				return false
			}
		}
	}
	return true
}
