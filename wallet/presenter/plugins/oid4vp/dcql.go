package oid4vp

import (
	"encoding/json"
	"fmt"
	"regexp"
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
}

// CredentialSetQuery represents a request for one or more Credential Queries
// to be satisfied (OID4VP 1.0 Section 6.2).
type CredentialSetQuery struct {
	Options  [][]string `json:"options,omitempty"`
	Required *bool      `json:"required,omitempty"`
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
// wallet can serialize presentations for. They must stay in sync with
// credential.SupportedSerializationFlavor.OID4VPFormatIdentifier.
var supportedCredentialFormats = map[string]bool{
	"jwt_vc_json": true,
	"dc+sd-jwt":   true,
}

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

	return nil
}
