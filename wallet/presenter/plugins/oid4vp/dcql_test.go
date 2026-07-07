package oid4vp

import (
	"errors"
	"testing"
)

// sample dcql_query values follow the examples in OID4VP 1.0 Section 6 and
// trustknots/vcknots-internal#35.
const sampleSdJwtDcqlQuery = `{
	"credentials": [
		{
			"id": "pid",
			"format": "dc+sd-jwt",
			"meta": {
				"vct_values": ["https://credentials.example.com/identity_credential"]
			}
		}
	]
}`

const sampleJwtVcDcqlQuery = `{
	"credentials": [
		{
			"id": "example_jwt_vc",
			"format": "jwt_vc_json",
			"meta": {
				"type_values": [["IDCredential"]]
			}
		}
	]
}`

func assertAuthzErrorCode(t *testing.T, err error, wantCode OAuthAuthzError) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var authzErr *AuthorizationRequestError
	if !errors.As(err, &authzErr) {
		t.Fatalf("expected *AuthorizationRequestError, got %T: %v", err, err)
	}
	if authzErr.Code != wantCode {
		t.Fatalf("expected error code %q, got %q (%v)", wantCode, authzErr.Code, err)
	}
}

func TestParseDcqlQuery_Valid(t *testing.T) {
	t.Run("sd-jwt vc sample as JSON string", func(t *testing.T) {
		query, err := parseDcqlQuery(sampleSdJwtDcqlQuery)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(query.Credentials) != 1 {
			t.Fatalf("expected 1 credential query, got %d", len(query.Credentials))
		}
		cred := query.Credentials[0]
		if cred.ID != "pid" || cred.Format != "dc+sd-jwt" {
			t.Fatalf("unexpected credential query: %+v", cred)
		}
		if cred.Meta == nil {
			t.Fatal("expected meta to be populated")
		}
		// multiple omitted must default to false
		if cred.Multiple {
			t.Fatal("expected multiple to default to false")
		}
	})

	t.Run("jwt vc json sample as JSON string", func(t *testing.T) {
		query, err := parseDcqlQuery(sampleJwtVcDcqlQuery)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if query.Credentials[0].Format != "jwt_vc_json" {
			t.Fatalf("unexpected format: %s", query.Credentials[0].Format)
		}
	})

	t.Run("decoded JSON object (request object claim)", func(t *testing.T) {
		raw := map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "my_credential",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{},
				},
			},
		}
		query, err := parseDcqlQuery(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if query.Credentials[0].ID != "my_credential" {
			t.Fatalf("unexpected id: %s", query.Credentials[0].ID)
		}
	})

	t.Run("empty meta object means no additional constraints", func(t *testing.T) {
		query, err := parseDcqlQuery(`{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{}}]}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(query.Credentials[0].Meta) != 0 {
			t.Fatalf("expected empty meta, got %+v", query.Credentials[0].Meta)
		}
	})

	t.Run("multiple=true is preserved", func(t *testing.T) {
		query, err := parseDcqlQuery(`{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{},"multiple":true}]}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !query.Credentials[0].Multiple {
			t.Fatal("expected multiple to be true")
		}
	})

	t.Run("credential_sets non-empty array is accepted", func(t *testing.T) {
		query, err := parseDcqlQuery(`{
			"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{}}],
			"credential_sets":[{"options":[["c1"]]}]
		}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(query.CredentialSets) != 1 {
			t.Fatalf("expected 1 credential set query, got %d", len(query.CredentialSets))
		}
	})

	t.Run("id allows alphanumeric, underscore and hyphen", func(t *testing.T) {
		_, err := parseDcqlQuery(`{"credentials":[{"id":"Cred_01-a","format":"jwt_vc_json","meta":{}}]}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestParseDcqlQuery_InvalidRequest(t *testing.T) {
	tests := []struct {
		name string
		raw  any
	}{
		{name: "invalid JSON string", raw: `{invalid`},
		{name: "JSON string but not an object (array)", raw: `[]`},
		{name: "JSON string but not an object (number)", raw: `1`},
		{name: "non-object non-string value", raw: 42},
		{name: "missing credentials", raw: `{}`},
		{name: "credentials not an array", raw: `{"credentials":{}}`},
		{name: "credentials empty array", raw: `{"credentials":[]}`},
		{name: "credential query not an object", raw: `{"credentials":["not-an-object"]}`},
		{name: "missing id", raw: `{"credentials":[{"format":"jwt_vc_json","meta":{}}]}`},
		{name: "id empty string", raw: `{"credentials":[{"id":"","format":"jwt_vc_json","meta":{}}]}`},
		{name: "id not a string", raw: `{"credentials":[{"id":1,"format":"jwt_vc_json","meta":{}}]}`},
		{name: "id with invalid characters", raw: `{"credentials":[{"id":"my credential!","format":"jwt_vc_json","meta":{}}]}`},
		{
			name: "duplicated ids",
			raw: `{"credentials":[
				{"id":"dup","format":"jwt_vc_json","meta":{}},
				{"id":"dup","format":"dc+sd-jwt","meta":{}}
			]}`,
		},
		{name: "missing format", raw: `{"credentials":[{"id":"c1","meta":{}}]}`},
		{name: "format not a string", raw: `{"credentials":[{"id":"c1","format":1,"meta":{}}]}`},
		{name: "missing meta", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json"}]}`},
		{name: "meta not an object", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":"x"}]}`},
		{name: "multiple not a boolean", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{},"multiple":"yes"}]}`},
		{name: "credential_sets not an array", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{}}],"credential_sets":{}}`},
		{name: "credential_sets empty array", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{}}],"credential_sets":[]}`},
		{name: "credential_sets element not an object", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{}}],"credential_sets":["x"]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDcqlQuery(tt.raw)
			assertAuthzErrorCode(t, err, InvalidRequestError)
		})
	}
}

func TestParseDcqlQuery_UnsupportedFormat(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "unknown format", raw: `{"credentials":[{"id":"c1","format":"mso_mdoc","meta":{}}]}`},
		{
			name: "supported and unsupported formats mixed",
			raw: `{"credentials":[
				{"id":"c1","format":"jwt_vc_json","meta":{}},
				{"id":"c2","format":"ldp_vc","meta":{}}
			]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseDcqlQuery(tt.raw)
			assertAuthzErrorCode(t, err, VPFormatsNotSupportedError)
		})
	}
}
