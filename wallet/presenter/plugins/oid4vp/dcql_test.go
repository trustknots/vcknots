package oid4vp

import (
	"encoding/json"
	"errors"
	"reflect"
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
					"meta":   map[string]any{"vct_values": []any{"urn:test:identity"}},
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

	t.Run("multiple=true is preserved", func(t *testing.T) {
		query, err := parseDcqlQuery(`{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]},"multiple":true}]}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !query.Credentials[0].Multiple {
			t.Fatal("expected multiple to be true")
		}
	})

	t.Run("credential_sets non-empty array is accepted", func(t *testing.T) {
		query, err := parseDcqlQuery(`{
			"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}],
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
		_, err := parseDcqlQuery(`{"credentials":[{"id":"Cred_01-a","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`)
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
		{name: "missing id", raw: `{"credentials":[{"format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`},
		{name: "id empty string", raw: `{"credentials":[{"id":"","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`},
		{name: "id not a string", raw: `{"credentials":[{"id":1,"format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`},
		{name: "id with invalid characters", raw: `{"credentials":[{"id":"my credential!","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`},
		{
			name: "duplicated ids",
			raw: `{"credentials":[
				{"id":"dup","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}},
				{"id":"dup","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]}}
			]}`,
		},
		{name: "missing format", raw: `{"credentials":[{"id":"c1","meta":{}}]}`},
		{name: "format not a string", raw: `{"credentials":[{"id":"c1","format":1,"meta":{}}]}`},
		{name: "missing meta", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json"}]}`},
		{name: "meta not an object", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":"x"}]}`},
		// OID4VP 1.0 Appendix B.1.1 and B.3.5 make these meta members REQUIRED.
		{name: "jwt_vc_json meta without type_values", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{}}]}`},
		{name: "type_values not an array", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":"IDCredential"}}]}`},
		{name: "type_values empty", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":[]}}]}`},
		{name: "type_values alternative empty", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":[[]]}}]}`},
		{name: "type_values alternative not an array", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":["IDCredential"]}}]}`},
		{name: "type_values non-string type", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":[[1]]}}]}`},
		{name: "dc+sd-jwt meta without vct_values", raw: `{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{}}]}`},
		{name: "vct_values empty", raw: `{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{"vct_values":[]}}]}`},
		{name: "vct_values non-string", raw: `{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{"vct_values":[1]}}]}`},
		{name: "multiple not a boolean", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]},"multiple":"yes"}]}`},
		{name: "credential_sets not an array", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}],"credential_sets":{}}`},
		{name: "credential_sets empty array", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}],"credential_sets":[]}`},
		{name: "credential_sets element not an object", raw: `{"credentials":[{"id":"c1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}],"credential_sets":["x"]}`},
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
				{"id":"c1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}},
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

func TestParseDcqlQuery_HolderBindingRequirement(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		value                  any
		present, want, invalid bool
	}{
		{name: "omitted", want: true},
		{name: "true", value: true, present: true, want: true},
		{name: "false", value: false, present: true},
		{name: "null", present: true, invalid: true},
		{name: "string", value: "false", present: true, invalid: true},
		{name: "number", value: 0, present: true, invalid: true},
		{name: "array", value: []any{false}, present: true, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := map[string]any{"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:test:identity"}}}
			if tc.present {
				raw["require_cryptographic_holder_binding"] = tc.value
			}
			query, err := parseDcqlQuery(map[string]any{"credentials": []any{raw}})
			if tc.invalid {
				assertAuthzErrorCode(t, err, InvalidRequestError)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := query.Credentials[0].RequiresHolderBinding(); got != tc.want {
				t.Fatalf("holder binding = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseDraft24DcqlQuery_IgnoresFinalHolderBindingField(t *testing.T) {
	rawQuery := map[string]any{"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{}, "require_cryptographic_holder_binding": "ignored"}
	query, err := parseDraft24DcqlQuery(map[string]any{"credentials": []any{rawQuery}})
	if err != nil {
		t.Fatal(err)
	}
	if query.Credentials[0].RequireCryptographicHolderBinding != nil {
		t.Fatal("Final field was retained in Draft24 query")
	}
	if rawQuery["require_cryptographic_holder_binding"] != "ignored" {
		t.Fatal("caller input was mutated")
	}
}

func TestParseDCQLClaimSetsPreservesClaimIDsAndValues(t *testing.T) {
	const raw = `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},
		"claims":[{"id":"age","path":["age_over_18"],"values":[true]},
		{"id":"number","path":["number"],"values":[9007199254740993,"18",false,-3,1.0]}],
		"claim_sets":[["age"],["number"]]}]}`
	for _, parser := range []struct {
		name  string
		parse func(any) (*DcqlQuery, error)
	}{{"final", parseDcqlQuery}, {"draft24", parseDraft24DcqlQuery}} {
		t.Run(parser.name, func(t *testing.T) {
			query, err := parser.parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			credential := query.Credentials[0]
			if !reflect.DeepEqual(credential.ClaimSets, [][]string{{"age"}, {"number"}}) || credential.Claims[0].ID != "age" {
				t.Fatalf("claim set identifiers were lost: %#v", credential)
			}
			want := []any{json.Number("9007199254740993"), "18", false, json.Number("-3"), json.Number("1.0")}
			if !reflect.DeepEqual(credential.Claims[1].Values, want) {
				t.Fatalf("values = %#v, want %#v", credential.Claims[1].Values, want)
			}
			encoded, err := json.Marshal(query)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip, err := parser.parse(string(encoded))
			if err != nil || !reflect.DeepEqual(query, roundTrip) {
				t.Fatalf("DCQL round trip lost constraints: %#v, %v", roundTrip, err)
			}
		})
	}
}

func TestParseDCQLInvalidClaimConstraints(t *testing.T) {
	for _, tc := range []struct{ name, fields string }{
		{"claims null", `"claims":null`},
		{"claims object", `"claims":{}`},
		{"claims empty", `"claims":[]`},
		{"claim not object", `"claims":[true]`},
		{"path missing", `"claims":[{}]`},
		{"path empty", `"claims":[{"path":[]}]`},
		{"path string", `"claims":[{"path":"name"}]`},
		{"negative index", `"claims":[{"path":["items",-1]}]`},
		{"fractional index", `"claims":[{"path":["items",1.5]}]`},
		{"id empty", `"claims":[{"id":"","path":["name"]}]`},
		{"id invalid", `"claims":[{"id":"a b","path":["name"]}]`},
		{"id null", `"claims":[{"id":null,"path":["name"]}]`},
		{"duplicate id without sets", `"claims":[{"id":"n","path":["name"]},{"id":"n","path":["birthdate"]}]`},
		{"claim sets without claims", `"claim_sets":[["name"]]`},
		{"claim sets null", `"claims":[{"id":"n","path":["name"]}],"claim_sets":null`},
		{"claim sets empty", `"claims":[{"id":"n","path":["name"]}],"claim_sets":[]`},
		{"claim set null", `"claims":[{"id":"n","path":["name"]}],"claim_sets":[null]`},
		{"claim set not array", `"claims":[{"id":"n","path":["name"]}],"claim_sets":["n"]`},
		{"claim set unknown id", `"claims":[{"id":"n","path":["name"]}],"claim_sets":[["missing"]]`},
		{"claim set numeric id", `"claims":[{"id":"n","path":["name"]}],"claim_sets":[[3]]`},
		{"claim id required with sets", `"claims":[{"path":["name"]}],"claim_sets":[["n"]]`},
		{"values null", `"claims":[{"path":["name"],"values":null}]`},
		{"values empty", `"claims":[{"path":["name"],"values":[]}]`},
		{"values not array", `"claims":[{"path":["name"],"values":"Alice"}]`},
		{"value null", `"claims":[{"path":["name"],"values":[null]}]`},
		{"value object", `"claims":[{"path":["name"],"values":[{}]}]`},
		{"value array", `"claims":[{"path":["name"],"values":[[]]}]`},
		{"fractional value", `"claims":[{"path":["age"],"values":[18.5]}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},` + tc.fields + `}]}`)
			assertAuthzErrorCode(t, err, InvalidRequestError)
		})
	}
}

func TestParseDCQLInvalidCredentialSetConstraints(t *testing.T) {
	for _, set := range []string{
		`{}`, `{"options":null}`, `{"options":[]}`, `{"options":[[]]}`,
		`{"options":[null]}`,
		`{"options":["pid"]}`, `{"options":[[1]]}`, `{"options":[["unknown"]]}`,
		`{"options":[["unknown"]],"required":false}`, `{"options":[["pid"]],"required":null}`,
		`{"options":[["pid"]],"required":"false"}`,
	} {
		t.Run(set, func(t *testing.T) {
			_, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]}}],"credential_sets":[` + set + `]}`)
			assertAuthzErrorCode(t, err, InvalidRequestError)
		})
	}
}

func TestParseDCQLPreservesEmptyClaimSetOption(t *testing.T) {
	query, err := parseDcqlQuery(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"id":"age","path":["age_over_18"]}],"claim_sets":[["age"],[]]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(query.Credentials[0].ClaimSets, [][]string{{"age"}, {}}) {
		t.Fatalf("empty claim set option was not preserved: %#v", query.Credentials[0].ClaimSets)
	}
}

func TestParseDCQLIgnoresUnknownExtensions(t *testing.T) {
	query, err := parseDcqlQuery(`{"extension":true,"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"extension":true,"claims":[{"id":"n","path":["name"],"extension":true}],"claim_sets":[["n"]]}],"credential_sets":[{"options":[["pid"]],"extension":true}]}`)
	if err != nil || len(query.Credentials) != 1 {
		t.Fatalf("unknown extensions must be ignored: %#v, %v", query, err)
	}
}

func TestParseDCQLRejectsTrailingJSON(t *testing.T) {
	_, err := parseDcqlQuery(sampleSdJwtDcqlQuery + ` {}`)
	assertAuthzErrorCode(t, err, InvalidRequestError)
}
