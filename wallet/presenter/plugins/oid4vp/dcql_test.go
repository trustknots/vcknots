package oid4vp

import (
	"errors"
	"reflect"
	"testing"

	"github.com/trustknots/vcknots/wallet/credential"
)

// sample dcql_query values follow the examples in OID4VP 1.0 Section 6.
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
		{name: "claims empty array", raw: `{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{},"claims":[]}]}`},
		{name: "claim without path", raw: `{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"a"}]}]}`},
		{name: "claim path with negative index", raw: `{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{},"claims":[{"path":["a",-1]}]}]}`},
		{name: "claim path with a boolean", raw: `{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{},"claims":[{"path":[true]}]}]}`},
		{name: "claim_sets without claims", raw: `{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{},"claim_sets":[["a"]]}]}`},
		{name: "claim_sets with a claim lacking an id", raw: `{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{},"claims":[{"path":["a"]}],"claim_sets":[["a"]]}]}`},
		{name: "claim_sets with unknown claim id", raw: `{"credentials":[{"id":"c1","format":"dc+sd-jwt","meta":{},"claims":[{"id":"a","path":["a"]}],"claim_sets":[["b"]]}]}`},
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

func TestParseDcqlQuery_Claims(t *testing.T) {
	query, err := parseDcqlQuery(`{"credentials":[{
		"id":"pid","format":"dc+sd-jwt","meta":{},
		"claims":[{"id":"given","path":["given_name"]},{"id":"street","path":["address",null,0]}],
		"claim_sets":[["street"],["given"]]
	}]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := query.Credentials[0]
	wantClaims := []ClaimQuery{{ID: "given", Path: []any{"given_name"}}, {ID: "street", Path: []any{"address", nil, float64(0)}}}
	if !reflect.DeepEqual(got.Claims, wantClaims) {
		t.Fatalf("claims = %#v, want %#v", got.Claims, wantClaims)
	}
	if want := [][]string{{"street"}, {"given"}}; !reflect.DeepEqual(got.ClaimSets, want) {
		t.Fatalf("claim_sets = %#v, want %#v", got.ClaimSets, want)
	}

	// Section 6.4.1: an absent claims member must stay distinguishable from a present one.
	query, err = parseDcqlQuery(sampleSdJwtDcqlQuery)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if query.Credentials[0].Claims != nil {
		t.Fatalf("claims = %#v, want nil when absent", query.Credentials[0].Claims)
	}
}

func TestCredentialQuery_Matches(t *testing.T) {
	pid := &credential.Credential{Types: []string{"urn:eu.europa.ec.eudi:pid:1"}}
	tests := []struct {
		name   string
		query  CredentialQuery
		format string
		want   bool
	}{
		{"vct among vct_values", CredentialQuery{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []any{"urn:other", "urn:eu.europa.ec.eudi:pid:1"}}}, "dc+sd-jwt", true},
		{"vct not among vct_values", CredentialQuery{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []any{"urn:conformance-suite:nonexistent:credential:1"}}}, "dc+sd-jwt", false},
		{"empty meta constrains nothing", CredentialQuery{Format: "dc+sd-jwt", Meta: map[string]any{}}, "dc+sd-jwt", true},
		{"malformed vct_values matches nothing", CredentialQuery{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": "urn:eu.europa.ec.eudi:pid:1"}}, "dc+sd-jwt", false},
		{"different format", CredentialQuery{Format: "jwt_vc_json", Meta: map[string]any{}}, "dc+sd-jwt", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.query.Matches(tt.format, pid); got != tt.want {
				t.Fatalf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDcqlQuery_SelectCredentialQuery pins OID4VP 1.0 Section 6.4.2 with the queries
// the conformance suite sends: its modules append a query for a credential no wallet
// holds, in an optional or a required credential set.
func TestDcqlQuery_SelectCredentialQuery(t *testing.T) {
	held := func(q *CredentialQuery) bool { return q.ID == "pid" }
	optional, required := false, true
	pid := CredentialQuery{ID: "pid", Format: "dc+sd-jwt"}
	missing := CredentialQuery{ID: "nonexistent_credential", Format: "dc+sd-jwt"}

	t.Run("without credential_sets every query is required", func(t *testing.T) {
		got, err := (&DcqlQuery{Credentials: []CredentialQuery{pid}}).SelectCredentialQuery(held)
		if err != nil || got.ID != "pid" {
			t.Fatalf("got %v, %v; want pid", got, err)
		}
		_, err = (&DcqlQuery{Credentials: []CredentialQuery{pid, missing}}).SelectCredentialQuery(held)
		assertAuthzErrorCode(t, err, AccessDeniedError)
	})

	t.Run("an optional set that cannot be satisfied is skipped", func(t *testing.T) {
		got, err := (&DcqlQuery{
			Credentials: []CredentialQuery{pid, missing},
			CredentialSets: []CredentialSetQuery{
				{Options: [][]string{{"pid"}}, Required: &required},
				{Options: [][]string{{"nonexistent_credential"}}, Required: &optional},
			},
		}).SelectCredentialQuery(held)
		if err != nil || got.ID != "pid" {
			t.Fatalf("got %v, %v; want pid", got, err)
		}
	})

	t.Run("a required set that cannot be satisfied is access_denied", func(t *testing.T) {
		_, err := (&DcqlQuery{
			Credentials: []CredentialQuery{pid, missing},
			CredentialSets: []CredentialSetQuery{
				{Options: [][]string{{"pid"}}, Required: &required},
				{Options: [][]string{{"nonexistent_credential"}}}, // required defaults to true
			},
		}).SelectCredentialQuery(held)
		assertAuthzErrorCode(t, err, AccessDeniedError)
	})

	t.Run("the first satisfiable option is taken", func(t *testing.T) {
		got, err := (&DcqlQuery{
			Credentials:    []CredentialQuery{pid, missing},
			CredentialSets: []CredentialSetQuery{{Options: [][]string{{"nonexistent_credential"}, {"pid"}}}},
		}).SelectCredentialQuery(held)
		if err != nil || got.ID != "pid" {
			t.Fatalf("got %v, %v; want pid", got, err)
		}
	})

	t.Run("an option answerable with one Credential wins over an earlier one needing two", func(t *testing.T) {
		both := func(*CredentialQuery) bool { return true }
		got, err := (&DcqlQuery{
			Credentials:    []CredentialQuery{pid, missing},
			CredentialSets: []CredentialSetQuery{{Options: [][]string{{"pid", "nonexistent_credential"}, {"pid"}}}},
		}).SelectCredentialQuery(both)
		if err != nil || got.ID != "pid" {
			t.Fatalf("got %v, %v; want pid", got, err)
		}
	})

	t.Run("two required credentials are refused, not half answered", func(t *testing.T) {
		both := func(*CredentialQuery) bool { return true }
		_, err := (&DcqlQuery{Credentials: []CredentialQuery{pid, missing}}).SelectCredentialQuery(both)
		var authzErr *AuthorizationRequestError
		if err == nil || errors.As(err, &authzErr) {
			t.Fatalf("err = %v; want a plain error, not an OAuth error response", err)
		}
	})
}
