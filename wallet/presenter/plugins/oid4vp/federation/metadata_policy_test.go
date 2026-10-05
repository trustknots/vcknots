package federation

import (
	"encoding/json"
	"reflect"
	"testing"
)

// obj decodes a JSON object literal the way an Entity Statement payload is
// decoded, so the tests exercise the same value shapes.
func obj(t *testing.T, literal string) map[string]any {
	t.Helper()
	value, err := decodeJSONObject([]byte(literal))
	if err != nil {
		t.Fatalf("bad test literal %s: %v", literal, err)
	}
	return value
}

// requireJSON compares a result with an expected JSON object literal.
func requireJSON(t *testing.T, got map[string]any, want string) {
	t.Helper()
	expected := obj(t, want)
	if !jsonEqual(got, expected) {
		encoded, _ := json.Marshal(got)
		t.Fatalf("got %s, want %s", encoded, want)
	}
}

func TestApplyMetadataPolicyRunsEveryOperatorInOrder(t *testing.T) {
	got, err := ApplyMetadataPolicy(obj(t, `{
		"client_name": "Original verifier",
		"contacts": ["ops@example.test"],
		"response_modes_supported": ["direct_post", "fragment"],
		"vp_formats_supported": ["dc+sd-jwt", "jwt_vp_json"]
	}`), obj(t, `{"openid_credential_verifier": {
		"client_name": {"value": "Federated verifier", "one_of": ["Federated verifier"]},
		"logo_uri": {"default": "https://verifier.example.test/logo.png", "essential": true},
		"contacts": {"add": ["security@example.test", "ops@example.test"]},
		"response_modes_supported": {"subset_of": ["direct_post", "direct_post.jwt"]},
		"vp_formats_supported": {"superset_of": ["dc+sd-jwt"]}
	}}`), VerifierEntityType)
	if err != nil {
		t.Fatal(err)
	}
	requireJSON(t, got, `{
		"client_name": "Federated verifier",
		"contacts": ["ops@example.test", "security@example.test"],
		"logo_uri": "https://verifier.example.test/logo.png",
		"response_modes_supported": ["direct_post"],
		"vp_formats_supported": ["dc+sd-jwt", "jwt_vp_json"]
	}`)
}

func TestApplyMetadataPolicy(t *testing.T) {
	cases := []struct {
		name     string
		metadata string
		policy   string
		want     string
		fragment string
	}{
		{
			name:     "value null removes the parameter",
			metadata: `{"policy_uri": "https://verifier.example.test/policy"}`,
			policy:   `{"openid_credential_verifier": {"policy_uri": {"value": null}}}`,
			want:     `{}`,
		},
		{
			name:     "essential parameter missing",
			metadata: `{}`,
			policy:   `{"openid_credential_verifier": {"client_name": {"essential": true}}}`,
			fragment: "metadata essential value is missing",
		},
		{
			name:     "policy for another entity type",
			metadata: `{"client_name": "Original verifier"}`,
			policy:   `{"openid_provider": {"client_name": {"value": "Issuer policy"}}}`,
			want:     `{"client_name": "Original verifier"}`,
		},
		{
			name:     "malformed scope",
			metadata: `{}`,
			policy:   `{"openid_credential_verifier": "not-object"}`,
			fragment: "metadata policy scope must be an object",
		},
		{
			name:     "non-critical unknown operator is ignored",
			metadata: `{"client_name": "Original verifier"}`,
			policy:   `{"openid_credential_verifier": {"client_name": {"regexp": "^Verifier"}}}`,
			want:     `{"client_name": "Original verifier"}`,
		},
		{
			name:     "array operator on a scalar parameter",
			metadata: `{"response_modes_supported": "direct_post"}`,
			policy:   `{"openid_credential_verifier": {"response_modes_supported": {"subset_of": ["direct_post"]}}}`,
			fragment: "metadata parameter response_modes_supported must be a string array for this policy",
		},
		{
			name:     "one_of combined with add",
			metadata: `{}`,
			policy:   `{"openid_credential_verifier": {"contacts": {"add": ["ops@example.test"], "one_of": []}}}`,
			fragment: "one_of policy cannot be combined with add",
		},
		{
			name:     "value outside one_of",
			metadata: `{"client_name": "Other"}`,
			policy:   `{"openid_credential_verifier": {"client_name": {"one_of": ["Federated verifier"]}}}`,
			fragment: "metadata value is not allowed by one_of",
		},
		{
			name:     "superset_of not satisfied",
			metadata: `{"scopes": ["openid"]}`,
			policy:   `{"openid_credential_verifier": {"scopes": {"superset_of": ["openid", "profile"]}}}`,
			fragment: "metadata value does not satisfy superset_of",
		},
		{
			name:     "one_of compares objects structurally",
			metadata: `{"format": {"b": [1, 2], "a": "x"}}`,
			policy:   `{"openid_credential_verifier": {"format": {"one_of": [{"a": "x", "b": [1.0, 2]}]}}}`,
			want:     `{"format": {"a": "x", "b": [1, 2]}}`,
		},
		{
			name:     "default fills a missing parameter only",
			metadata: `{"a": "kept"}`,
			policy:   `{"openid_credential_verifier": {"a": {"default": "x"}, "b": {"default": "y"}}}`,
			want:     `{"a": "kept", "b": "y"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ApplyMetadataPolicy(obj(t, tc.metadata), obj(t, tc.policy), VerifierEntityType)
			if tc.fragment != "" {
				requireCode(t, err, ErrMetadataPolicyInvalid, tc.fragment)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			requireJSON(t, got, tc.want)
		})
	}
}

func TestApplyMetadataPolicyDoesNotMutateItsInput(t *testing.T) {
	metadata := obj(t, `{"contacts": ["ops@example.test"]}`)
	if _, err := ApplyMetadataPolicy(metadata, obj(t, `{"openid_credential_verifier": {"contacts": {"add": ["x@example.test"]}}}`), VerifierEntityType); err != nil {
		t.Fatal(err)
	}
	requireJSON(t, metadata, `{"contacts": ["ops@example.test"]}`)
}

func TestResolveMetadataPolicyMergesFromSuperiorToSubordinate(t *testing.T) {
	got, err := ResolveMetadataPolicy([]map[string]any{
		obj(t, `{"openid_credential_verifier": {
			"contacts": {"add": ["ops@example.test"]},
			"response_modes_supported": {"subset_of": ["direct_post", "direct_post.jwt"]},
			"scopes_supported": {"superset_of": ["openid"]},
			"client_name": {"one_of": ["Federated verifier", "Other verifier"]},
			"logo_uri": {"default": "https://verifier.example.test/logo.png"},
			"terms_of_service_uri": {"essential": false}
		}}`),
		obj(t, `{"openid_credential_verifier": {
			"contacts": {"add": ["security@example.test", "ops@example.test"]},
			"response_modes_supported": {"subset_of": ["direct_post"]},
			"scopes_supported": {"superset_of": ["profile"]},
			"client_name": {"one_of": ["Federated verifier"]},
			"logo_uri": {"default": "https://verifier.example.test/logo.png"},
			"terms_of_service_uri": {"essential": true}
		}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	requireJSON(t, got, `{"openid_credential_verifier": {
		"client_name": {"one_of": ["Federated verifier"]},
		"contacts": {"add": ["ops@example.test", "security@example.test"]},
		"logo_uri": {"default": "https://verifier.example.test/logo.png"},
		"response_modes_supported": {"subset_of": ["direct_post"]},
		"scopes_supported": {"superset_of": ["openid", "profile"]},
		"terms_of_service_uri": {"essential": true}
	}}`)
}

func TestResolveMetadataPolicy(t *testing.T) {
	cases := []struct {
		name     string
		policies []string
		want     string
		fragment string
	}{
		{
			name: "conflicting value policies",
			policies: []string{
				`{"openid_credential_verifier": {"client_name": {"value": "Trust anchor verifier"}}}`,
				`{"openid_credential_verifier": {"client_name": {"value": "Immediate superior verifier"}}}`,
			},
			fragment: "metadata value policy values do not match",
		},
		{
			name:     "unknown operators are dropped",
			policies: []string{`{"openid_credential_verifier": {"client_name": {"regexp": "^Verifier"}, "contacts": {"add": ["ops@example.test"], "extension": ["ignored"]}}}`},
			want:     `{"openid_credential_verifier": {"contacts": {"add": ["ops@example.test"]}}}`,
		},
		{
			// value and default merge by structure, so member order
			// and number spelling do not make equal values conflict.
			name: "structurally equal object values merge",
			policies: []string{
				`{"openid_credential_verifier": {"vp_formats": {"value": {"jwt_vp": {"alg": ["ES256"]}, "ldp_vp": {"n": 1}}}}}`,
				`{"openid_credential_verifier": {"vp_formats": {"value": {"ldp_vp": {"n": 1.0}, "jwt_vp": {"alg": ["ES256"]}}}}}`,
			},
			want: `{"openid_credential_verifier": {"vp_formats": {"value": {"jwt_vp": {"alg": ["ES256"]}, "ldp_vp": {"n": 1}}}}}`,
		},
		{
			name: "structurally different default values conflict",
			policies: []string{
				`{"openid_credential_verifier": {"x": {"default": {"a": [1, 2]}}}}`,
				`{"openid_credential_verifier": {"x": {"default": {"a": [2, 1]}}}}`,
			},
			fragment: "metadata default policy values do not match",
		},
		{
			name: "disjoint one_of merge",
			policies: []string{
				`{"openid_credential_verifier": {"x": {"one_of": ["a"]}}}`,
				`{"openid_credential_verifier": {"x": {"one_of": ["b"]}}}`,
			},
			fragment: "one_of policy merge is empty",
		},
		{
			name: "merged value no longer satisfies subset_of",
			policies: []string{
				`{"openid_credential_verifier": {"x": {"subset_of": ["a"]}}}`,
				`{"openid_credential_verifier": {"x": {"value": ["a", "b"]}}}`,
			},
			fragment: "value policy does not satisfy subset_of",
		},
		{
			name:     "value null with default",
			policies: []string{`{"openid_credential_verifier": {"x": {"value": null, "default": "a"}}}`},
			fragment: "value and default policies are incompatible",
		},
		{
			name:     "value null with essential",
			policies: []string{`{"openid_credential_verifier": {"x": {"value": null, "essential": true}}}`},
			fragment: "value and essential policies are incompatible",
		},
		{
			name:     "non-boolean essential",
			policies: []string{`{"openid_credential_verifier": {"x": {"essential": "yes"}}}`},
			fragment: "essential policy must be boolean",
		},
		{
			name:     "null default",
			policies: []string{`{"openid_credential_verifier": {"x": {"default": null}}}`},
			fragment: "default policy must not be null",
		},
		{
			name:     "value missing add values",
			policies: []string{`{"openid_credential_verifier": {"x": {"value": ["a"], "add": ["b"]}}}`},
			fragment: "value policy must include add values",
		},
		{
			name:     "subset_of missing superset_of values",
			policies: []string{`{"openid_credential_verifier": {"x": {"subset_of": ["a"], "superset_of": ["b"]}}}`},
			fragment: "subset_of policy does not satisfy superset_of",
		},
		{
			name:     "add outside subset_of",
			policies: []string{`{"openid_credential_verifier": {"x": {"add": ["b"], "subset_of": ["a"]}}}`},
			fragment: "add policy does not satisfy subset_of",
		},
		{
			name:     "value missing superset_of values",
			policies: []string{`{"openid_credential_verifier": {"x": {"value": ["a"], "superset_of": ["b"]}}}`},
			fragment: "value policy does not satisfy superset_of",
		},
		{
			name:     "value outside one_of",
			policies: []string{`{"openid_credential_verifier": {"x": {"value": "b", "one_of": ["a"]}}}`},
			fragment: "value policy is not allowed by one_of",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policies := make([]map[string]any, len(tc.policies))
			for i, literal := range tc.policies {
				policies[i] = obj(t, literal)
			}
			got, err := ResolveMetadataPolicy(policies)
			if tc.fragment != "" {
				requireCode(t, err, ErrMetadataPolicyInvalid, tc.fragment)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			requireJSON(t, got, tc.want)
		})
	}
}

func TestResolveMetadataPolicyReturnsNilWithoutPolicies(t *testing.T) {
	got, err := ResolveMetadataPolicy([]map[string]any{obj(t, `{"openid_credential_verifier": {"x": {"regexp": "."}}}`)})
	if err != nil || got != nil {
		t.Fatalf("got %v, %v; want nil, nil", got, err)
	}
}

func TestJSONEqual(t *testing.T) {
	cases := []struct {
		left, right any
		want        bool
	}{
		{json.Number("1"), 1.0, true},
		{json.Number("1.50"), json.Number("1.5"), true},
		{json.Number("1"), "1", false},
		{map[string]any{"a": 1, "b": 2}, map[string]any{"b": 2, "a": 1}, true},
		{map[string]any{"a": 1}, map[string]any{"a": 1, "b": nil}, false},
		{[]any{"a", "b"}, []string{"a", "b"}, true},
		{[]any{"a", "b"}, []any{"b", "a"}, false},
		{nil, nil, true},
		{true, false, false},
	}
	for _, tc := range cases {
		if got := jsonEqual(tc.left, tc.right); got != tc.want {
			t.Errorf("jsonEqual(%#v, %#v) = %v, want %v", tc.left, tc.right, got, tc.want)
		}
	}
	if !reflect.DeepEqual(stringsToJSON([]string{"a"}), []any{"a"}) {
		t.Fatal("stringsToJSON must produce decoded-JSON arrays")
	}
}
