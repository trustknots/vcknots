package oid4vp

import (
	"encoding/json"
	"testing"
)

// The official suite's ignores-unusable-encryption-key module mixes a
// post-quantum placeholder and an unknown kty into client_metadata.jwks.
func TestVerifierMetadataIgnoresUnusableJWKSEntries(t *testing.T) {
	raw := `{"jwks":{"keys":[
		{"kty":"AKP","alg":"ML-KEM-9999","kid":"unusable-pq","use":"enc","pub":"AAAA"},
		{"kty":"EC","use":"enc","crv":"P-256","kid":"usable","x":"AuKXjZzwieyKT8ADa8rbncTvNv9Bck0QNLvz494DOTk","y":"4JtZ5OENUsXaQvSsp5M3luNNljvHnR_69-LcjXlGiJk","alg":"ECDH-ES"},
		{"kty":"OIDF-CONFORMANCE-UNSUPPORTED","alg":"OIDF-CONFORMANCE-UNSUPPORTED","kid":"unusable-unknown","use":"enc"}
	]},"encrypted_response_enc_values_supported":["A128GCM","A256GCM"],"client_name":"v"}`
	var metadata VerifierMetadata
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(metadata.Jwks.Keys) != 1 || metadata.Jwks.Keys[0].KeyID != "usable" {
		t.Fatalf("expected only the usable key, got %#v", metadata.Jwks.Keys)
	}
	if metadata.ClientName != "v" || len(metadata.EncryptedResponseEncValuesSupported) != 2 {
		t.Fatalf("other fields must survive: %#v", metadata)
	}
	var empty VerifierMetadata
	if err := json.Unmarshal([]byte(`{"jwks":null}`), &empty); err != nil || len(empty.Jwks.Keys) != 0 {
		t.Fatalf("null jwks: %v %#v", err, empty.Jwks)
	}
	if err := json.Unmarshal([]byte(`{"jwks":"x"}`), &empty); err == nil {
		t.Fatal("a jwks that is not an object must be rejected")
	}
}
