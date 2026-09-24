package types

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestSignatureAlgorithmUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected SignatureAlgorithm
		wantErr  bool
	}{
		{
			name:     "JWA name",
			raw:      `"ES256"`,
			expected: SignatureAlgorithm(jose.ES256),
		},
		{
			name:     "COSE identifier for ES256",
			raw:      `-7`,
			expected: SignatureAlgorithm(jose.ES256),
		},
		{
			name:     "COSE identifier for EdDSA",
			raw:      `-8`,
			expected: SignatureAlgorithm(jose.EdDSA),
		},
		{
			name:     "COSE identifier for ESP256 (fully-specified ES256)",
			raw:      `-9`,
			expected: SignatureAlgorithm(jose.ES256),
		},
		{
			name:     "COSE identifier for PS512",
			raw:      `-39`,
			expected: SignatureAlgorithm(jose.PS512),
		},
		{
			name:    "unsupported COSE identifier",
			raw:     `999`,
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			raw:     `{}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var alg SignatureAlgorithm
			err := json.Unmarshal([]byte(tt.raw), &alg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (alg=%v)", alg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if alg != tt.expected {
				t.Fatalf("got %v, want %v", alg, tt.expected)
			}
		})
	}
}

func TestCredentialConfigurationUnmarshalJSONMixedAlgValues(t *testing.T) {
	raw := `{
		"format": "mso_mdoc",
		"credential_signing_alg_values_supported": ["ES256", -7, -9, -8, -257]
	}`

	var cfg CredentialConfiguration
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []SignatureAlgorithm{
		SignatureAlgorithm(jose.ES256),
		SignatureAlgorithm(jose.ES256),
		SignatureAlgorithm(jose.ES256),
		SignatureAlgorithm(jose.EdDSA),
		SignatureAlgorithm(jose.RS256),
	}
	if len(cfg.CredentialSigningAlgValuesSupported) != len(want) {
		t.Fatalf("got %v, want %v", cfg.CredentialSigningAlgValuesSupported, want)
	}
	for i, alg := range want {
		if cfg.CredentialSigningAlgValuesSupported[i] != alg {
			t.Fatalf("index %d: got %v, want %v", i, cfg.CredentialSigningAlgValuesSupported[i], alg)
		}
	}
}

func TestCredentialConfigurationIgnoresNonStandardCredentialIdentifier(t *testing.T) {
	raw := `{
		"credential_issuer": "https://issuer.example",
		"credential_endpoint": "https://issuer.example/credential",
		"credential_configurations_supported": {
			"UniversityDegree": {
				"format": "vc+sd-jwt",
				"credential_identifier": "nonstandard-identifier"
			}
		}
	}`

	var metadata CredentialIssuerMetadata
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		t.Fatalf("metadata carrying the non-standard credential_identifier member did not parse: %v", err)
	}
	if _, ok := metadata.CredentialConfigurationSupported["UniversityDegree"]; !ok {
		t.Fatal("credential configuration is not keyed by its credential_configurations_supported name")
	}

	request, err := json.Marshal(CredentialRequest{CredentialConfigurationID: "UniversityDegree"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Contains(request, []byte("credential_identifier")) {
		t.Fatalf("credential request carries the non-standard credential_identifier member: %s", request)
	}
	if !bytes.Contains(request, []byte(`"credential_configuration_id":"UniversityDegree"`)) {
		t.Fatalf("credential request does not select the configuration by credential_configuration_id: %s", request)
	}
}

func TestCredentialIssuerMetadataSignedMetadataRoundTrip(t *testing.T) {
	const signed = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.signature"
	raw := `{"credential_issuer":"https://issuer.example","signed_metadata":"` + signed + `"}`
	var metadata CredentialIssuerMetadata
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if metadata.SignedMetadata != signed {
		t.Fatalf("signed_metadata = %q, want %q", metadata.SignedMetadata, signed)
	}
	metadata.MetadataSignature = &MetadataVerification{LeafCertificateSHA256: "fingerprint", Subject: "CN=issuer"}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"signed_metadata":"`+signed+`"`)) {
		t.Fatalf("signed_metadata not serialized: %s", encoded)
	}
	if bytes.Contains(encoded, []byte("MetadataSignature")) || bytes.Contains(encoded, []byte("fingerprint")) {
		t.Fatalf("MetadataVerification must not be serialized: %s", encoded)
	}
}
