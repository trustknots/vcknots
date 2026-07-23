package types

import (
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
		"credential_signing_alg_values_supported": ["ES256", -8, -257]
	}`

	var cfg CredentialConfiguration
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []SignatureAlgorithm{
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
