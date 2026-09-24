package jose

import (
	"crypto/sha256"
	"crypto/sha512"
	"slices"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		algStr   string
		expected jose.SignatureAlgorithm
		wantErr  bool
	}{
		{
			name:     "ES256",
			algStr:   "ES256",
			expected: jose.ES256,
			wantErr:  false,
		},
		{
			name:     "ES384",
			algStr:   "ES384",
			expected: jose.ES384,
			wantErr:  false,
		},
		{
			name:     "ES512",
			algStr:   "ES512",
			expected: jose.ES512,
			wantErr:  false,
		},
		{
			name:     "EdDSA",
			algStr:   "EdDSA",
			expected: jose.EdDSA,
			wantErr:  false,
		},
		{
			name:     "RS256",
			algStr:   "RS256",
			expected: jose.RS256,
			wantErr:  false,
		},
		{
			name:     "RS384",
			algStr:   "RS384",
			expected: jose.RS384,
			wantErr:  false,
		},
		{
			name:     "RS512",
			algStr:   "RS512",
			expected: jose.RS512,
			wantErr:  false,
		},
		{
			name:     "PS256",
			algStr:   "PS256",
			expected: jose.PS256,
			wantErr:  false,
		},
		{
			name:     "PS384",
			algStr:   "PS384",
			expected: jose.PS384,
			wantErr:  false,
		},
		{
			name:     "PS512",
			algStr:   "PS512",
			expected: jose.PS512,
			wantErr:  false,
		},
		{
			name:     "unsupported algorithm",
			algStr:   "HS256",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "none is never an algorithm",
			algStr:   "none",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "the comparison is case sensitive",
			algStr:   "es256",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "empty string",
			algStr:   "",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseAlgorithm(tt.algStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("ParseAlgorithm() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestAcceptedSignatureAlgorithms(t *testing.T) {
	expected := []jose.SignatureAlgorithm{
		jose.ES256, jose.ES384, jose.ES512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	}

	got := AcceptedSignatureAlgorithms()
	if len(got) != len(expected) {
		t.Fatalf("expected %d algorithms, got %d: %v", len(expected), len(got), got)
	}
	for _, alg := range expected {
		if !slices.Contains(got, alg) {
			t.Errorf("expected %v to be accepted", alg)
		}
	}

	for _, rejected := range []jose.SignatureAlgorithm{"none", jose.HS256, jose.HS384, jose.HS512} {
		if slices.Contains(got, rejected) {
			t.Errorf("algorithm %v must never be accepted", rejected)
		}
		if _, err := ParseAlgorithm(string(rejected)); err == nil {
			t.Errorf("ParseAlgorithm(%q) unexpectedly succeeded", rejected)
		}
	}

	// The returned slice is a copy: mutating it must not affect the canonical list.
	got[0] = jose.HS256
	if slices.Contains(AcceptedSignatureAlgorithms(), jose.HS256) {
		t.Error("mutating the returned slice changed the canonical list")
	}
}

func TestNewHashFromAlgorithm(t *testing.T) {
	tests := []struct {
		name         string
		alg          jose.SignatureAlgorithm
		expectedSize int // Size of the hash output in bytes
	}{
		{
			name:         "ES256",
			alg:          jose.ES256,
			expectedSize: 32, // SHA-256
		},
		{
			name:         "RS256",
			alg:          jose.RS256,
			expectedSize: 32, // SHA-256
		},
		{
			name:         "ES384",
			alg:          jose.ES384,
			expectedSize: 48, // SHA-384
		},
		{
			name:         "ES512",
			alg:          jose.ES512,
			expectedSize: 64, // SHA-512
		},
		{
			name:         "RS384",
			alg:          jose.RS384,
			expectedSize: 48, // SHA-384
		},
		{
			name:         "RS512",
			alg:          jose.RS512,
			expectedSize: 64, // SHA-512
		},
		{
			name:         "PS256",
			alg:          jose.PS256,
			expectedSize: 32, // SHA-256
		},
		{
			name:         "PS384",
			alg:          jose.PS384,
			expectedSize: 48, // SHA-384
		},
		{
			name:         "PS512",
			alg:          jose.PS512,
			expectedSize: 64, // SHA-512
		},
		{
			name:         "EdDSA",
			alg:          jose.EdDSA,
			expectedSize: 64, // SHA-512
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := NewHashFromAlgorithm(tt.alg)
			if hash == nil {
				t.Fatal("expected non-nil hash")
			}

			// Verify hash output size by writing some data and checking the sum
			testData := []byte("test data")
			hash.Write(testData)
			sum := hash.Sum(nil)

			if len(sum) != tt.expectedSize {
				t.Errorf("expected hash size %d, got %d", tt.expectedSize, len(sum))
			}

			// Verify specific hash types
			switch tt.alg {
			case jose.ES256, jose.RS256:
				expected := sha256.Sum256(testData)
				if string(sum) != string(expected[:]) {
					t.Error("expected SHA-256 hash")
				}
			case jose.ES384:
				expected := sha512.Sum384(testData)
				if string(sum) != string(expected[:]) {
					t.Error("expected SHA-384 hash")
				}
			case jose.ES512, jose.EdDSA:
				expected := sha512.Sum512(testData)
				if string(sum) != string(expected[:]) {
					t.Error("expected SHA-512 hash")
				}
			}
		})
	}
}
