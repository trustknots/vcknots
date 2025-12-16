package jose

import (
	"crypto/sha256"
	"crypto/sha512"
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
			name:     "unsupported algorithm",
			algStr:   "HS256",
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
