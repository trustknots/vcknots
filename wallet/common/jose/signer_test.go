package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// mockKeyEntry implements keystore.KeyEntry for testing
type mockKeyEntry struct {
	keyID      string
	publicKey  jose.JSONWebKey
	privateKey any
	algorithm  string
}

func (m *mockKeyEntry) ID() string {
	return m.keyID
}

func (m *mockKeyEntry) PublicKey() jose.JSONWebKey {
	return m.publicKey
}

func (m *mockKeyEntry) Sign(data []byte) ([]byte, error) {
	// Only ECDSA is currently tested
	if ecdsaKey, ok := m.privateKey.(*ecdsa.PrivateKey); ok {
		hash := sha256.Sum256(data)
		return ecdsa.SignASN1(rand.Reader, ecdsaKey, hash[:])
	}
	return nil, nil
}

func createMockECDSAKey(curve elliptic.Curve, alg string) *mockKeyEntry {
	privateKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
	jwk := jose.JSONWebKey{
		Algorithm: alg,
		KeyID:     "test-key",
		Use:       "sig",
		Key:       &privateKey.PublicKey,
	}
	return &mockKeyEntry{
		keyID:      "test-key",
		publicKey:  jwk,
		privateKey: privateKey,
		algorithm:  alg,
	}
}

// Unused helper functions removed - will be added when needed for RSA/EdDSA tests

func TestNewJWKSigner(t *testing.T) {
	t.Run("nil keyEntry", func(t *testing.T) {
		signer, err := NewJWKSigner(nil, jose.ES256)
		if err == nil {
			t.Error("expected error for nil keyEntry")
		}
		if signer != nil {
			t.Error("expected nil signer for nil keyEntry")
		}
	})

	t.Run("successful creation with ES256", func(t *testing.T) {
		keyEntry := createMockECDSAKey(elliptic.P256(), "ES256")
		signer, err := NewJWKSigner(keyEntry, jose.ES256)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if signer == nil {
			t.Error("expected non-nil signer")
		}
		if signer != nil && signer.algorithm != jose.ES256 {
			t.Errorf("expected algorithm ES256, got %v", signer.algorithm)
		}
	})
}

func TestJWKSigner_SignPayload(t *testing.T) {
	tests := []struct {
		name           string
		curve          elliptic.Curve
		signerAlg      jose.SignatureAlgorithm
		requestedAlg   jose.SignatureAlgorithm
		expectedSigLen int
		wantErr        bool
		verifyFunc     func(pubKey *ecdsa.PublicKey, hash []byte, sig []byte) bool
	}{
		{
			name:           "algorithm mismatch",
			curve:          elliptic.P256(),
			signerAlg:      jose.ES256,
			requestedAlg:   jose.ES384,
			expectedSigLen: 0,
			wantErr:        true,
			verifyFunc:     nil,
		},
		{
			name:           "ES256 signing and verification",
			curve:          elliptic.P256(),
			signerAlg:      jose.ES256,
			requestedAlg:   jose.ES256,
			expectedSigLen: 64,
			wantErr:        false,
			verifyFunc: func(pubKey *ecdsa.PublicKey, hash []byte, sig []byte) bool {
				if len(sig) != 64 {
					return false
				}
				r := new(big.Int).SetBytes(sig[:32])
				s := new(big.Int).SetBytes(sig[32:])
				return ecdsa.Verify(pubKey, hash, r, s)
			},
		},
		{
			name:           "ES384 signing and verification",
			curve:          elliptic.P384(),
			signerAlg:      jose.ES384,
			requestedAlg:   jose.ES384,
			expectedSigLen: 96,
			wantErr:        false,
			verifyFunc: func(pubKey *ecdsa.PublicKey, hash []byte, sig []byte) bool {
				if len(sig) != 96 {
					return false
				}
				r := new(big.Int).SetBytes(sig[:48])
				s := new(big.Int).SetBytes(sig[48:])
				return ecdsa.Verify(pubKey, hash, r, s)
			},
		},
		// Note: ES512 (P-521) test is skipped due to variable-length DER encoding issues
		// Will be implemented using RFC 7515 test vectors
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var keyEntry *mockKeyEntry
			if tt.curve != nil {
				keyEntry = createMockECDSAKey(tt.curve, string(tt.signerAlg))
			}

			signer, _ := NewJWKSigner(keyEntry, tt.signerAlg)
			payload := []byte("test payload")

			signature, err := signer.SignPayload(payload, tt.requestedAlg)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignPayload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify signature length
			if len(signature) != tt.expectedSigLen {
				t.Errorf("expected signature length %d, got %d", tt.expectedSigLen, len(signature))
			}

			// Verify signature cryptographically
			if tt.verifyFunc != nil {
				pubKey := keyEntry.publicKey.Key.(*ecdsa.PublicKey)
				hash := sha256.Sum256(payload)
				if !tt.verifyFunc(pubKey, hash[:], signature) {
					t.Error("signature verification failed")
				}
			}
		})
	}
}

// derSignature encodes r and s as SEQUENCE { INTEGER, INTEGER }, short-form only.
func derSignature(r, s []byte) []byte {
	var body []byte
	for _, component := range [][]byte{r, s} {
		body = append(body, 0x02, byte(len(component)))
		body = append(body, component...)
	}
	return append([]byte{0x30, byte(len(body))}, body...)
}

func TestConvertDERToRaw(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		keySize     int
		expectedLen int
		wantErr     bool
	}{
		{
			name: "RFC 7515 A.3 ES256 raw signature",
			// RFC 7515 Appendix A.3 ES256 signature (already in raw format)
			input: func() []byte {
				sig, _ := base64.RawURLEncoding.DecodeString("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q")
				return sig
			}(),
			keySize:     32,
			expectedLen: 64,
			wantErr:     false,
		},
		{
			name: "ES256 raw signature starting with DER sequence tag",
			input: func() []byte {
				sig := make([]byte, 64)
				sig[0] = 0x30
				sig[1] = 0x01
				sig[2] = 0x7f
				sig[32] = 0x20
				sig[63] = 0x01
				return sig
			}(),
			keySize:     32,
			expectedLen: 64,
			wantErr:     false,
		},
		{
			name:        "invalid DER signature too short",
			input:       []byte{0x30, 0x05},
			keySize:     32,
			expectedLen: 0,
			wantErr:     true,
		},
		{
			name:        "invalid format and wrong length",
			input:       []byte{0xFF, 0xFF, 0xFF},
			keySize:     32,
			expectedLen: 0,
			wantErr:     true,
		},
		{
			name:        "DER signature with trailing data",
			input:       append(derSignature(bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 32)), 0x00),
			keySize:     32,
			expectedLen: 0,
			wantErr:     true,
		},
		{
			name:        "DER component wider than the key size",
			input:       derSignature(bytes.Repeat([]byte{0x01}, 33), bytes.Repeat([]byte{0x02}, 32)),
			keySize:     32,
			expectedLen: 0,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawSig, err := ConvertDERToRaw(tt.input, tt.keySize)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, rawSig, tt.expectedLen)
		})
	}
}

func TestConvertDERToRawAcceptsASN1Signatures(t *testing.T) {
	tests := []struct {
		name    string
		curve   elliptic.Curve
		keySize int
	}{
		{"P-256 (ES256)", elliptic.P256(), 32},
		{"P-384 (ES384)", elliptic.P384(), 48},
		// P-521 DER runs past 127 bytes, so its SEQUENCE length is long-form.
		{"P-521 (ES512)", elliptic.P521(), 66},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)
			hash := sha256.Sum256([]byte("payload"))

			// R and S differ per signature, so repeat to also hit short components.
			for i := 0; i < 20; i++ {
				derSig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
				require.NoError(t, err)

				rawSig, err := ConvertDERToRaw(derSig, tt.keySize)
				require.NoError(t, err, "DER length %d", len(derSig))
				require.Len(t, rawSig, tt.keySize*2)

				r := new(big.Int).SetBytes(rawSig[:tt.keySize])
				s := new(big.Int).SetBytes(rawSig[tt.keySize:])
				require.True(t, ecdsa.Verify(&key.PublicKey, hash[:], r, s), "converted signature failed verification")
			}
		})
	}
}

func TestGetKeySizeForAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		alg      jose.SignatureAlgorithm
		expected int
		wantErr  bool
	}{
		{
			name:     "ES256",
			alg:      jose.ES256,
			expected: 32,
			wantErr:  false,
		},
		{
			name:     "ES384",
			alg:      jose.ES384,
			expected: 48,
			wantErr:  false,
		},
		{
			name:     "ES512",
			alg:      jose.ES512,
			expected: 66,
			wantErr:  false,
		},
		{
			name:     "RS256 unsupported",
			alg:      jose.RS256,
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "EdDSA unsupported",
			alg:      jose.EdDSA,
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := GetKeySizeForAlgorithm(tt.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetKeySizeForAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if size != tt.expected {
				t.Errorf("expected size %d, got %d", tt.expected, size)
			}
		})
	}
}
