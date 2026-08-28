package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPrivateJWK(t *testing.T, curve elliptic.Curve, keyID, alg string) jose.JSONWebKey {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return jose.JSONWebKey{
		Key:       privKey,
		KeyID:     keyID,
		Algorithm: alg,
		Use:       "sig",
	}
}

func TestNewKeyEntryFromJWK_ExposesPublicHalfOnly(t *testing.T) {
	privateJWK := newPrivateJWK(t, elliptic.P256(), "client-key-1", "ES256")

	entry, err := NewKeyEntryFromJWK(privateJWK)
	require.NoError(t, err)

	assert.Equal(t, "client-key-1", entry.ID())

	publicJWK := entry.PublicKey()
	assert.Equal(t, "client-key-1", publicJWK.KeyID)
	assert.Equal(t, "ES256", publicJWK.Algorithm)
	assert.Equal(t, "sig", publicJWK.Use)
	assert.True(t, publicJWK.IsPublic(), "PublicKey must not leak the private component")

	expected := privateJWK.Public()
	assert.Equal(t, expected.Key, publicJWK.Key)
}

func TestNewKeyEntryFromJWK_SignVerifiesAgainstPublicKey(t *testing.T) {
	tests := []struct {
		name   string
		curve  elliptic.Curve
		alg    string
		digest func([]byte) []byte
	}{
		{
			name:  "P-256 uses SHA-256",
			curve: elliptic.P256(),
			alg:   "ES256",
			digest: func(payload []byte) []byte {
				sum := sha256.Sum256(payload)
				return sum[:]
			},
		},
		{
			name:  "P-384 uses SHA-384",
			curve: elliptic.P384(),
			alg:   "ES384",
			digest: func(payload []byte) []byte {
				sum := sha512.Sum384(payload)
				return sum[:]
			},
		},
		{
			name:  "P-521 uses SHA-512",
			curve: elliptic.P521(),
			alg:   "ES512",
			digest: func(payload []byte) []byte {
				sum := sha512.Sum512(payload)
				return sum[:]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateJWK := newPrivateJWK(t, tt.curve, "client-key-1", tt.alg)

			entry, err := NewKeyEntryFromJWK(privateJWK)
			require.NoError(t, err)

			payload := []byte("client assertion signing input")
			signature, err := entry.Sign(payload)
			require.NoError(t, err)

			publicKey, ok := entry.PublicKey().Key.(*ecdsa.PublicKey)
			require.True(t, ok)
			assert.True(t, ecdsa.VerifyASN1(publicKey, tt.digest(payload), signature))
		})
	}
}

func TestNewKeyEntryFromJWK_FallsBackToThumbprintWhenKidIsAbsent(t *testing.T) {
	privateJWK := newPrivateJWK(t, elliptic.P256(), "", "ES256")

	entry, err := NewKeyEntryFromJWK(privateJWK)
	require.NoError(t, err)

	assert.NotEmpty(t, entry.ID())
	// The kid stays empty so that callers requiring one still fail their own
	// validation, as private_key_jwt does.
	assert.Empty(t, entry.PublicKey().KeyID)
}

func TestNewKeyEntryFromJWK_RejectsUnusableKeys(t *testing.T) {
	t.Run("public key only", func(t *testing.T) {
		privateJWK := newPrivateJWK(t, elliptic.P256(), "client-key-1", "ES256")

		_, err := NewKeyEntryFromJWK(privateJWK.Public())
		require.ErrorIs(t, err, ErrInvalidPrivateKey)
	})

	t.Run("unsupported curve", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)

		_, err = NewKeyEntryFromJWK(jose.JSONWebKey{Key: privKey, KeyID: "client-key-1"})
		require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})

	t.Run("non-EC key type", func(t *testing.T) {
		_, err := NewKeyEntryFromJWK(jose.JSONWebKey{Key: []byte("symmetric"), KeyID: "client-key-1"})
		require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
	})
}

func TestNewKeyEntryFromJWKBytes(t *testing.T) {
	privateJWK := newPrivateJWK(t, elliptic.P256(), "client-key-1", "ES256")
	data, err := json.Marshal(privateJWK)
	require.NoError(t, err)

	entry, err := NewKeyEntryFromJWKBytes(data)
	require.NoError(t, err)
	assert.Equal(t, "client-key-1", entry.ID())

	_, err = NewKeyEntryFromJWKBytes([]byte("{"))
	require.ErrorIs(t, err, ErrInvalidKeyEntry)
}
