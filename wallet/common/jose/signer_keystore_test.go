package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/keystore"
)

// TestJWKSigner_SignsForEveryClientAuthAlgorithm exercises the full signing
// path used by client assertions: a key entry built from a private JWK, wrapped
// by JWKSigner, driven by go-jose, and verified with the public key.
//
// The DER signatures a P-521 key produces use the long form sequence length,
// which the raw conversion has to handle for ES512 to work at all.
func TestJWKSigner_SignsForEveryClientAuthAlgorithm(t *testing.T) {
	tests := []struct {
		alg   jose.SignatureAlgorithm
		curve elliptic.Curve
	}{
		{jose.ES256, elliptic.P256()},
		{jose.ES384, elliptic.P384()},
		{jose.ES512, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			entry, err := keystore.NewKeyEntryFromJWK(jose.JSONWebKey{
				Key:       privKey,
				KeyID:     "client-key-1",
				Algorithm: string(tt.alg),
				Use:       "sig",
			})
			require.NoError(t, err)

			signerAdapter, err := NewJWKSigner(entry, tt.alg)
			require.NoError(t, err)

			signer, err := jose.NewSigner(
				jose.SigningKey{Algorithm: tt.alg, Key: signerAdapter},
				(&jose.SignerOptions{}).WithType("JWT"),
			)
			require.NoError(t, err)

			// Repeat: DER integer lengths vary with the random signature, so a
			// single round can miss an encoding that trips the conversion.
			for range 20 {
				signed, err := signer.Sign([]byte(`{"iss":"wallet-id"}`))
				require.NoError(t, err)

				serialized, err := signed.CompactSerialize()
				require.NoError(t, err)

				parsed, err := jose.ParseSigned(serialized, []jose.SignatureAlgorithm{tt.alg})
				require.NoError(t, err)

				payload, err := parsed.Verify(&privKey.PublicKey)
				require.NoError(t, err)
				assert.JSONEq(t, `{"iss":"wallet-id"}`, string(payload))
			}
		})
	}
}
