package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/profile"
)

// HAIP 1.0 §5 narrows OpenID4VP 1.0 §8.3 response encryption to ECDH-ES on
// P-256 with A128GCM or A256GCM. A Verifier the narrower rules exclude is
// refused naming the option that excluded it.
func TestResponseEncryptionRefusalsNameTheOption(t *testing.T) {
	p256 := fixtureResponseEncryptionKey()
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rules := profile.HAIPOptions().ResponseEncryption
	tests := map[string]struct {
		keys   []jose.JSONWebKey
		enc    []string
		option string
		want   error
	}{
		"P-384 key": {
			keys:   []jose.JSONWebKey{{Key: &p384.PublicKey, KeyID: "p384", Use: "enc", Algorithm: "ECDH-ES"}},
			option: "ResponseEncryption.P256Only", want: ErrResponseEncryptionKeyUnusable,
		},
		"key wrapping alg": {
			keys:   []jose.JSONWebKey{{Key: &p256.PublicKey, KeyID: "kw", Use: "enc", Algorithm: "ECDH-ES+A128KW"}},
			option: "ResponseEncryption.ECDHESOnly", want: ErrResponseEncryptionKeyUnusable,
		},
		"CBC content encryption only": {
			keys:   []jose.JSONWebKey{{Key: &p256.PublicKey, KeyID: "enc", Use: "enc", Algorithm: "ECDH-ES"}},
			enc:    []string{"A128CBC-HS256"},
			option: "ResponseEncryption.GCMOnly", want: ErrResponseEncryptionEncUnsupported,
		},
		"no key any rule would use": {
			keys: []jose.JSONWebKey{{Key: &p256.PublicKey, KeyID: "sig", Use: "sig", Algorithm: "ECDH-ES"}},
			want: ErrResponseEncryptionKeyUnusable,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := selectResponseEncryptionForProfile(encryptionMetadataWith(tt.keys, tt.enc), rules)
			require.ErrorIs(t, err, tt.want)
			var refused *profile.OptionError
			if tt.option == "" {
				require.False(t, errors.As(err, &refused), "a refusal no option caused names none")
				return
			}
			require.ErrorAs(t, err, &refused)
			require.Equal(t, tt.option, refused.Option)
			// Final applies none of the narrower rules.
			_, err = selectResponseEncryptionForProfile(encryptionMetadataWith(tt.keys, tt.enc), profile.ResponseEncryptionRules{})
			require.NoError(t, err)
		})
	}
}
