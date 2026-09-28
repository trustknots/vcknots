package wallet

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/idprof/plugins/did"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
)

func unsignedJWTVC(t *testing.T, claims map[string]any) []byte {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return []byte("eyJhbGciOiJFUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln")
}

func didKeyOf(t *testing.T, key jose.JSONWebKey) string {
	t.Helper()
	public := key.Public()
	profile, err := did.NewDIDKeyProfile(&did.DIDKeyProfileCreateOptions{
		DIDProfileCreateOptions: did.DIDProfileCreateOptions{Method: "key"},
		PublicKey:               &public,
	})
	require.NoError(t, err)
	return profile.ToDIDProfile().ID
}

// A W3C VC is bound to its holder through the subject DID rather than cnf
// (OpenID4VCI 1.0 Section 12.2.4 cryptographic_binding_methods_supported
// "did:key"), so a jwt_vc_json credential whose subject is the holder's
// did:key satisfies a configuration that requires binding.
func TestJWTVCBindingThroughTheSubjectDID(t *testing.T) {
	holder := jose.JSONWebKey{Key: testutil.NewP256Key(t)}
	other := jose.JSONWebKey{Key: testutil.NewP256Key(t)}
	holders := []jose.JSONWebKey{holder}

	t.Run("sub names the holder's did:key", func(t *testing.T) {
		raw := unsignedJWTVC(t, map[string]any{"iss": "https://issuer.example", "sub": didKeyOf(t, holder)})
		bound, err := matchBatchHolderKey(raw, credential.JwtVc, holders, make([]bool, 1), true)
		require.NoError(t, err)
		require.NotNil(t, bound)
	})
	t.Run("credentialSubject.id names the holder's did:key", func(t *testing.T) {
		raw := unsignedJWTVC(t, map[string]any{"iss": "https://issuer.example", "vc": map[string]any{
			"credentialSubject": map[string]any{"id": didKeyOf(t, holder)},
		}})
		bound, err := matchBatchHolderKey(raw, credential.JwtVc, holders, make([]bool, 1), true)
		require.NoError(t, err)
		require.NotNil(t, bound)
	})
	t.Run("sub names another key", func(t *testing.T) {
		raw := unsignedJWTVC(t, map[string]any{"iss": "https://issuer.example", "sub": didKeyOf(t, other)})
		_, err := matchBatchHolderKey(raw, credential.JwtVc, holders, make([]bool, 1), true)
		require.ErrorIs(t, err, acceptance.ErrHolderBindingMismatch)
	})
	t.Run("no subject DID", func(t *testing.T) {
		raw := unsignedJWTVC(t, map[string]any{"iss": "https://issuer.example", "sub": "https://holder.example"})
		_, err := matchBatchHolderKey(raw, credential.JwtVc, holders, make([]bool, 1), true)
		require.ErrorIs(t, err, acceptance.ErrHolderBindingMissing)
	})
}
