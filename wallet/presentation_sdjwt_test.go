package wallet

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// sdJWTRaw builds the compact SD-JWT VC wire value the helper reads: a
// three-part JWS followed by one disclosure, so the confirmation check has to
// stop at the first separator.
func sdJWTRaw(t *testing.T, payload map[string]any) []byte {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"})
	require.NoError(t, err)
	body, err := json.Marshal(payload)
	require.NoError(t, err)
	return []byte(base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body) + ".signature~disclosure")
}

// TestsdJWTCarriesConfirmation pins the holder-binding signal OpenID4VP
// 1.0 Appendix B.3 relies on: the issuer JWT payload carries cnf.
func TestSDJWTCarriesConfirmation(t *testing.T) {
	t.Run("carries-cnf", func(t *testing.T) {
		require.True(t, sdJWTCarriesConfirmation(sdJWTRaw(t, map[string]any{
			"vct": "https://example/pid",
			"cnf": map[string]any{"jwk": map[string]any{"kty": "EC"}},
		})))
	})
	t.Run("without-cnf", func(t *testing.T) {
		require.False(t, sdJWTCarriesConfirmation(sdJWTRaw(t, map[string]any{"vct": "https://example/pid"})))
	})
	t.Run("not-a-compact-jws", func(t *testing.T) {
		require.False(t, sdJWTCarriesConfirmation([]byte("not-a-jwt")))
	})
	t.Run("payload-not-a-json-object", func(t *testing.T) {
		raw := []byte("header." + base64.RawURLEncoding.EncodeToString([]byte("[1,2]")) + ".signature")
		require.False(t, sdJWTCarriesConfirmation(raw))
	})
	t.Run("payload-not-base64url", func(t *testing.T) {
		require.False(t, sdJWTCarriesConfirmation([]byte("header.!!!.signature")))
	})
}
