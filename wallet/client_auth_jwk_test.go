package wallet

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

const conformanceClientAuthJWKConfig = `{
	"client_id": "test-client-id",
	"client_assertion_audience": "https://authz.example.com",
	"jwks": {
		"keys": [
			{
				"kty": "EC",
				"crv": "P-256",
				"x": "ezZgKwMueAyZLHUgSpzNkbOWDgjJXTAOJn8MftOnayQ",
				"y": "Fy_U4KyZQf-9jKpFJtH6OFFRXmwAcveyfuoDp1hSOFo",
				"d": "jAfOh_53IRxqpEsFojZK8iHP--L8ol3ePEo3DnwiIyM",
				"alg": "ES256",
				"use": "sig",
				"kid": "client-key-1"
			}
		]
	}
}`

func TestParseClientAuthJWKConfig_ConformanceKey(t *testing.T) {
	config, err := ParseClientAuthJWKConfig([]byte(conformanceClientAuthJWKConfig))
	require.NoError(t, err)

	assert.Equal(t, receiverTypes.PrivateKeyJwt, config.Method)
	assert.Equal(t, "test-client-id", config.ClientID)
	assert.Equal(t, "https://authz.example.com", config.AssertionAudience)
	require.NotNil(t, config.Key)
	assert.Equal(t, "client-key-1", config.Key.ID())
	assert.Equal(t, "client-key-1", config.Key.PublicKey().KeyID)

	w := &Wallet{}
	assertion, err := w.generateClientAssertion(config.Key, config.ClientID, config.AssertionAudience)
	require.NoError(t, err)

	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3)
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	assert.Equal(t, "client-key-1", header["kid"])
	assert.Equal(t, "ES256", header["alg"])
}

func TestParseClientAuthJWKConfig_RequiresKeySelectionForMultipleKeys(t *testing.T) {
	input := strings.Replace(
		conformanceClientAuthJWKConfig,
		`"keys": [`,
		`"keys": [
			{
				"kty": "EC",
				"crv": "P-256",
				"x": "ezZgKwMueAyZLHUgSpzNkbOWDgjJXTAOJn8MftOnayQ",
				"y": "Fy_U4KyZQf-9jKpFJtH6OFFRXmwAcveyfuoDp1hSOFo",
				"d": "jAfOh_53IRxqpEsFojZK8iHP--L8ol3ePEo3DnwiIyM",
				"alg": "ES256",
				"use": "sig",
				"kid": "old-client-key"
			},`,
		1,
	)

	_, err := ParseClientAuthJWKConfig([]byte(input))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing_key_id is required")

	input = strings.Replace(input, `"client_id": "test-client-id",`, `"client_id": "test-client-id", "signing_key_id": "client-key-1",`, 1)
	config, err := ParseClientAuthJWKConfig([]byte(input))
	require.NoError(t, err)
	assert.Equal(t, "client-key-1", config.Key.ID())
}
