package common

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet"
	joseutil "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/receiver"
)

// serverClients is the subset of server/samples/oauth-clients.json needed to
// confirm that the wallet-side and server-side sample files describe the same
// client registration.
type serverClients struct {
	Clients []struct {
		ClientID string              `json:"client_id"`
		JWKS     *jose.JSONWebKeySet `json:"jwks"`
	} `json:"clients"`
}

const serverClientsPath = "../../../server/samples/oauth-clients.json"

func TestLoadClientAuth_ReadsCommittedSampleConfiguration(t *testing.T) {
	clientAuth, err := LoadClientAuth()
	require.NoError(t, err)

	assert.Equal(t, receiver.PrivateKeyJwt, clientAuth.Method)
	assert.Equal(t, DefaultClientID, clientAuth.ClientID)
	assert.Equal(t, jose.ES256, clientAuth.SigningAlg)
	assert.Equal(t, "https://authz.example.com", clientAuth.AssertionAudience)

	require.NotNil(t, clientAuth.Key)
	publicJWK := clientAuth.Key.PublicKey()
	assert.Equal(t, "client-key-1", publicJWK.KeyID)
	assert.True(t, publicJWK.IsPublic(), "the wallet must not expose the private component")
}

func TestLoadClientAuth_ProducesAcceptedWalletConfig(t *testing.T) {
	clientAuth, err := LoadClientAuth()
	require.NoError(t, err)

	w, err := wallet.NewWalletWithConfig(wallet.Config{ClientAuth: clientAuth})
	require.NoError(t, err)
	assert.NotNil(t, w)
}

func TestSampleClientConfig_MatchesServerRegistration(t *testing.T) {
	clientAuth, err := LoadClientAuth()
	require.NoError(t, err)

	data, err := os.ReadFile(serverClientsPath)
	require.NoError(t, err)

	var registered serverClients
	require.NoError(t, json.Unmarshal(data, &registered))

	var registeredJWK *jose.JSONWebKey
	for _, client := range registered.Clients {
		if client.ClientID != clientAuth.ClientID || client.JWKS == nil {
			continue
		}
		for _, key := range client.JWKS.Keys {
			if key.KeyID == clientAuth.Key.PublicKey().KeyID {
				registeredJWK = &key
				break
			}
		}
	}
	require.NotNil(t, registeredJWK,
		"client %q key %q is not registered in %s",
		clientAuth.ClientID, clientAuth.Key.PublicKey().KeyID, serverClientsPath)

	equal, err := joseutil.EqualPublicKey(*registeredJWK, clientAuth.Key.PublicKey())
	require.NoError(t, err)
	assert.True(t, equal,
		"the wallet signing key no longer matches the public key registered in %s", serverClientsPath)
}
