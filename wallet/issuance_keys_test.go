package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/keystore"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestWallet_generateDPoPProof_HeaderAndPayload(t *testing.T) {
	key, err := newInMemoryECKeyEntry()
	require.NoError(t, err)

	w := &Wallet{}
	proof, err := w.generateDPoPProof(key, http.MethodPost, "https://server.example.com/token", "", nil)
	require.NoError(t, err)

	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var header map[string]any
	var payload map[string]any

	require.NoError(t, json.Unmarshal(headerBytes, &header))
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))

	assert.Equal(t, "dpop+jwt", header["typ"])
	assert.Equal(t, "ES256", header["alg"])

	jwk, ok := header["jwk"].(map[string]any)
	require.True(t, ok)
	assert.NotNil(t, jwk["kty"])
	assert.Nil(t, jwk["d"])

	assert.NotEmpty(t, payload["jti"])
	assert.Equal(t, "POST", payload["htm"])
	assert.Equal(t, "https://server.example.com/token", payload["htu"])
	assert.NotNil(t, payload["iat"])
}

func TestWallet_generateDPoPProof_JtiIsUnique(t *testing.T) {
	key, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	w := &Wallet{}
	proof1, err := w.generateDPoPProof(
		key,
		http.MethodPost,
		"https://server.example.com/token",
		"",
		nil,
	)
	require.NoError(t, err)
	proof2, err := w.generateDPoPProof(
		key,
		http.MethodPost,
		"https://server.example.com/token",
		"",
		nil,
	)
	require.NoError(t, err)
	jti1 := extractPayloadField(t, proof1, "jti")
	jti2 := extractPayloadField(t, proof2, "jti")
	assert.NotEqual(t, jti1, jti2)
}

func TestWallet_generateDPoPProof_NilKey(t *testing.T) {
	w := &Wallet{}
	_, err := w.generateDPoPProof(
		nil,
		http.MethodPost,
		"https://server.example.com/token",
		"",
		nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dpop key is required")
}

func TestWallet_generateDPoPProof_SignatureVerifies(t *testing.T) {
	key, err := newInMemoryECKeyEntry()
	require.NoError(t, err)

	w := &Wallet{}
	proof, err := w.generateDPoPProof(key, http.MethodPost, "https://server.example.com/token", "", nil)
	require.NoError(t, err)

	parsed, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	embeddedJWK := parsed.Signatures[0].Header.JSONWebKey
	require.NotNil(t, embeddedJWK)

	_, err = parsed.Verify(embeddedJWK.Key)
	require.NoError(t, err)
}

func TestController_generateDPoPProof_IncludesAccessTokenHashAndNonce(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	accessToken := "dpop-access-token"
	nonce := "dpop-nonce"
	htu := "https://issuer.example.com/credential"

	proof, err := controller.generateDPoPProof(key, http.MethodPost, htu, accessToken, &nonce)
	require.NoError(t, err)

	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "dpop+jwt", header["typ"])
	assert.Equal(t, "ES256", header["alg"])
	assert.Contains(t, header, "jwk")

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))

	accessTokenHash := sha256.Sum256([]byte(accessToken))
	expectedAth := base64.RawURLEncoding.EncodeToString(accessTokenHash[:])
	assert.Equal(t, http.MethodPost, payload["htm"])
	assert.Equal(t, htu, payload["htu"])
	assert.Equal(t, expectedAth, payload["ath"])
	assert.Equal(t, nonce, payload["nonce"])
	assert.NotEmpty(t, payload["jti"])
	assert.NotZero(t, payload["iat"])
}

func TestController_generateDPoPProof_RejectsInvalidES256SignatureEncoding(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := &invalidSignatureKeyEntry{mockKeyEntry: newMockKeyEntry()}

	proof, err := controller.generateDPoPProof(key, http.MethodPost, "https://issuer.example.com/credential", "access-token", nil)
	require.Error(t, err)
	assert.Empty(t, proof)
	assert.Contains(t, err.Error(), "failed to serialize dpop proof")
}

// --- private_key_jwt client authentication tests ---

func newClientAuthKeyEntry(t *testing.T, keyID string) (*mockKeyEntry, jose.JSONWebKey) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privateJWK := jose.JSONWebKey{
		Key:       privKey,
		KeyID:     keyID,
		Algorithm: "ES256",
		Use:       "sig",
	}
	publicJWK := privateJWK.Public()
	return &mockKeyEntry{
		id:         keyID,
		key:        publicJWK,
		privateKey: privKey,
	}, publicJWK
}

func TestWallet_generateClientAssertion_HeaderAndPayload(t *testing.T) {
	w := &Wallet{}

	key, _ := newClientAuthKeyEntry(t, "client-key-1")
	const clientID = "test-client-id"
	const tokenEndpoint = "https://as.example.com/token"

	assertion, err := w.generateClientAssertion(key, clientID, tokenEndpoint, jose.ES256)
	require.NoError(t, err)

	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3)

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "JWT", header["typ"])
	assert.Equal(t, "ES256", header["alg"])
	assert.Equal(t, "client-key-1", header["kid"])

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))

	assert.Equal(t, clientID, payload["iss"])
	assert.Equal(t, clientID, payload["sub"])
	assert.Equal(t, tokenEndpoint, payload["aud"])
	assert.NotEmpty(t, payload["jti"])
	assert.NotZero(t, payload["iat"])
	assert.NotZero(t, payload["exp"])
	assert.NotZero(t, payload["nbf"])

	expClaim, ok := payload["exp"].(float64)
	require.True(t, ok)
	iatClaim, ok := payload["iat"].(float64)
	require.True(t, ok)
	assert.InDelta(t, float64(clientAssertionLifetime.Seconds()), expClaim-iatClaim, 2)
}

func TestWallet_generateClientAssertion_ErrorsOnMissingInputs(t *testing.T) {
	w := &Wallet{}
	key, _ := newClientAuthKeyEntry(t, "client-key-1")

	_, err := w.generateClientAssertion(nil, "client-id", "https://as.example.com/token", jose.ES256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client auth key is required")

	_, err = w.generateClientAssertion(key, "  ", "https://as.example.com/token", jose.ES256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clientID is required")

	_, err = w.generateClientAssertion(key, "client-id", "  ", jose.ES256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience is required")
}

func boolPtr(v bool) *bool { return &v }

func authMethodsPtr(methods ...receiverTypes.TokenEndpointAuthMethod) *[]receiverTypes.TokenEndpointAuthMethod {
	m := methods
	return &m
}

func TestResolveClientAuthMethod(t *testing.T) {
	key, _ := newClientAuthKeyEntry(t, "client-key-1")

	t.Run("defaults to none when anonymous supported and nothing configured", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
		}
		method, ok := resolveClientAuthMethod(ClientAuthConfig{}, authMetadata)
		require.True(t, ok)
		assert.Equal(t, receiverTypes.None, method)
	})

	t.Run("selects private_key_jwt when configured and advertised", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
			TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.ES256},
		}
		method, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		require.True(t, ok)
		assert.Equal(t, receiverTypes.PrivateKeyJwt, method)
	})

	t.Run("defaults to none even when private_key_jwt credentials are configured", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
		}
		method, ok := resolveClientAuthMethod(ClientAuthConfig{
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		require.True(t, ok)
		assert.Equal(t, receiverTypes.None, method)
	})

	t.Run("honors explicit private_key_jwt method", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
			TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.ES256},
		}
		method, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		require.True(t, ok)
		assert.Equal(t, receiverTypes.PrivateKeyJwt, method)
	})

	t.Run("does not fall back to none when private_key_jwt is not advertised", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
		}
		_, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		assert.False(t, ok)
	})

	t.Run("returns false when no method is usable", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(false),
		}
		_, ok := resolveClientAuthMethod(ClientAuthConfig{}, authMetadata)
		assert.False(t, ok)
	})

	t.Run("private_key_jwt rejected when alg not supported", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
			TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.RS256},
		}
		_, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		assert.False(t, ok)
	})

	t.Run("private_key_jwt rejected when signing alg metadata is omitted", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported: authMethodsPtr(receiverTypes.PrivateKeyJwt),
		}
		_, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		assert.False(t, ok)
	})

	t.Run("private_key_jwt rejected when signing alg metadata is empty", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
			TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{},
		}
		_, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		assert.False(t, ok)
	})

	t.Run("private_key_jwt rejected when client id/key missing", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported: authMethodsPtr(receiverTypes.PrivateKeyJwt),
		}
		_, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method: receiverTypes.PrivateKeyJwt,
		}, authMetadata)
		assert.False(t, ok)
	})
}

func TestClientAuthMethodAvailable_HonoursConfiguredSigningAlg(t *testing.T) {
	key, _ := newClientAuthKeyEntry(t, "client-key-1")
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
		TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.ES384},
	}

	// The authorization server advertises ES384 only, so the ES256 default
	// finds no usable method.
	assert.False(t, clientAuthMethodAvailable(
		receiverTypes.PrivateKeyJwt,
		ClientAuthConfig{ClientID: "wallet-id", Key: key},
		authMetadata,
	))

	assert.True(t, clientAuthMethodAvailable(
		receiverTypes.PrivateKeyJwt,
		ClientAuthConfig{ClientID: "wallet-id", Key: key, SigningAlg: jose.ES384},
		authMetadata,
	))
}

func TestWallet_generateClientAssertion_SupportsEveryConfigurableAlgorithm(t *testing.T) {
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
			// mockKeyEntry only signs with P-256, so use the key entry the
			// configuration loader actually produces.
			key, err := keystore.NewKeyEntryFromJWK(jose.JSONWebKey{
				Key:       privKey,
				KeyID:     "client-key-1",
				Algorithm: string(tt.alg),
				Use:       "sig",
			})
			require.NoError(t, err)

			clientAuth := ClientAuthConfig{
				Method:     receiverTypes.PrivateKeyJwt,
				ClientID:   "wallet-id",
				Key:        key,
				SigningAlg: tt.alg,
			}
			require.NoError(t, validateClientAuthConfig(clientAuth))

			w := &Wallet{clientAuth: clientAuth}
			assertion, err := w.generateClientAssertion(key, "wallet-id", "https://as.example.com", tt.alg)
			require.NoError(t, err)

			parts := strings.Split(assertion, ".")
			require.Len(t, parts, 3)

			headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
			require.NoError(t, err)
			var header map[string]interface{}
			require.NoError(t, json.Unmarshal(headerBytes, &header))
			assert.Equal(t, string(tt.alg), header["alg"])

			// Parsing with the public key proves the signature encoding is the
			// IEEE P1363 form a JWS verifier expects, not raw DER.
			parsed, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{tt.alg})
			require.NoError(t, err)
			claims := map[string]interface{}{}
			require.NoError(t, parsed.Claims(&privKey.PublicKey, &claims))
			assert.Equal(t, "wallet-id", claims["iss"])
		})
	}
}

func TestWallet_generateClientAssertion_RejectsNonECDSAAlgorithm(t *testing.T) {
	w := &Wallet{}
	key, _ := newClientAuthKeyEntry(t, "client-key-1")

	_, err := w.generateClientAssertion(key, "client-id", "https://as.example.com", jose.RS256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported client authentication signing algorithm")
}

func TestResolveClientAssertionAudience(t *testing.T) {
	tokenEndpoint := "https://as.example.com/token"
	issuer, err := common.ParseURIField("https://as.example.com")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{Issuer: *issuer}

	assert.Equal(t, "https://registered-audience.example.com", resolveClientAssertionAudience(
		ClientAuthConfig{AssertionAudience: "https://registered-audience.example.com"},
		authMetadata,
		tokenEndpoint,
	))
	assert.Equal(t, "https://as.example.com", resolveClientAssertionAudience(
		ClientAuthConfig{},
		authMetadata,
		tokenEndpoint,
	))
	assert.Equal(t, tokenEndpoint, resolveClientAssertionAudience(
		ClientAuthConfig{},
		&receiverTypes.AuthorizationServerMetadata{},
		tokenEndpoint,
	))
}
