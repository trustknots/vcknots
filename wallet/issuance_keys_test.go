package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
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

	t.Run("rejects when token_endpoint_auth_methods_supported is omitted", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(false),
		}
		_, err := resolveClientAuthMethod(ClientAuthConfig{}, authMetadata)
		require.ErrorIs(t, err, errNoUsableClientAuthMethod)
		assert.Contains(t, err.Error(), "token_endpoint_auth_methods_supported is absent")
		assert.Contains(t, err.Error(), "client_secret_basic",
			"the rule that decides this is nowhere in the metadata, so the error has to name it")
	})

	// Configured private_key_jwt credentials never promote an unset Method.
	t.Run("an unset method is never promoted to private_key_jwt", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
		}
		_, err := resolveClientAuthMethod(ClientAuthConfig{
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		require.ErrorIs(t, err, errNoUsableClientAuthMethod)
		assert.Contains(t, err.Error(), `the wallet is configured for "none"`)
	})

	t.Run("does not fall back to none when private_key_jwt is not advertised", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.None),
		}
		_, err := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		require.ErrorIs(t, err, errNoUsableClientAuthMethod)
		assert.Contains(t, err.Error(), `the wallet is configured for "private_key_jwt"`,
			"none is usable here, and the wallet still must not silently take it")
	})

	t.Run("a method list without none outweighs explicit anonymous support", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
		}
		_, err := resolveClientAuthMethod(ClientAuthConfig{}, authMetadata)
		require.ErrorIs(t, err, errNoUsableClientAuthMethod)
		assert.Contains(t, err.Error(), `the wallet is configured for "none"`)
		assert.Contains(t, err.Error(), "only whether client_id may be omitted",
			"an operator reading anonymous access: true needs to be told why it was not enough")
	})

	t.Run("private_key_jwt rejected when alg not supported", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
			TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.RS256},
		}
		_, err := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		require.ErrorIs(t, err, errNoUsableClientAuthMethod)
		assert.Contains(t, err.Error(), "does not advertise ES256")
	})

	// RFC 8414 section 2 defines no default, so absent and empty fail alike.
	t.Run("private_key_jwt rejected when signing alg metadata is unusable", func(t *testing.T) {
		for _, algs := range []*[]jose.SignatureAlgorithm{nil, {}} {
			_, err := resolveClientAuthMethod(ClientAuthConfig{
				Method:   receiverTypes.PrivateKeyJwt,
				ClientID: "client-id",
				Key:      key,
			}, &receiverTypes.AuthorizationServerMetadata{
				TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
				TokenEndpointAuthSigningAlgValuesSupported: algs,
			})
			require.ErrorIs(t, err, errNoUsableClientAuthMethod)
			assert.Contains(t, err.Error(), "omits token_endpoint_auth_signing_alg_values_supported")
		}
	})
}

// TestResolveClientAuthMethod_Matrix covers metadata list x anonymous flag x
// wallet config. The disagreeing cells used to resolve the other way round.
func TestResolveClientAuthMethod_Matrix(t *testing.T) {
	key, _ := newClientAuthKeyEntry(t, "client-key-1")

	// Without C2's client_id, "sent none" and "had none to send" look identical.
	var (
		configNoClientID = ClientAuthConfig{}
		configClientID   = ClientAuthConfig{Method: receiverTypes.None, ClientID: "wallet-id"}
		configPrivateKey = ClientAuthConfig{Method: receiverTypes.PrivateKeyJwt, ClientID: "wallet-id", Key: key}
	)

	const (
		errListAbsent      = "token_endpoint_auth_methods_supported is absent"
		errNotAdvertised   = `the wallet is configured for "none"`
		errClientIDAbsent  = "pre-authorized_grant_anonymous_access_supported is absent"
		errClientIDRefused = "pre-authorized_grant_anonymous_access_supported is false"
	)

	tests := []struct {
		name             string
		methods          *[]receiverTypes.TokenEndpointAuthMethod
		anon             *bool
		clientAuth       ClientAuthConfig
		wantMethod       receiverTypes.TokenEndpointAuthMethod
		wantSendClientID bool
		wantErrContains  string
	}{
		// Absent list: RFC 8414 section 2 default.
		{name: "methods=absent/anon=absent/config=C1", methods: nil, anon: nil, clientAuth: configNoClientID, wantErrContains: errListAbsent},
		{name: "methods=absent/anon=absent/config=C2", methods: nil, anon: nil, clientAuth: configClientID, wantErrContains: errListAbsent},
		{name: "methods=absent/anon=absent/config=C3", methods: nil, anon: nil, clientAuth: configPrivateKey, wantErrContains: errListAbsent},
		// Except for an anonymous request: OpenID4VCI 1.0 Sections 6.1 and 12.3
		// let a server that declares anonymous access take a request without
		// client authentication and without client_id, and the RFC 8414
		// default names only how a confidential client authenticates.
		{name: "methods=absent/anon=true/config=C1", methods: nil, anon: boolPtr(true), clientAuth: configNoClientID, wantMethod: receiverTypes.None},
		{name: "methods=absent/anon=true/config=C2", methods: nil, anon: boolPtr(true), clientAuth: configClientID, wantMethod: receiverTypes.None},
		{name: "methods=absent/anon=true/config=C3", methods: nil, anon: boolPtr(true), clientAuth: configPrivateKey, wantErrContains: errListAbsent},
		{name: "methods=absent/anon=false/config=C1", methods: nil, anon: boolPtr(false), clientAuth: configNoClientID, wantErrContains: errListAbsent},
		{name: "methods=absent/anon=false/config=C2", methods: nil, anon: boolPtr(false), clientAuth: configClientID, wantErrContains: errListAbsent},
		{name: "methods=absent/anon=false/config=C3", methods: nil, anon: boolPtr(false), clientAuth: configPrivateKey, wantErrContains: errListAbsent},

		// none is advertised, so the anonymous parameter gets to do its one job.
		{name: "methods=contains_none/anon=absent/config=C1", methods: authMethodsPtr(receiverTypes.None, receiverTypes.PrivateKeyJwt), anon: nil, clientAuth: configNoClientID, wantErrContains: errClientIDAbsent},
		{name: "methods=contains_none/anon=absent/config=C2", methods: authMethodsPtr(receiverTypes.None, receiverTypes.PrivateKeyJwt), anon: nil, clientAuth: configClientID, wantMethod: receiverTypes.None, wantSendClientID: true},
		{name: "methods=contains_none/anon=absent/config=C3", methods: authMethodsPtr(receiverTypes.None, receiverTypes.PrivateKeyJwt), anon: nil, clientAuth: configPrivateKey, wantMethod: receiverTypes.PrivateKeyJwt, wantSendClientID: true},
		{name: "methods=contains_none/anon=true/config=C1", methods: authMethodsPtr(receiverTypes.None, receiverTypes.PrivateKeyJwt), anon: boolPtr(true), clientAuth: configNoClientID, wantMethod: receiverTypes.None},
		{name: "methods=contains_none/anon=true/config=C2", methods: authMethodsPtr(receiverTypes.None, receiverTypes.PrivateKeyJwt), anon: boolPtr(true), clientAuth: configClientID, wantMethod: receiverTypes.None},
		// The cell that tells the two readings apart: none must not downgrade.
		{name: "methods=contains_none/anon=true/config=C3", methods: authMethodsPtr(receiverTypes.None, receiverTypes.PrivateKeyJwt), anon: boolPtr(true), clientAuth: configPrivateKey, wantMethod: receiverTypes.PrivateKeyJwt, wantSendClientID: true},
		{name: "methods=contains_none/anon=false/config=C1", methods: authMethodsPtr(receiverTypes.None, receiverTypes.PrivateKeyJwt), anon: boolPtr(false), clientAuth: configNoClientID, wantErrContains: errClientIDRefused},
		// Refusing anonymous access does not close the endpoint to a named client.
		{name: "methods=contains_none/anon=false/config=C2", methods: authMethodsPtr(receiverTypes.None, receiverTypes.PrivateKeyJwt), anon: boolPtr(false), clientAuth: configClientID, wantMethod: receiverTypes.None, wantSendClientID: true},
		{name: "methods=contains_none/anon=false/config=C3", methods: authMethodsPtr(receiverTypes.None, receiverTypes.PrivateKeyJwt), anon: boolPtr(false), clientAuth: configPrivateKey, wantMethod: receiverTypes.PrivateKeyJwt, wantSendClientID: true},

		// none not advertised: no anonymous-access claim can override that.
		{name: "methods=lacks_none/anon=absent/config=C1", methods: authMethodsPtr(receiverTypes.PrivateKeyJwt), anon: nil, clientAuth: configNoClientID, wantErrContains: errNotAdvertised},
		{name: "methods=lacks_none/anon=absent/config=C2", methods: authMethodsPtr(receiverTypes.PrivateKeyJwt), anon: nil, clientAuth: configClientID, wantErrContains: errNotAdvertised},
		{name: "methods=lacks_none/anon=absent/config=C3", methods: authMethodsPtr(receiverTypes.PrivateKeyJwt), anon: nil, clientAuth: configPrivateKey, wantMethod: receiverTypes.PrivateKeyJwt, wantSendClientID: true},
		{name: "methods=lacks_none/anon=true/config=C1", methods: authMethodsPtr(receiverTypes.PrivateKeyJwt), anon: boolPtr(true), clientAuth: configNoClientID, wantErrContains: errNotAdvertised},
		{name: "methods=lacks_none/anon=true/config=C2", methods: authMethodsPtr(receiverTypes.PrivateKeyJwt), anon: boolPtr(true), clientAuth: configClientID, wantErrContains: errNotAdvertised},
		{name: "methods=lacks_none/anon=true/config=C3", methods: authMethodsPtr(receiverTypes.PrivateKeyJwt), anon: boolPtr(true), clientAuth: configPrivateKey, wantMethod: receiverTypes.PrivateKeyJwt, wantSendClientID: true},
		{name: "methods=lacks_none/anon=false/config=C1", methods: authMethodsPtr(receiverTypes.PrivateKeyJwt), anon: boolPtr(false), clientAuth: configNoClientID, wantErrContains: errNotAdvertised},
		{name: "methods=lacks_none/anon=false/config=C2", methods: authMethodsPtr(receiverTypes.PrivateKeyJwt), anon: boolPtr(false), clientAuth: configClientID, wantErrContains: errNotAdvertised},
		{name: "methods=lacks_none/anon=false/config=C3", methods: authMethodsPtr(receiverTypes.PrivateKeyJwt), anon: boolPtr(false), clientAuth: configPrivateKey, wantMethod: receiverTypes.PrivateKeyJwt, wantSendClientID: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMetadata := &receiverTypes.AuthorizationServerMetadata{
				TokenEndpointAuthMethodsSupported:          tt.methods,
				TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.ES256},
				PreAuthorizedGrantAnonymousAccessSupported: tt.anon,
			}

			auth, err := resolveClientAuthMethod(tt.clientAuth, authMetadata)
			if tt.wantErrContains != "" {
				require.ErrorIs(t, err, errNoUsableClientAuthMethod)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantMethod, auth.Method)
			assert.Equal(t, tt.wantSendClientID, auth.SendClientID)
		})
	}
}

// TestResolveClientAuthMethod_UnusableCombinations covers refusals that stop the
// negotiation early.
func TestResolveClientAuthMethod_UnusableCombinations(t *testing.T) {
	key, _ := newClientAuthKeyEntry(t, "client-key-1")

	// Returns before anon or the wallet config is read, so one call covers the
	// grid the rest of this file walks; anon=true is the tempting cell.
	t.Run("empty method list advertises nothing", func(t *testing.T) {
		_, err := resolveClientAuthMethod(ClientAuthConfig{}, &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(),
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
		})
		require.ErrorIs(t, err, errNoUsableClientAuthMethod)
		assert.Contains(t, err.Error(), "token_endpoint_auth_methods_supported is an empty array")
	})

	t.Run("list of methods this wallet does not implement", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.ClientSecretBasic),
			TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.ES256},
		}
		for _, clientAuth := range []ClientAuthConfig{
			{},
			{Method: receiverTypes.None, ClientID: "wallet-id"},
			{Method: receiverTypes.PrivateKeyJwt, ClientID: "wallet-id", Key: key},
		} {
			_, err := resolveClientAuthMethod(clientAuth, authMetadata)
			require.ErrorIs(t, err, errNoUsableClientAuthMethod)
			assert.Contains(t, err.Error(), "token_endpoint_auth_methods_supported is [client_secret_basic]")
		}
	})

	t.Run("private_key_jwt without complete credentials", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
			TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.ES256},
		}
		for _, clientAuth := range []ClientAuthConfig{
			{Method: receiverTypes.PrivateKeyJwt, Key: key},
			{Method: receiverTypes.PrivateKeyJwt, ClientID: "wallet-id"},
		} {
			_, err := resolveClientAuthMethod(clientAuth, authMetadata)
			require.ErrorIs(t, err, errNoUsableClientAuthMethod)
			assert.Contains(t, err.Error(), "requires both a client_id and a client authentication key")
		}
	})

	// Reported before the metadata is read, so an absent list must not mask it.
	t.Run("method this wallet does not implement", func(t *testing.T) {
		for _, methods := range []*[]receiverTypes.TokenEndpointAuthMethod{
			nil,
			authMethodsPtr(receiverTypes.None),
			authMethodsPtr(receiverTypes.ClientSecretBasic),
		} {
			_, err := resolveClientAuthMethod(
				ClientAuthConfig{Method: receiverTypes.ClientSecretBasic, ClientID: "wallet-id"},
				&receiverTypes.AuthorizationServerMetadata{
					TokenEndpointAuthMethodsSupported:          methods,
					PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
				})
			require.ErrorIs(t, err, errNoUsableClientAuthMethod)
			assert.Contains(t, err.Error(), `token_endpoint_auth_method "client_secret_basic" is configured`)
		}
	})

	// A programming error, not a failed negotiation.
	t.Run("missing authorization server metadata", func(t *testing.T) {
		_, err := resolveClientAuthMethod(ClientAuthConfig{}, nil)
		require.Error(t, err)
		assert.NotErrorIs(t, err, errNoUsableClientAuthMethod)
		assert.Contains(t, err.Error(), "authorization server metadata is required")
	})
}

func TestClientAuthMethodUsable_HonoursConfiguredSigningAlg(t *testing.T) {
	key, _ := newClientAuthKeyEntry(t, "client-key-1")
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
		TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.ES384},
	}

	// The authorization server advertises ES384 only, so the ES256 default
	// finds no usable method.
	assert.Error(t, clientAuthMethodUsable(
		receiverTypes.PrivateKeyJwt,
		ClientAuthConfig{ClientID: "wallet-id", Key: key},
		authMetadata,
	))

	assert.NoError(t, clientAuthMethodUsable(
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

// generateDPoPProof builds one DPoP proof through jwtproof.DPoP; a nil or
// empty nonce omits the claim. The wallet's own requests use
// dpopProofFactory; this helper lets the tests pin the proof shape.
func (w *Wallet) generateDPoPProof(key IKeyEntry, method, targetURL, accessToken string, nonce *string) (string, error) {
	if key == nil {
		return "", fmt.Errorf("dpop key is required")
	}
	options := jwtproof.DPoPOptions{Method: method, URL: targetURL, AccessToken: accessToken}
	if nonce != nil {
		options.Nonce = *nonce
	}
	proof, err := jwtproof.DPoP(context.Background(), key, options)
	if err != nil {
		return "", fmt.Errorf("failed to serialize dpop proof: %w", err)
	}
	return proof, nil
}

// generateClientAssertion is clientAssertion without a context.
func (w *Wallet) generateClientAssertion(key IKeyEntry, clientID, audience string, alg jose.SignatureAlgorithm) (string, error) {
	return clientAssertion(context.Background(), key, clientID, audience, alg)
}
