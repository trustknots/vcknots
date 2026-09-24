package wallet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestController_requestCredential_DPoPAccessTokenRetriesWithNonceFromHeader(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const (
		accessTokenValue = "dpop-access-token"
		dpopNonce        = "issuer-dpop-nonce"
	)

	obs := newServerObservations(t, "nonce", "credential")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			obs.called("nonce")
			if r.Method != http.MethodPost {
				http.Error(w, "invalid method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("DPoP-Nonce", dpopNonce)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"c_nonce":"credential-proof-nonce"}`))
		case "/credential":
			credentialRequests := obs.called("credential")
			if got := r.Header.Get("Authorization"); got != "DPoP "+accessTokenValue {
				http.Error(w, "invalid authorization header: "+got, http.StatusBadRequest)
				return
			}
			dpopProof := r.Header.Get("DPoP")
			if dpopProof == "" {
				http.Error(w, "missing DPoP header", http.StatusBadRequest)
				return
			}

			parts := strings.Split(dpopProof, ".")
			if len(parts) != 3 {
				http.Error(w, "invalid DPoP proof", http.StatusBadRequest)
				return
			}
			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				http.Error(w, "invalid DPoP payload", http.StatusBadRequest)
				return
			}
			var payload map[string]interface{}
			if err := json.Unmarshal(payloadBytes, &payload); err != nil {
				http.Error(w, "invalid DPoP payload json", http.StatusBadRequest)
				return
			}

			accessTokenHash := sha256.Sum256([]byte(accessTokenValue))
			expectedAth := base64.RawURLEncoding.EncodeToString(accessTokenHash[:])
			if payload["ath"] != expectedAth {
				http.Error(w, "invalid ath", http.StatusBadRequest)
				return
			}

			if credentialRequests == 1 {
				if _, exists := payload["nonce"]; exists {
					http.Error(w, "first DPoP proof should not include nonce", http.StatusBadRequest)
					return
				}
				w.Header().Set("DPoP-Nonce", dpopNonce)
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
					"error": "use_dpop_nonce",
				})
				return
			}

			if payload["nonce"] != dpopNonce {
				http.Error(w, "retry DPoP proof missing nonce", http.StatusBadRequest)
				return
			}

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)
	nonceEndpoint, err := common.ParseURIField(server.URL + "/nonce")
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
		NonceEndpoint:      nonceEndpoint,
	}
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, 2, obs.callCount("credential"))
}

func TestController_requestCredential_DPoPAccessTokenUsesConfiguredDPoPKey(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	holderKey := newMockKeyEntry()
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const accessTokenValue = "dpop-access-token"

	obs := newServerObservations(t, "credential")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/credential" {
			http.NotFound(w, r)
			return
		}
		obs.called("credential")
		if got := r.Header.Get("Authorization"); got != "DPoP "+accessTokenValue {
			http.Error(w, "invalid authorization header: "+got, http.StatusBadRequest)
			return
		}
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		headerJWK, found := observedHeaderField(obs, dpopProof, "jwk")
		if !found {
			http.Error(w, "DPoP proof has no jwk header", http.StatusBadRequest)
			return
		}
		jwk, ok := headerJWK.(map[string]any)
		if !assert.True(obs, ok) {
			http.Error(w, "DPoP proof jwk header is not an object", http.StatusBadRequest)
			return
		}
		if got := jwk["kid"]; got != dpopKey.ID() {
			http.Error(w, fmt.Sprintf("DPoP proof kid = %v", got), http.StatusBadRequest)
			return
		}

		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{{
				"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
			}},
		})
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  holderKey,
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
	}

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.NoError(t, err)
	require.NotNil(t, credential)
}

func TestController_requestCredential_DPoPNonceChallengeDoesNotRefetchCredentialNonce(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const (
		accessTokenValue       = "dpop-access-token"
		credentialHeaderNonce  = "credential-dpop-nonce"
		nonceEndpointDPoPNonce = "nonce-endpoint-dpop-nonce"
	)

	obs := newServerObservations(t, "nonce", "credential")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			obs.called("nonce")
			if !assert.Zero(obs, obs.callCount("credential"), "c_nonce must be fetched before requesting the credential") {
				http.Error(w, "c_nonce must be fetched before requesting the credential", http.StatusBadRequest)
				return
			}
			if r.Method != http.MethodPost {
				http.Error(w, "invalid method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("DPoP-Nonce", nonceEndpointDPoPNonce)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"c_nonce":"credential-proof-nonce"}`))
			return
		case "/credential":
		default:
			http.NotFound(w, r)
			return
		}

		credentialRequests := obs.called("credential")
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(dpopProof, ".")[1])
		if err != nil {
			http.Error(w, "invalid DPoP payload", http.StatusBadRequest)
			return
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			http.Error(w, "invalid DPoP payload json", http.StatusBadRequest)
			return
		}

		if credentialRequests == 1 {
			if _, exists := payload["nonce"]; exists {
				http.Error(w, "first DPoP proof should not include nonce", http.StatusBadRequest)
				return
			}
			w.Header().Set("DPoP-Nonce", credentialHeaderNonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if payload["nonce"] != credentialHeaderNonce {
			http.Error(w, "retry DPoP proof missing nonce", http.StatusBadRequest)
			return
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{{
				"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
			}},
		})
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
	}
	nonceEndpoint, err := common.ParseURIField(server.URL + "/nonce")
	require.NoError(t, err)
	issuerMetadata.NonceEndpoint = nonceEndpoint

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, 2, obs.callCount("credential"))
	assert.Equal(t, 1, obs.callCount("nonce"))
}

func TestController_requestCredential_DPoPNonceError_StopsAfterSecondChallenge(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const accessTokenValue = "dpop-access-token"

	obs := newServerObservations(t, "credential")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/credential" {
			http.NotFound(w, r)
			return
		}
		obs.called("credential")
		if got := r.Header.Get("Authorization"); got != "DPoP "+accessTokenValue {
			http.Error(w, "invalid authorization header: "+got, http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("DPoP"); got == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		w.Header().Set("DPoP-Nonce", "credential-endpoint-nonce")
		mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
			"error": "use_dpop_nonce",
		})
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
	}
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.Error(t, err)
	require.Nil(t, credential)
	assert.ErrorIs(t, err, receiverTypes.ErrUseDPoPNonce)
	assert.Equal(t, 2, obs.callCount("credential"))
}
