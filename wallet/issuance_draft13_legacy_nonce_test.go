package wallet

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/env"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

const testMaxNonceResponseBodyBytes int64 = 4 << 10

func TestController_fetchCredentialNonce_FallbackToAccessTokenWhenEndpointMissing(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	cnonce := "token-c-nonce"
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{CNonce: &cnonce}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, cnonce, *nonce)
}

func TestController_fetchCredentialNonce_ReturnsNilWhenNoNonceSource(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, &receiverTypes.CredentialIssuerMetadata{}, &receiverTypes.CredentialIssuanceAccessToken{})
	require.NoError(t, err)
	require.Nil(t, nonce)
}

func TestController_fetchCredentialNonce_FallbackToAccessTokenWhenEndpointFails(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	nonceEndpoint, err := common.ParseURIField("http://127.0.0.1:1/nonce")
	require.NoError(t, err)

	cnonce := "token-c-nonce"
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{CNonce: &cnonce}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, cnonce, *nonce)
}

func TestController_fetchCredentialNonce_RejectsNonHTTPSNonceEndpoint(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(false)
	controller := createTestControllerWithDefaults(t)

	nonceEndpoint, err := common.ParseURIField("http://example.com/nonce")
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "unsupported URL scheme")
}

func TestController_fetchCredentialNonce_UsesNonceEndpointWhenFallbackMissing(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	nonceValue := "nonce-from-endpoint"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"` + nonceValue + `"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, nonceValue, *nonce)
}

func TestController_fetchCredentialNonce_ReturnsErrorWhenEndpointFailsWithoutFallback(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary failure", http.StatusInternalServerError)
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "nonce endpoint returned status")
}

func TestController_fetchCredentialNonce_FallbackToAccessTokenWhenResponseTooLarge(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	largeNonce := strings.Repeat("a", int(testMaxNonceResponseBodyBytes))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"` + largeNonce + `"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	fallback := "token-c-nonce"
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{CNonce: &fallback}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, fallback, *nonce)
}

func TestController_fetchCredentialNonce_ReturnsErrorWhenResponseTooLargeWithoutFallback(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	largeNonce := strings.Repeat("a", int(testMaxNonceResponseBodyBytes))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"` + largeNonce + `"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "nonce endpoint response exceeds")
}
