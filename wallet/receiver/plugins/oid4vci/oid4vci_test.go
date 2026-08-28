package oid4vci

import (
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// Existing tests

func TestOid4vciReceiver_FetchIssuerMetadata(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	// Create mock OID4VCI issuer server
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL())
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetDebugMode(dbg_mode)
		defer env.SetHTTPAllowed(http_allowed)
		env.SetDebugMode(false)
		env.SetHTTPAllowed(false)

		_, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
		if err == nil {
			t.Fatal("FetchIssuerMetadata should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		metadata, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if metadata == nil {
			t.Fatal("Expected metadata, got nil")
		}

		// Verify metadata contains expected fields from mock server
		if metadata.CredentialIssuer != endpoint.String() {
			t.Errorf("Expected CredentialIssuer %s, got %s", endpoint.String(), metadata.CredentialIssuer)
		}
	})

	t.Run("Unsupported receiving type", func(t *testing.T) {
		_, err := receiver.FetchIssuerMetadata(common.URIField{}, types.SupportedReceivingTypes(999))
		if err == nil {
			t.Fatal("Expected error for unsupported receiving type")
		}
	})

	t.Run("Server error", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/.well-known/openid-credential-issuer", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.FetchIssuerMetadata(common.URIField(*errorURL), types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Empty response body", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		emptyServer := mockserver.NewMockServer()
		defer emptyServer.Close()

		emptyServer.SetTextResponse("/.well-known/openid-credential-issuer", http.StatusOK, "")

		emptyURL, _ := url.Parse(emptyServer.URL())
		_, err := receiver.FetchIssuerMetadata(common.URIField(*emptyURL), types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error for empty response body")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/.well-known/openid-credential-issuer", http.StatusOK, "{not-a-valid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.FetchIssuerMetadata(common.URIField(*invalidJSONURL), types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})

	t.Run("Trailing slash in endpoint", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		metadata := types.CredentialIssuerMetadata{
			CredentialIssuer: "http://example.com",
		}
		// Use a raw handler to bypass ServeMux's automatic path cleaning and redirects
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check RequestURI for double slashes before any normalization
			if strings.Contains(r.RequestURI, "//") {
				http.Error(w, "Double slash detected: "+r.RequestURI, http.StatusBadRequest)
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, metadata)
		}))
		defer server.Close()

		// Create endpoint WITH trailing slash
		endpointURL, _ := url.Parse(server.URL + "/")
		endpoint := common.URIField(*endpointURL)

		res, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
		if err != nil {
			t.Fatalf("Expected no error with trailing slash, got %v. If this is a 400 error, it means a double slash was detected.", err)
		}
		if res.CredentialIssuer != metadata.CredentialIssuer {
			t.Errorf("Expected metadata, got %v", res)
		}
	})

	t.Run("Trailing slash in endpoint with path component", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		metadata := types.CredentialIssuerMetadata{
			CredentialIssuer: "http://example.com/issuer",
		}
		// Use a raw handler to bypass ServeMux's automatic path cleaning and redirects
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.RequestURI, "//") {
				http.Error(w, "Double slash detected: "+r.RequestURI, http.StatusBadRequest)
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, metadata)
		}))
		defer server.Close()

		// Create endpoint WITH path and trailing slash
		endpointURL, _ := url.Parse(server.URL + "/issuer/")
		endpoint := common.URIField(*endpointURL)

		res, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
		if err != nil {
			t.Fatalf("Expected no error with trailing slash and path, got %v. If this is a 400 error, it means a double slash was detected.", err)
		}
		if res.CredentialIssuer != metadata.CredentialIssuer {
			t.Errorf("Expected metadata, got %v", res)
		}
	})
}

func TestOid4vciReceiver_FetchAuthorizationServerMetadata(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	// Create mock OID4VCI issuer server (which also serves auth server metadata)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL())
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetDebugMode(dbg_mode)
		defer env.SetHTTPAllowed(http_allowed)
		env.SetDebugMode(false)
		env.SetHTTPAllowed(false)

		_, err := receiver.FetchAuthorizationServerMetadata(endpoint, types.Oid4vci)
		if err == nil {
			t.Fatal("FetchAuthorizationServerMetadata should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		metadata, err := receiver.FetchAuthorizationServerMetadata(endpoint, types.Oid4vci)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if metadata == nil {
			t.Fatal("Expected metadata, got nil")
		}

		// Verify metadata contains expected fields from mock server
		if metadata.Issuer.String() != endpoint.String() {
			t.Errorf("Expected Issuer %s, got %s", endpoint.String(), metadata.Issuer.String())
		}
		if metadata.TokenEndpoint == nil {
			t.Error("Expected TokenEndpoint to be set")
		}
	})

	t.Run("Server error", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/.well-known/oauth-authorization-server", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.FetchAuthorizationServerMetadata(common.URIField(*errorURL), types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/.well-known/oauth-authorization-server", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.FetchAuthorizationServerMetadata(common.URIField(*invalidJSONURL), types.Oid4vci)
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})
}

func TestOid4vciReceiver_FetchAccessToken(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	// Create mock OID4VCI issuer server (which serves token endpoint)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL() + "/token")
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetDebugMode(dbg_mode)
		defer env.SetHTTPAllowed(http_allowed)
		env.SetDebugMode(false)
		env.SetHTTPAllowed(false)

		_, err := receiver.FetchAccessToken(types.Oid4vci, endpoint, "test-code", "")
		if err == nil {
			t.Fatal("FetchAccessToken should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		token, err := receiver.FetchAccessToken(types.Oid4vci, endpoint, "test-code", "")
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if token == nil {
			t.Fatal("Expected token, got nil")
		}

		// Verify token contains expected fields from mock server
		if token.Token != "mock-access-token" {
			t.Errorf("Expected Token 'mock-access-token', got %s", token.Token)
		}
		if token.TokenType != "Bearer" {
			t.Errorf("Expected TokenType 'Bearer', got %s", token.TokenType)
		}
	})
	t.Run("Request includes tx_code when provided", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request form: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
				handlerErrCh <- fmt.Errorf("expected grant_type to be urn:ietf:params:oauth:grant-type:pre-authorized_code, got %s", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("pre-authorized_code"); got != "test-code" {

				handlerErrCh <- fmt.Errorf("expected pre-authorized_code to be test-code, got %s", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("tx_code"); got != "123456" {
				handlerErrCh <- fmt.Errorf("expected tx_code to be 123456, got %s", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]string{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
			})
		})
		captureURL, _ := url.Parse(captureServer.URL() + "/token")
		token, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*captureURL), "test-code", "123456", nil)
		require.NoError(t, err)
		require.NotNil(t, token)
		require.NoError(t, <-handlerErrCh)
	})

	t.Run("DPoP header is set when proof is provided", func(t *testing.T) {

		httpAllowed := env.IsHTTPAllowed()
		defer env.SetHTTPAllowed(httpAllowed)
		env.SetHTTPAllowed(true)
		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()
		var capturedDPoPValues []string
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			capturedDPoPValues = r.Header.Values("DPoP")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
		})
		captureURL, err := url.Parse(captureServer.URL() + "/token")
		require.NoError(t, err)
		proof := "header.payload.signature"
		token, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*captureURL), "code", "", types.WithDPoPProof(proof))
		require.NoError(t, err)
		require.NotNil(t, token)
		require.Len(t, capturedDPoPValues, 1)
		assert.Equal(t, proof, capturedDPoPValues[0])
	})

	t.Run("DPoP header is absent when proof is nil", func(t *testing.T) {
		httpAllowed := env.IsHTTPAllowed()
		defer env.SetHTTPAllowed(httpAllowed)
		env.SetHTTPAllowed(true)
		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()
		var capturedDPoPValues []string
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			capturedDPoPValues = r.Header.Values("DPoP")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
		})
		captureURL, err := url.Parse(captureServer.URL() + "/token")
		require.NoError(t, err)
		token, err := receiver.FetchAccessToken(
			types.Oid4vci,
			common.URIField(*captureURL),
			"code",
			"",
		)
		require.NoError(t, err)
		require.NotNil(t, token)
		assert.Len(t, capturedDPoPValues, 0)
	})

	t.Run("DPoP header is absent when proof is empty string", func(t *testing.T) {
		httpAllowed := env.IsHTTPAllowed()
		defer env.SetHTTPAllowed(httpAllowed)
		env.SetHTTPAllowed(true)
		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()
		var capturedDPoPValues []string
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			capturedDPoPValues = r.Header.Values("DPoP")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
		})
		captureURL, err := url.Parse(captureServer.URL() + "/token")
		require.NoError(t, err)
		empty := ""
		token, err := receiver.FetchAccessToken(
			types.Oid4vci,
			common.URIField(*captureURL),
			"code",
			"",
			types.WithDPoPProof(empty),
		)
		require.NoError(t, err)
		require.NotNil(t, token)
		assert.Len(t, capturedDPoPValues, 0)
	})

	t.Run("Server error", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/token", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL() + "/token")
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*errorURL), "test-code", "")
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("use_dpop_nonce error includes nonce hint", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		nonceServer := mockserver.NewMockServer()
		defer nonceServer.Close()

		nonceServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("DPoP-Nonce", "token-dpop-nonce")
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
				"error": "use_dpop_nonce",
			})
		})

		nonceURL, _ := url.Parse(nonceServer.URL() + "/token")
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*nonceURL), "test-code", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, types.ErrTokenRequestFailed)
		assert.Contains(t, err.Error(), "use_dpop_nonce")
		assert.Contains(t, err.Error(), "token-dpop-nonce")
	})

	t.Run("bad request error field is surfaced", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
				"error": "invalid_dpop_proof",
			})
		})

		errorURL, _ := url.Parse(errorServer.URL() + "/token")
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*errorURL), "test-code", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, types.ErrTokenRequestFailed)
		assert.Contains(t, err.Error(), "invalid_dpop_proof")
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/token", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL() + "/token")
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*invalidJSONURL), "test-code", "")
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})
}

func TestOid4vciReceiver_FetchAccessToken_ClientAssertion(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	t.Run("client_assertion form fields are sent when provided", func(t *testing.T) {
		httpAllowed := env.IsHTTPAllowed()
		defer env.SetHTTPAllowed(httpAllowed)
		env.SetHTTPAllowed(true)

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse form: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("client_id"); got != "wallet-id" {
				handlerErrCh <- fmt.Errorf("expected client_id wallet-id, got %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("client_assertion_type"); got != types.ClientAssertionTypeJWTBearer {
				handlerErrCh <- fmt.Errorf("expected client_assertion_type jwt-bearer, got %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("client_assertion"); got != "assertion.jwt.value" {
				handlerErrCh <- fmt.Errorf("expected client_assertion assertion.jwt.value, got %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{
				"access_token": "tok",
				"token_type":   "Bearer",
			})
		})

		captureURL, err := url.Parse(captureServer.URL() + "/token")
		require.NoError(t, err)
		token, err := receiver.FetchAccessToken(
			types.Oid4vci,
			common.URIField(*captureURL),
			"code",
			"",
			types.WithClientAssertion("wallet-id", "assertion.jwt.value"),
		)
		require.NoError(t, err)
		require.NotNil(t, token)
		require.NoError(t, <-handlerErrCh)
	})

	t.Run("client_assertion form fields are absent when not provided", func(t *testing.T) {
		httpAllowed := env.IsHTTPAllowed()
		defer env.SetHTTPAllowed(httpAllowed)
		env.SetHTTPAllowed(true)

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse form: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("client_assertion"); got != "" {
				handlerErrCh <- fmt.Errorf("client_assertion must be absent, got %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Form.Get("client_id"); got != "" {
				handlerErrCh <- fmt.Errorf("client_id must be absent, got %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{
				"access_token": "tok",
				"token_type":   "Bearer",
			})
		})

		captureURL, err := url.Parse(captureServer.URL() + "/token")
		require.NoError(t, err)
		token, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*captureURL), "code", "")
		require.NoError(t, err)
		require.NotNil(t, token)
		require.NoError(t, <-handlerErrCh)
	})
}

func TestOid4vciReceiver_FetchAccessToken_RequiresClientIDWithAssertion(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{
			"access_token": "tok",
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	tokenURL, err := url.Parse(server.URL + "/token")
	require.NoError(t, err)

	token, err := receiver.FetchAccessToken(
		types.Oid4vci,
		common.URIField(*tokenURL),
		"code",
		"",
		types.WithClientAssertion("  ", "assertion.jwt.value"),
	)
	require.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "client_id is required when a client assertion is sent")
	assert.Zero(t, requests, "the request must not be sent at all")
}

func TestOid4vciReceiver_FetchAccessToken_DoesNotFollowRedirects(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	// A 307 keeps the method and body, so following the redirect would replay
	// the client_assertion against this second origin.
	var relayedRequests int
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		relayedRequests++
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{
			"access_token": "leaked",
			"token_type":   "Bearer",
		})
	}))
	defer relay.Close()

	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, relay.URL+"/token", http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	tokenURL, err := url.Parse(redirecting.URL + "/token")
	require.NoError(t, err)

	token, err := receiver.FetchAccessToken(
		types.Oid4vci,
		common.URIField(*tokenURL),
		"code",
		"",
		types.WithClientAssertion("wallet-id", "assertion.jwt.value"),
	)
	require.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "redirects are not followed for token requests")
	assert.Zero(t, relayedRequests, "the client_assertion must not reach the redirect target")
}

func TestOid4vciReceiver_ReceiveCredential(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	accessToken := types.CredentialIssuanceAccessToken{Token: "test_token", TokenType: "bearer"}

	// Create mock OID4VCI issuer server (which serves credential endpoint)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL() + "/credential")
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		dbg_mode := env.IsDebugMode()
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetDebugMode(dbg_mode)
		defer env.SetHTTPAllowed(http_allowed)
		env.SetDebugMode(false)
		env.SetHTTPAllowed(false)

		_, err := receiver.ReceiveCredential(types.Oid4vci, endpoint, "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("ReceiveCredential should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		credential, err := receiver.ReceiveCredential(types.Oid4vci, endpoint, "test-config", nil, accessToken, nil, nil)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if credential == nil || *credential == "" {
			t.Fatal("Expected credential, got empty string")
		}

		// The mock server returns a default JWT credential
		if !strings.HasPrefix(*credential, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9") {
			t.Errorf("Expected JWT credential to start with header, got %s", (*credential)[:50])
		}
	})

	t.Run("Request uses credential_configuration_id and proofs", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		var capturedBody map[string]interface{}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)
		proof := "eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6InRlc3QifQ.signature"

		credential, err := receiver.ReceiveCredential(types.Oid4vci, captureEndpoint, "test-config", nil, accessToken, nil, &proof)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NotEmpty(t, *credential)
		require.NoError(t, <-handlerErrCh)

		_, exists := capturedBody["format"]
		assert.False(t, exists, "format should not be present in credential request body")
		_, exists = capturedBody["proof"]
		assert.False(t, exists, "proof should not be present in credential request body")

		credentialConfigurationID, ok := capturedBody["credential_configuration_id"].(string)
		require.True(t, ok, "credential_configuration_id must be present as string")
		assert.Equal(t, "test-config", credentialConfigurationID)

		proofs, ok := capturedBody["proofs"].(map[string]interface{})
		require.True(t, ok, "proofs must be present as object")
		jwtProofs, ok := proofs["jwt"].([]interface{})
		require.True(t, ok, "proofs.jwt must be present as array")
		require.Len(t, jwtProofs, 1, "proofs.jwt must contain one JWT value")
		assert.Equal(t, proof, jwtProofs[0])
	})

	t.Run("Request omits proof fields when jwt proof is not provided", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		var capturedBody map[string]interface{}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		credential, err := receiver.ReceiveCredential(types.Oid4vci, captureEndpoint, "test-config", nil, accessToken, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NotEmpty(t, *credential)
		require.NoError(t, <-handlerErrCh)

		credentialConfigurationID, ok := capturedBody["credential_configuration_id"].(string)
		require.True(t, ok, "credential_configuration_id must be present as string")
		assert.Equal(t, "test-config", credentialConfigurationID)

		_, exists := capturedBody["proof"]
		assert.False(t, exists, "proof should not be present in credential request body")
		_, exists = capturedBody["proofs"]
		assert.False(t, exists, "proofs should not be present when proof is not provided")
		_, exists = capturedBody["format"]
		assert.False(t, exists, "format should not be present in credential request body")
	})

	t.Run("DPoP access token sends DPoP authorization and proof headers", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		dpopProof := "dpop.proof.jwt"
		dpopAccessToken := types.CredentialIssuanceAccessToken{
			Token:     "dpop-access-token",
			TokenType: "DPoP",
		}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "DPoP dpop-access-token" {
				handlerErrCh <- fmt.Errorf("Authorization header = %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Header.Get("DPoP"); got != dpopProof {
				handlerErrCh <- fmt.Errorf("DPoP header = %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		credential, err := receiver.ReceiveCredential(
			types.Oid4vci,
			captureEndpoint,
			"test-config",
			nil,
			dpopAccessToken,
			nil,
			nil,
			&types.CredentialRequestOptions{DPoPProofJWT: &dpopProof},
		)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NoError(t, <-handlerErrCh)
	})

	t.Run("use_dpop_nonce error is returned as sentinel error", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		dpopProof := "dpop.proof.jwt"
		dpopAccessToken := types.CredentialIssuanceAccessToken{
			Token:     "dpop-access-token",
			TokenType: "DPoP",
		}
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
				"error": "use_dpop_nonce",
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		_, err := receiver.ReceiveCredential(
			types.Oid4vci,
			captureEndpoint,
			"test-config",
			nil,
			dpopAccessToken,
			nil,
			nil,
			&types.CredentialRequestOptions{DPoPProofJWT: &dpopProof},
		)
		require.Error(t, err)
		assert.ErrorIs(t, err, types.ErrUseDPoPNonce)
	})

	t.Run("DPoP access token skips nil request options", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		dpopProof := "dpop.proof.jwt"
		dpopAccessToken := types.CredentialIssuanceAccessToken{
			Token:     "dpop-access-token",
			TokenType: "DPoP",
		}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("DPoP"); got != dpopProof {
				handlerErrCh <- fmt.Errorf("DPoP header = %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		credential, err := receiver.ReceiveCredential(
			types.Oid4vci,
			captureEndpoint,
			"test-config",
			nil,
			dpopAccessToken,
			nil,
			nil,
			nil,
			&types.CredentialRequestOptions{DPoPProofJWT: &dpopProof},
		)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NoError(t, <-handlerErrCh)
	})

	t.Run("Request uses credential_identifier when provided", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		var capturedBody map[string]interface{}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)
		credentialIdentifier := "cred-id-1"

		credential, err := receiver.ReceiveCredential(types.Oid4vci, captureEndpoint, "test-config", &credentialIdentifier, accessToken, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NotEmpty(t, *credential)
		require.NoError(t, <-handlerErrCh)

		identifier, ok := capturedBody["credential_identifier"].(string)
		require.True(t, ok, "credential_identifier must be present as string")
		assert.Equal(t, credentialIdentifier, identifier)

		_, exists := capturedBody["credential_configuration_id"]
		assert.False(t, exists, "credential_configuration_id should not be present when credential_identifier is used")
	})

	t.Run("Server error", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/credential", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*errorURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/credential", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*invalidJSONURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})

	t.Run("No credential in response", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		noCredServer := mockserver.NewMockServer()
		defer noCredServer.Close()

		// Return valid JSON but without credential field
		noCredServer.SetJSONResponse("/credential", http.StatusOK, map[string]string{"status": "success"})

		noCredURL, _ := url.Parse(noCredServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*noCredURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error when no credential is present in the response")
		}
	})

	t.Run("Multiple credentials in response", func(t *testing.T) {
		http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
		defer env.SetHTTPAllowed(http_allowed)
		env.SetHTTPAllowed(true)

		multiCredServer := mockserver.NewMockServer()
		defer multiCredServer.Close()

		multiCredServer.SetJSONResponse("/credential", http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{
				{"credential": "cred-1"},
				{"credential": "cred-2"},
			},
		})

		multiCredURL, _ := url.Parse(multiCredServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*multiCredURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error when multiple credentials are present in the response")
		}
	})
}

func TestOid4vciReceiver_MetadataDiscovery_UrlPatterns(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	tests := []struct {
		name         string
		identifier   string
		expectedPath string
		discovery    func(common.URIField) error
	}{
		{
			name:         "Auth Server (Base URL)",
			identifier:   "",
			expectedPath: "/.well-known/oauth-authorization-server",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchAuthorizationServerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Auth Server (Root Path)",
			identifier:   "/",
			expectedPath: "/.well-known/oauth-authorization-server",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchAuthorizationServerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Auth Server (With Path)",
			identifier:   "/tenant1",
			expectedPath: "/.well-known/oauth-authorization-server/tenant1",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchAuthorizationServerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Auth Server (With Trailing Slash)",
			identifier:   "/tenant1/",
			expectedPath: "/.well-known/oauth-authorization-server/tenant1/",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchAuthorizationServerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Credential Issuer (Base URL)",
			identifier:   "",
			expectedPath: "/.well-known/openid-credential-issuer",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchIssuerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Credential Issuer (Root Path)",
			identifier:   "/",
			expectedPath: "/.well-known/openid-credential-issuer",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchIssuerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Credential Issuer (With Path)",
			identifier:   "/tenant2",
			expectedPath: "/.well-known/openid-credential-issuer/tenant2",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchIssuerMetadata(u, types.Oid4vci)
				return err
			},
		},
		{
			name:         "Credential Issuer (With Trailing Slash)",
			identifier:   "/tenant2/",
			expectedPath: "/.well-known/openid-credential-issuer/tenant2/",
			discovery: func(u common.URIField) error {
				_, err := receiver.FetchIssuerMetadata(u, types.Oid4vci)
				return err
			},
		},
	}

	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tt.expectedPath {
					w.WriteHeader(http.StatusOK)
					// Return minimal valid JSON for both types
					fmt.Fprint(w, `{"issuer": "https://example.com", "credential_issuer": "https://example.com"}`)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			serverURL, _ := url.Parse(server.URL)
			identifierURL := *serverURL
			// Empty identifier keeps the parsed base URL's empty path (e.g. "https://host"),
			// while "/" sets the root path so the originalPath == "/" branch is exercised.
			if tt.identifier != "" {
				identifierURL.Path = tt.identifier
			}
			endpoint := common.URIField(identifierURL)

			assert.NoError(t, tt.discovery(endpoint), "Pattern %s failed: expected success at %s", tt.name, tt.expectedPath)
		})
	}
}
