package oid4vci

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestOid4vciReceiver_FetchAccessToken(t *testing.T) {

	// Create mock OID4VCI issuer server (which serves token endpoint)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL() + "/token")
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = false

		_, err := receiver.FetchAccessToken(types.Oid4vci, endpoint, "test-code", "")
		if err == nil {
			t.Fatal("FetchAccessToken should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

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

func TestOid4vciReceiver_FetchAccessToken_WithTransactionCode(t *testing.T) {
	form := fetchAccessTokenRequestForm(t, types.TokenRequest{
		PreAuthorizedCode: "pre-authorized-code",
		TxCode:            "123456",
	})

	require.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", form.Get("grant_type"))
	require.Equal(t, "pre-authorized-code", form.Get("pre-authorized_code"))
	require.Equal(t, "123456", form.Get("tx_code"))
}

func TestOid4vciReceiver_FetchAccessToken_WithoutTransactionCode(t *testing.T) {
	form := fetchAccessTokenRequestForm(t, types.TokenRequest{
		PreAuthorizedCode: "pre-authorized-code",
	})

	require.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", form.Get("grant_type"))
	require.Equal(t, "pre-authorized-code", form.Get("pre-authorized_code"))
	_, present := form["tx_code"]
	require.False(t, present)
}

func fetchAccessTokenRequestForm(t *testing.T, request types.TokenRequest) url.Values {
	t.Helper()

	forms := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		forms <- r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-token","token_type":"Bearer"}`))
	}))
	t.Cleanup(server.Close)

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	_, err = receiver.FetchAccessToken(types.Oid4vci, common.URIField(*serverURL), request.PreAuthorizedCode, request.TxCode)
	require.NoError(t, err)

	return <-forms
}

func TestOid4vciReceiver_RequestTokenAuthorizationCode(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	var attestationPops []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		attestationPops = append(attestationPops, r.Header.Get("OAuth-Client-Attestation-PoP"))
		if got := r.Header.Get("OAuth-Client-Attestation"); got != "attestation-jwt" {
			t.Errorf("OAuth-Client-Attestation header = %q", got)
		}
		if attempts == 1 {
			if r.Header.Get("DPoP") != "proof:" {
				t.Errorf("first DPoP proof = %q", r.Header.Get("DPoP"))
			}
			w.Header().Set("DPoP-Nonce", "nonce-1")
			useDPoPNonceTokenChallenge(w)
			return
		}
		if r.Header.Get("DPoP") != "proof:nonce-1" {
			t.Errorf("second DPoP proof = %q", r.Header.Get("DPoP"))
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{
			"access_token": "access-1",
			"token_type":   "DPoP",
		})
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	headerFactoryCalls := 0
	var proofNonces []string
	response, err := receiver.RequestToken(t.Context(), common.URIField(*parsed), types.TokenRequest{
		GrantType:    types.AuthorizationCode,
		Code:         "code-1",
		RedirectURI:  "openid-credential-offer://callback",
		CodeVerifier: "verifier-1",
		ClientID:     "client-1",
	}, types.ClientAuthentication{ClientAttestation: func() (types.OAuthClientAttestationHeaders, error) {
		headerFactoryCalls++
		return types.OAuthClientAttestationHeaders{
			ClientAttestation:    "attestation-jwt",
			ClientAttestationPop: fmt.Sprintf("attestation-pop-jwt-%d", headerFactoryCalls),
		}, nil
	}, DPoP: func(nonce string) (string, error) {
		proofNonces = append(proofNonces, nonce)
		return "proof:" + nonce, nil
	}})
	if err != nil {
		t.Fatalf("RequestToken() error = %v", err)
	}
	if response.Token != "access-1" || response.TokenType != "DPoP" {
		t.Fatalf("response = %#v", response)
	}
	if attempts != 2 || headerFactoryCalls != 2 {
		t.Fatalf("attempts = %d, headerFactoryCalls = %d", attempts, headerFactoryCalls)
	}
	if len(attestationPops) != 2 || attestationPops[0] == attestationPops[1] {
		t.Fatalf("attestation PoP headers = %#v", attestationPops)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
}

func TestOid4vciReceiver_FetchAccessToken_ClientAssertion(t *testing.T) {
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	t.Run("client_assertion form fields are sent when provided", func(t *testing.T) {

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

// countingTransport records how many requests actually left the HTTP client.
type countingTransport struct {
	attempts int
}

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.attempts++
	return nil, fmt.Errorf("no request should have been attempted")
}

// withCountedTokenTransport injects a per-receiver transport so that a test
// can prove nothing was sent, and restores it afterwards.
func withCountedTokenTransport(t *testing.T, receiver *Oid4vciReceiver) *countingTransport {
	t.Helper()
	counter := &countingTransport{}
	original := receiver.HTTPClient
	receiver.HTTPClient = &http.Client{Transport: counter}
	t.Cleanup(func() { receiver.HTTPClient = original })
	return counter
}

func TestOid4vciReceiver_FetchAccessToken_RefusesClientAssertionOverPlainHTTP(t *testing.T) {
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	// HTTP is allowed, which is what makes this worth testing: the assertion
	// must still be refused on a host that is not this machine.

	tests := []struct {
		name    string
		rawURL  string
		allowed bool
	}{
		{name: "remote host over http", rawURL: "http://as.example.com/token", allowed: false},
		{name: "private network address over http", rawURL: "http://10.0.0.1:8080/token", allowed: false},
		{name: "host merely named like localhost", rawURL: "http://localhost.evil.com/token", allowed: false},
		{name: "loopback name over http", rawURL: "http://localhost:8080/token", allowed: true},
		{name: "loopback address over http", rawURL: "http://127.0.0.1:8080/token", allowed: true},
		{name: "IPv6 loopback over http", rawURL: "http://[::1]:8080/token", allowed: true},
		{name: "remote host over https", rawURL: "https://as.example.com/token", allowed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter := withCountedTokenTransport(t, receiver)

			tokenURL, err := url.Parse(tt.rawURL)
			require.NoError(t, err)

			_, err = receiver.FetchAccessToken(
				types.Oid4vci,
				common.URIField(*tokenURL),
				"code",
				"",
				types.WithClientAssertion("wallet-id", "assertion.jwt.value"),
			)
			require.Error(t, err)

			if tt.allowed {
				// The transport is reached, which is as far as this test goes;
				// it deliberately fails there rather than contacting anything.
				assert.Equal(t, 1, counter.attempts)
				assert.NotContains(t, err.Error(), "https is required")
				return
			}

			assert.Contains(t, err.Error(), "https is required for any host other than loopback")
			assert.Zero(t, counter.attempts, "the client assertion must not be sent at all")
		})
	}
}

func TestOid4vciReceiver_FetchAccessToken_PlainHTTPStaysAllowedWithoutAssertion(t *testing.T) {
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	// Without a client assertion the existing VCKNOTS_WALLET_HTTP_ALLOWED
	// behaviour is unchanged, so the restriction stays scoped to the assertion.
	counter := withCountedTokenTransport(t, receiver)

	tokenURL, err := url.Parse("http://as.example.com/token")
	require.NoError(t, err)

	_, err = receiver.FetchAccessToken(types.Oid4vci, common.URIField(*tokenURL), "code", "")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "https is required")
	assert.Equal(t, 1, counter.attempts, "the request must still be attempted")
}

func TestOid4vciReceiver_FetchAccessToken_RequiresClientIDWithAssertion(t *testing.T) {
	receiver := &Oid4vciReceiver{AllowHTTP: true}

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
	receiver := &Oid4vciReceiver{AllowHTTP: true}

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
	assert.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	assert.Zero(t, relayedRequests, "the client_assertion must not reach the redirect target")
}

func TestOid4vciReceiver_RequestTokenClientAssertion(t *testing.T) {
	var captured url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		captured = r.Form
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"access_token": "access-1", "token_type": "DPoP"})
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	receiver := &Oid4vciReceiver{AllowHTTP: true}
	token, err := receiver.RequestToken(t.Context(), common.URIField(*parsed), types.TokenRequest{
		GrantType:    types.AuthorizationCode,
		Code:         "code-1",
		RedirectURI:  "https://wallet.example/callback",
		CodeVerifier: "verifier-1",
		ClientID:     "client-1",
	}, types.ClientAuthentication{
		ClientAssertion: func() (string, error) { return "assertion-jwt", nil },
		DPoP:            fixedProof("dpop-proof"),
	})
	require.NoError(t, err)
	assert.Equal(t, "access-1", token.Token)
	assert.Equal(t, "assertion-jwt", captured.Get("client_assertion"))
	assert.Equal(t, types.ClientAssertionTypeJWTBearer, captured.Get("client_assertion_type"))
}

func TestOid4vciReceiver_RequestTokenRetryRefreshesClientAssertion(t *testing.T) {
	attempts := 0
	var captured []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		_ = r.ParseForm()
		captured = append(captured, r.Form)
		if attempts == 1 {
			w.Header().Set("DPoP-Nonce", "nonce-1")
			useDPoPNonceTokenChallenge(w)
			return
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"access_token": "access-1", "token_type": "DPoP"})
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	factoryCalls := 0
	_, err = receiver.RequestToken(t.Context(), common.URIField(*parsed), types.TokenRequest{
		GrantType:    types.AuthorizationCode,
		Code:         "code-1",
		RedirectURI:  "https://wallet.example/callback",
		CodeVerifier: "verifier-1",
		ClientID:     "client-1",
	}, types.ClientAuthentication{
		ClientAssertion: func() (string, error) {
			factoryCalls++
			return fmt.Sprintf("assertion-%d", factoryCalls), nil
		},
		DPoP: fixedProof("dpop-proof"),
	})
	require.NoError(t, err)
	require.Equal(t, 2, attempts)
	require.Equal(t, 2, factoryCalls)
	require.Len(t, captured, 2)
	for _, form := range captured {
		assert.Equal(t, types.ClientAssertionTypeJWTBearer, form.Get("client_assertion_type"))
	}
	assert.NotEqual(t, captured[0].Get("client_assertion"), captured[1].Get("client_assertion"))
}

// preAuthorizedAttestationIssuer is a mock issuer that requires the Appendix E
// client authentication on its token endpoint, with the keys the wallet side of
// the test signs with.
func preAuthorizedAttestationIssuer(t *testing.T, configure func(*mockserver.OID4VCIIssuerConfig)) (*mockserver.OID4VCIIssuerServer, jose.JSONWebKey, jose.JSONWebKey) {
	t.Helper()
	clientPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	attesterPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientKey := jose.JSONWebKey{Key: clientPrivateKey, KeyID: "client-key-1", Algorithm: string(jose.ES256), Use: "sig"}
	attesterKey := jose.JSONWebKey{Key: attesterPrivateKey, KeyID: "attester-key-1", Algorithm: string(jose.ES256), Use: "sig"}

	config := mockserver.DefaultOID4VCIIssuerConfig()
	config.RequireClientAttestation = true
	config.ExpectedClientID = "client-1"
	attesterPublic := attesterKey.Public()
	config.ClientAttesterPublicKey = &attesterPublic
	config.RequireDPoP = true
	config.TokenResponse = map[string]interface{}{
		"access_token": "access-1",
		"token_type":   "DPoP",
		"expires_in":   3600,
	}
	if configure != nil {
		configure(config)
	}
	issuer := mockserver.NewOID4VCIIssuerServer(config)
	t.Cleanup(issuer.Close)
	return issuer, clientKey, attesterKey
}

// The §6.1 Pre-Authorized Code token request carries attestation-based client
// authentication in its headers, and an issuer that requires it accepts the
// request. OpenID4VCI 1.0 Appendix E profiles
// draft-ietf-oauth-attestation-based-client-auth for exactly this purpose, and
// HAIP §4.4.1 requires "an OAuth2 Client authentication mechanism at OAuth2
// Endpoints that support client authentication".
func TestRequestTokenPreAuthorizedCode_CarriesAttestationHeaders(t *testing.T) {
	issuer, clientKey, attesterKey := preAuthorizedAttestationIssuer(t, nil)
	receiver := &Oid4vciReceiver{AllowHTTP: true}
	tokenEndpoint := issuer.URL() + "/token"

	token, err := receiver.RequestToken(
		context.Background(), mustURIField(t, tokenEndpoint), types.TokenRequest{GrantType: types.PreAuthorizedCode, PreAuthorizedCode: "pre-auth-code-1", TxCode: "493536", ClientID: "client-1"}, types.ClientAuthentication{ClientAttestation: attestationHeadersFactory(t, clientKey, attesterKey, issuer.URL()), DPoP: func(nonce string) (string, error) {
			return signDPoP(clientKey, http.MethodPost, tokenEndpoint, nonce, "")
		}})
	require.NoError(t, err)
	require.Equal(t, "access-1", token.Token)

	forms := issuer.TokenRequests()
	require.Len(t, forms, 1)
	require.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", forms[0].Get("grant_type"))
	require.Equal(t, "pre-auth-code-1", forms[0].Get("pre-authorized_code"))
	require.Equal(t, "493536", forms[0].Get("tx_code"))
	require.Equal(t, "client-1", forms[0].Get("client_id"))

	headers := issuer.TokenRequestHeaders()
	require.Len(t, headers, 1)
	require.NotEmpty(t, headers[0].Get("OAuth-Client-Attestation"))
	require.NotEmpty(t, headers[0].Get("OAuth-Client-Attestation-PoP"))
}

// RFC 9449 §8: the retry the transport owns rebuilds the attestation headers
// for the second attempt, so the issuer sees a fresh PoP rather than a replayed
// one.
func TestRequestTokenPreAuthorizedCode_RebuildsHeadersOnNonceChallenge(t *testing.T) {
	issuer, clientKey, attesterKey := preAuthorizedAttestationIssuer(t, func(config *mockserver.OID4VCIIssuerConfig) {
		config.TokenDPoPNonce = "token-nonce-1"
	})
	receiver := &Oid4vciReceiver{AllowHTTP: true}
	tokenEndpoint := issuer.URL() + "/token"

	token, err := receiver.RequestToken(
		context.Background(), mustURIField(t, tokenEndpoint), types.TokenRequest{GrantType: types.PreAuthorizedCode, PreAuthorizedCode: "pre-auth-code-1", ClientID: "client-1"}, types.ClientAuthentication{ClientAttestation: attestationHeadersFactory(t, clientKey, attesterKey, issuer.URL()), DPoP: func(nonce string) (string, error) {
			return signDPoP(clientKey, http.MethodPost, tokenEndpoint, nonce, "")
		}})
	require.NoError(t, err)
	require.Equal(t, "access-1", token.Token)

	headers := issuer.TokenRequestHeaders()
	require.Len(t, headers, 2)
	require.NotEmpty(t, headers[1].Get("OAuth-Client-Attestation-PoP"))
	require.NotEqual(t, headers[0].Get("OAuth-Client-Attestation-PoP"), headers[1].Get("OAuth-Client-Attestation-PoP"))
	require.NotEqual(t, headers[0].Get("DPoP"), headers[1].Get("DPoP"))
}

// An issuer that requires attestation-based client authentication refuses the
// same request sent without the headers, which is what makes the acceptance
// above evidence.
func TestRequestTokenPreAuthorizedCode_IssuerRefusesMissingHeaders(t *testing.T) {
	issuer, clientKey, _ := preAuthorizedAttestationIssuer(t, nil)
	receiver := &Oid4vciReceiver{AllowHTTP: true}
	tokenEndpoint := issuer.URL() + "/token"

	_, err := receiver.RequestToken(
		context.Background(), mustURIField(t, tokenEndpoint), types.TokenRequest{GrantType: types.PreAuthorizedCode, PreAuthorizedCode: "pre-auth-code-1", ClientID: "client-1"}, types.ClientAuthentication{DPoP: func(nonce string) (string, error) {
			return signDPoP(clientKey, http.MethodPost, tokenEndpoint, nonce, "")
		}})
	require.ErrorContains(t, err, "invalid_client")
}

// attestationHeadersFactory mints a Client Attestation once and a fresh PoP for
// every attempt, the way a wallet holding a Client Attestation provider does.
func attestationHeadersFactory(t *testing.T, clientKey, attesterKey jose.JSONWebKey, authorizationServer string) types.OAuthClientAttestationHeadersFactory {
	t.Helper()
	attestation, err := signClientAttestation(clientKey, attesterKey, "https://client-attester.example", "client-1")
	require.NoError(t, err)
	return func() (types.OAuthClientAttestationHeaders, error) {
		pop, err := signClientAttestationPoP(clientKey, "client-1", authorizationServer, "")
		if err != nil {
			return types.OAuthClientAttestationHeaders{}, err
		}
		return types.OAuthClientAttestationHeaders{ClientAttestation: attestation, ClientAttestationPop: pop}, nil
	}
}
