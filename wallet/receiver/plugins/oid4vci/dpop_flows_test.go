package oid4vci

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestOid4vciReceiver_RequestCredentialDPoPRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.Header.Get("Authorization") != "DPoP access-1" {
			t.Errorf("Authorization header = %q", r.Header.Get("Authorization"))
		}
		if attempts == 1 {
			if r.Header.Get("DPoP") != "proof:" {
				t.Errorf("first DPoP proof = %q", r.Header.Get("DPoP"))
			}
			w.Header().Set("DPoP-Nonce", "nonce-1")
			useDPoPNonceResourceChallenge(w)
			return
		}
		if r.Header.Get("DPoP") != "proof:nonce-1" {
			t.Errorf("second DPoP proof = %q", r.Header.Get("DPoP"))
		}
		var body types.CredentialRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		if body.CredentialConfigurationID != "pid" {
			t.Errorf("credential_configuration_id = %q", body.CredentialConfigurationID)
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"credential": "credential-jwt"})
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	var proofNonces []string
	response, err := requestCredentialJSON(t.Context(), receiver,
		common.URIField(*parsed),
		"access-1",
		types.CredentialRequest{CredentialConfigurationID: "pid"},
		func(nonce string) (string, error) {
			proofNonces = append(proofNonces, nonce)
			return "proof:" + nonce, nil
		},
	)
	if err != nil {
		t.Fatalf("credential request error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
	if response.Credential != "credential-jwt" {
		t.Fatalf("response = %#v", response)
	}
}

func TestOid4vciReceiver_RequestCredentialEndpointDPoPRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if got := r.Header.Get("Authorization"); got != "DPoP access-1" {
			t.Errorf("Authorization header = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/jwt" {
			t.Errorf("Content-Type header = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}
		if string(body) != "encrypted-request" {
			t.Errorf("body = %q", string(body))
		}
		if attempts == 1 {
			if r.Header.Get("DPoP") != "proof:" {
				t.Errorf("first DPoP proof = %q", r.Header.Get("DPoP"))
			}
			w.Header().Set("DPoP-Nonce", "nonce-1")
			useDPoPNonceResourceChallenge(w)
			return
		}
		if r.Header.Get("DPoP") != "proof:nonce-1" {
			t.Errorf("second DPoP proof = %q", r.Header.Get("DPoP"))
		}
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte("encrypted-response"))
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	var proofNonces []string
	response, err := postCredentialBody(t.Context(), receiver,
		common.URIField(*parsed),
		"access-1",
		[]byte("encrypted-request"),
		"application/jwt",
		func(nonce string) (string, error) {
			proofNonces = append(proofNonces, nonce)
			return "proof:" + nonce, nil
		},
	)
	if err != nil {
		t.Fatalf("RequestCredential() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
	if string(response.Body) != "encrypted-response" || response.ContentType != "application/jwt" {
		t.Fatalf("response = %#v", response)
	}
}

func TestOid4vciReceiver_RequestTokenDPoPRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type header = %q", got)
		}
		if got := r.Header.Get("OAuth-Client-Attestation"); got != "attestation-jwt" {
			t.Errorf("OAuth-Client-Attestation header = %q", got)
		}
		if got := r.Header.Get("OAuth-Client-Attestation-PoP"); got != "attestation-pop-jwt" {
			t.Errorf("OAuth-Client-Attestation-PoP header = %q", got)
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
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if got := r.Form.Get("grant_type"); got != "authorization_code" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.Form.Get("code"); got != "code-1" {
			t.Errorf("code = %q", got)
		}
		if got := r.Form.Get("redirect_uri"); got != "openid-credential-offer://callback" {
			t.Errorf("redirect_uri = %q", got)
		}
		if got := r.Form.Get("code_verifier"); got != "verifier-1" {
			t.Errorf("code_verifier = %q", got)
		}
		if got := r.Form.Get("client_id"); got != "client-1" {
			t.Errorf("client_id = %q", got)
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

	var proofNonces []string
	response, err := receiver.RequestToken(t.Context(), common.URIField(*parsed), types.TokenRequest{
		GrantType:    types.AuthorizationCode,
		Code:         "code-1",
		RedirectURI:  "openid-credential-offer://callback",
		CodeVerifier: "verifier-1",
		ClientID:     "client-1",
	}, types.ClientAuthentication{ClientAttestation: fixedAttestationHeaders(types.OAuthClientAttestationHeaders{
		ClientAttestation:    "attestation-jwt",
		ClientAttestationPop: "attestation-pop-jwt",
	}), DPoP: func(nonce string) (string, error) {
		proofNonces = append(proofNonces, nonce)
		return "proof:" + nonce, nil
	}})
	if err != nil {
		t.Fatalf("token request error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
	if response.Token != "access-1" || response.TokenType != "DPoP" {
		t.Fatalf("response = %#v", response)
	}
}

func TestOid4vciReceiver_RequestDeferredCredentialDPoPRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			assertBearerJSONRequest(t, r, "access-1", "proof:")
			w.Header().Set("DPoP-Nonce", "nonce-1")
			useDPoPNonceResourceChallenge(w)
			return
		}
		assertBearerJSONRequest(t, r, "access-1", "proof:nonce-1")
		var body types.DeferredCredentialRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		if body.TransactionID != "tx-1" {
			t.Errorf("transaction_id = %q", body.TransactionID)
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"credential": "credential-jwt"})
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	var proofNonces []string
	response, err := requestCredentialJSON(t.Context(), receiver,
		common.URIField(*parsed),
		"access-1",
		types.DeferredCredentialRequest{TransactionID: "tx-1"},
		func(nonce string) (string, error) {
			proofNonces = append(proofNonces, nonce)
			return "proof:" + nonce, nil
		},
	)
	if err != nil {
		t.Fatalf("deferred credential request error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
	if response.Credential != "credential-jwt" {
		t.Fatalf("response = %#v", response)
	}
}

func TestOid4vciReceiver_SendCredentialNotificationDPoPRetry(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			assertBearerJSONRequest(t, r, "access-1", "proof:")
			w.Header().Set("DPoP-Nonce", "nonce-1")
			useDPoPNonceResourceChallenge(w)
			return
		}
		assertBearerJSONRequest(t, r, "access-1", "proof:nonce-1")
		var body types.NotificationRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		if body.NotificationID != "notification-1" || body.Event != "credential_accepted" {
			t.Errorf("notification request = %#v", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse server URL: %v", err)
	}

	var proofNonces []string
	err = receiver.SendNotification(t.Context(),
		common.URIField(*parsed),
		dpopAccessToken("access-1"),
		types.NotificationRequest{NotificationID: "notification-1", Event: "credential_accepted"},
		func(nonce string) (string, error) {
			proofNonces = append(proofNonces, nonce)
			return "proof:" + nonce, nil
		},
	)
	if err != nil {
		t.Fatalf("SendNotification() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d", attempts)
	}
	if len(proofNonces) != 2 || proofNonces[0] != "" || proofNonces[1] != "nonce-1" {
		t.Fatalf("proof nonces = %#v", proofNonces)
	}
}

func TestCredentialRequestUsesBearerSchemeForBearerToken(t *testing.T) {
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	response, err := receiver.RequestCredential(t.Context(),
		mustURIField(t, issuer.URL()+"/credential"),
		types.CredentialIssuanceAccessToken{Token: issuer.AccessToken(), TokenType: "Bearer"},
		"c-nonce-1",
		func(nonce string) ([]byte, string, error) {
			return []byte(`{"credential_configuration_id":"test-config"}`), "application/json", nil
		},
		nil,
		noopProofFactory,
	)

	require.NoError(t, err)
	require.NotNil(t, response)

	requests := issuer.CredentialRequests()
	require.Len(t, requests, 1)
	assert.Equal(t, "Bearer "+issuer.AccessToken(), requests[0].Authorization)
	assert.Empty(t, requests[0].DPoP, "a bearer token is not key-bound, so no DPoP proof is sent with it")
}

func TestCredentialRequestUsesDPoPSchemeForDPoPToken(t *testing.T) {
	// The issuer states a DPoP-bound token, so it accepts the DPoP scheme and
	// no other; the wallet must present the token the way the token response
	// named it.
	config := mockserver.DefaultOID4VCIIssuerConfig()
	config.TokenResponse["token_type"] = "DPoP"
	issuer := mockserver.NewOID4VCIIssuerServer(config)
	defer issuer.Close()
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	response, err := receiver.RequestCredential(t.Context(),
		mustURIField(t, issuer.URL()+"/credential"),
		types.CredentialIssuanceAccessToken{Token: issuer.AccessToken(), TokenType: "dpop"},
		"c-nonce-1",
		func(nonce string) ([]byte, string, error) {
			return []byte(`{"credential_configuration_id":"test-config"}`), "application/json", nil
		},
		nil,
		noopProofFactory,
	)

	require.NoError(t, err)
	require.NotNil(t, response)

	requests := issuer.CredentialRequests()
	require.Len(t, requests, 1)
	// token_type is case insensitive (RFC 6749 Section 7.1) but the scheme is
	// spelled as RFC 9449 Section 7.1 defines it.
	assert.Equal(t, "DPoP "+issuer.AccessToken(), requests[0].Authorization)
	assert.Equal(t, "dpop-proof", requests[0].DPoP)
}
