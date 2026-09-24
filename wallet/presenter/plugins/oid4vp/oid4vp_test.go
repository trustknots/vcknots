package oid4vp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// testDcqlQueryParam is the URL-encoded form of
// {"credentials":[{"id":"cred1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}
// for use in query-parameter style presentation request URIs.
const testDcqlQueryParam = "%7B%22credentials%22%3A%5B%7B%22id%22%3A%22cred1%22%2C%22format%22%3A%22jwt_vc_json%22%2C%22meta%22%3A%7B%22type_values%22%3A%5B%5B%22VerifiableCredential%22%5D%5D%7D%7D%5D%7D"

func TestOid4vpPresenter_Present(t *testing.T) {
	testPresentation := []byte("a.valid.jwt")
	testRequest := &types.PresentationRequest{
		CredentialQueryID: "cred1",
	}

	tests := []struct {
		name                   string
		protocol               types.SupportedPresentationProtocol
		serializedPresentation []byte
		wantErr                bool
		serverConfig           *mockserver.OID4VPPresenterConfig
		useUnreachableEndpoint bool // フラグで制御するように変更
	}{
		{
			name:                   "Normal case",
			protocol:               types.Oid4vp,
			serializedPresentation: testPresentation,
			wantErr:                false,
			serverConfig:           mockserver.DefaultOID4VPPresenterConfig(), // accepts all presentations
			useUnreachableEndpoint: false,
		},
		{
			name:                   "Protocol mismatch",
			protocol:               types.Oid4vp + 1,
			serializedPresentation: testPresentation,
			wantErr:                true,
			serverConfig:           mockserver.DefaultOID4VPPresenterConfig(),
			useUnreachableEndpoint: false,
		},
		{
			name:                   "Server returns non-200 status",
			protocol:               types.Oid4vp,
			serializedPresentation: []byte("force-server-error"),
			wantErr:                true,
			serverConfig: &mockserver.OID4VPPresenterConfig{
				AcceptAllPresentations: false, // rejects presentations
				CustomResponses:        make(map[string]any),
			},
			useUnreachableEndpoint: false,
		},
		{
			name:                   "Network error (unreachable)",
			protocol:               types.Oid4vp,
			serializedPresentation: testPresentation,
			wantErr:                true,
			serverConfig:           mockserver.DefaultOID4VPPresenterConfig(),
			useUnreachableEndpoint: true, // フラグで制御
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var endpoint url.URL
			if tt.useUnreachableEndpoint {
				// Use unreachable endpoint for network error test
				endpoint = *mustParseURL(t, "http://localhost:12345")
			} else {
				// Create a mock server with the specified configuration
				presenterServer := mockserver.NewOID4VPPresenterServer(tt.serverConfig)
				defer presenterServer.Close()
				presenterURL, _ := url.Parse(presenterServer.URL() + "/present")
				endpoint = *presenterURL
			}
			p := &Oid4vpPresenter{}
			_, err := p.Present(tt.protocol, endpoint, tt.serializedPresentation, testRequest)

			if (err != nil) != tt.wantErr {
				t.Errorf("Oid4vpPresenter.Present() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	t.Run("Returns redirect_uri from verifier resposnse", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{"redirect_uri":"https://example.com/callback"}`))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer server.Close()

		endpoint, err := url.Parse(server.URL)
		require.NoError(t, err)

		p := &Oid4vpPresenter{}
		redirectURI, err := p.Present(types.Oid4vp, *endpoint, testPresentation, testRequest)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback", redirectURI)
	})

	t.Run("Ignores non-JSON verifier response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("ok"))
			if err != nil {
				t.Fatalf("failed to write response: %v", err)
			}
		}))
		defer server.Close()

		endpoint, err := url.Parse(server.URL)
		require.NoError(t, err)

		p := &Oid4vpPresenter{}
		redirectURI, err := p.Present(types.Oid4vp, *endpoint, testPresentation, testRequest)
		require.NoError(t, err)
		assert.Empty(t, redirectURI)
	})

	// AC (Issue #606): vp_token must be a JSON object keyed by the DCQL
	// Credential Query id, and presentation_submission must not be sent.
	t.Run("Sends vp_token as DCQL JSON object", func(t *testing.T) {
		var gotVPToken, gotSubmission, gotState string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
			}
			gotVPToken = r.PostFormValue("vp_token")
			gotSubmission = r.PostFormValue("presentation_submission")
			gotState = r.PostFormValue("state")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		endpoint, err := url.Parse(server.URL)
		require.NoError(t, err)

		p := &Oid4vpPresenter{}
		req := &types.PresentationRequest{CredentialQueryID: "cred1", State: "test-state"}
		_, err = p.Present(types.Oid4vp, *endpoint, testPresentation, req)
		require.NoError(t, err)

		assert.JSONEq(t, `{"cred1":["a.valid.jwt"]}`, gotVPToken)
		assert.Empty(t, gotSubmission, "presentation_submission must not be sent")
		assert.Equal(t, "test-state", gotState)
	})

	t.Run("Missing credential query id is rejected", func(t *testing.T) {
		p := &Oid4vpPresenter{}
		endpoint := *mustParseURL(t, "http://localhost:12345")

		_, err := p.Present(types.Oid4vp, endpoint, testPresentation, &types.PresentationRequest{})
		if err == nil || !strings.Contains(err.Error(), "credential query id is required") {
			t.Fatalf("expected credential query id error, got: %v", err)
		}

		_, err = p.Present(types.Oid4vp, endpoint, testPresentation, nil)
		if err == nil || !strings.Contains(err.Error(), "credential query id is required") {
			t.Fatalf("expected credential query id error for nil request, got: %v", err)
		}
	})

	// Test network error case with connection hijacking
	t.Run("Network error (server closes connection)", func(t *testing.T) {
		// Create a mock server that closes connection immediately
		hijackServer := mockserver.NewMockServer()
		defer hijackServer.Close()
		hijackServer.HandleFunc("/present", func(w http.ResponseWriter, r *http.Request) {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("http.Hijacker not supported")
			}
			conn, _, _ := hijacker.Hijack()
			conn.Close()
		})

		hijackURL, _ := url.Parse(hijackServer.URL() + "/present")

		p := &Oid4vpPresenter{}
		_, err := p.Present(types.Oid4vp, *hijackURL, testPresentation, testRequest)

		if err == nil {
			t.Error("Expected error for hijacked connection, got nil")
		}
	})
}

func TestOid4vpPresenter_EncryptAuthorizationResponse(t *testing.T) {
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}

	p := &Oid4vpPresenter{}
	token, err := encryptResponseForTest(p,
		map[string]any{
			"vp_token": map[string]any{
				"pid": []string{"presented-sd-jwt"},
			},
			"state": "state-1",
		},
		&VerifierMetadata{
			Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{
					Key:       &recipient.PublicKey,
					KeyID:     "enc-key-1",
					Use:       "enc",
					Algorithm: string(jose.ECDH_ES),
				},
			}},
			EncryptedResponseEncValuesSupported: []string{"A256GCM"},
		},
	)
	if err != nil {
		t.Fatalf("encryptAuthorizationResponseJWE() error = %v", err)
	}

	jwe, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatalf("failed to parse encrypted response: %v", err)
	}
	if jwe.Header.KeyID != "enc-key-1" {
		t.Fatalf("expected kid enc-key-1, got %q", jwe.Header.KeyID)
	}
	if got := jwe.Header.ExtraHeaders[jose.HeaderContentType]; got != "json" {
		t.Fatalf("expected cty json, got %#v", got)
	}
	plaintext, err := jwe.Decrypt(recipient)
	if err != nil {
		t.Fatalf("failed to decrypt response: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if payload["state"] != "state-1" {
		t.Fatalf("expected state to round-trip, got %#v", payload["state"])
	}
	vpToken, ok := payload["vp_token"].(map[string]any)
	if !ok {
		t.Fatalf("expected vp_token object, got %#v", payload["vp_token"])
	}
	if _, ok := vpToken["pid"].([]any); !ok {
		t.Fatalf("expected pid credential array in vp_token, got %#v", vpToken["pid"])
	}
}

func TestOid4vpPresenter_DirectPostJWTResponse(t *testing.T) {
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}

	p := &Oid4vpPresenter{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		token := r.Form.Get("response")
		if token == "" {
			t.Fatal("missing response form field")
		}
		jwe, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
		if err != nil {
			t.Fatalf("failed to parse encrypted response: %v", err)
		}
		plaintext, err := jwe.Decrypt(recipient)
		if err != nil {
			t.Fatalf("failed to decrypt encrypted response: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			t.Fatalf("failed to unmarshal response payload: %v", err)
		}
		if payload["state"] != "state-1" {
			t.Fatalf("state = %#v", payload["state"])
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"redirect_uri":"https://example.com/callback"}`))
	}))
	defer server.Close()

	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse endpoint: %v", err)
	}
	redirect, err := sendDCQLForTest(p, *endpoint, map[string][]string{"pid": {"presented-sd-jwt"}}, &types.PresentationRequest{
		State:        "state-1",
		ResponseMode: string(OAuthAuthzReqResponseModeDirectPostJWT),
		ClientMetadata: &VerifierMetadata{
			Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key:       &recipient.PublicKey,
				KeyID:     "enc-key-1",
				Use:       "enc",
				Algorithm: string(jose.ECDH_ES),
			}}},
			EncryptedResponseEncValuesSupported: []string{"A256GCM"},
		},
	})
	if err != nil {
		t.Fatalf("direct_post.jwt response error = %v", err)
	}
	if redirect != "https://example.com/callback" {
		t.Fatalf("redirect = %q", redirect)
	}
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL '%s': %v", rawURL, err)
	}
	return u
}

func TestOid4vpPresenter_Draft24_ParsePresentationRequest(t *testing.T) {
	// mockserver / httptest.NewServer use http; allow it for these tests.

	// Setup mock verifier server with proper JWT signing
	verifierServer := mockserver.NewOID4VPVerifierServer(nil)
	defer verifierServer.Close()

	// Create client_metadata with JWKS for JWT verification
	keyPair := verifierServer.GetKeyPair()
	clientMetadata := map[string]any{
		"client_name": "Test Client",
		"jwks":        keyPair.CreateJWKS(),
	}

	// Create properly signed JWT with the mock verifier's issuer
	testClaims := map[string]any{
		"aud":           "test-client",
		"nonce":         "test-nonce",
		"client_id":     "redirect_uri:https://example.com/response",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"state":         "test-state",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{"id": "cred1", "format": "jwt_vc_json", "meta": map[string]any{"type_values": []any{[]any{"VerifiableCredential"}}}},
			},
		},
		"response_uri":    "https://example.com/response",
		"client_metadata": clientMetadata,
	}

	mockJWT, err := verifierServer.CreateSignedJWT(testClaims)
	if err != nil {
		t.Fatalf("Failed to create signed JWT: %v", err)
	}

	setupMockJWTServer := func(expectedMethod string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != expectedMethod {
				t.Errorf("Expected %s method, got %s", expectedMethod, r.Method)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockJWT))
		}))
	}

	tests := []struct {
		name    string
		uri     string
		setup   func() *httptest.Server
		wantErr bool
	}{
		{
			name:    "Query parameters without authority",
			uri:     "openid4vp:?client_id=redirect_uri:https://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&response_uri=https://example.com/response",
			setup:   nil,
			wantErr: false,
		},
		{
			name:    "Query parameters",
			uri:     "openid4vp://present?client_id=redirect_uri:https://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&response_uri=https://example.com/response",
			setup:   nil,
			wantErr: false,
		},
		{
			name:    "request_uri with default GET method",
			setup:   func() *httptest.Server { return setupMockJWTServer("GET") },
			wantErr: false,
		},
		{
			name:    "request_uri with explicit GET method",
			setup:   func() *httptest.Server { return setupMockJWTServer("GET") },
			wantErr: false,
		},
		{
			name:    "request_uri with POST method",
			setup:   func() *httptest.Server { return setupMockJWTServer("POST") },
			wantErr: false,
		},
		{
			name: "request_uri server error",
			setup: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			if tt.setup != nil {
				server = tt.setup()
				defer server.Close()
			}

			var uri string
			if tt.uri != "" {
				uri = tt.uri
			} else {
				// Build URI with request_uri
				switch tt.name {
				case "request_uri with default GET method":
					uri = "openid4vp://present?client_id=redirect_uri:https://example.com/response&request_uri=" + server.URL
				case "request_uri with explicit GET method":
					uri = "openid4vp://present?client_id=redirect_uri:https://example.com/response&request_uri=" + server.URL + "&request_uri_method=GET"
				case "request_uri with POST method":
					uri = "openid4vp://present?client_id=redirect_uri:https://example.com/response&request_uri=" + server.URL + "&request_uri_method=POST"
				case "request_uri server error":
					uri = "openid4vp://present?client_id=redirect_uri:https://example.com/response&request_uri=" + server.URL
				}
			}

			p := &Oid4vpPresenter{AllowHTTP: true}
			req, err := parseDraft24ForTest(p, uri)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePresentationRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && req == nil {
				t.Error("Expected non-nil request for successful case")
			}
		})
	}

	// Test invalid URI
	t.Run("Invalid URI", func(t *testing.T) {
		p := &Oid4vpPresenter{AllowHTTP: true}
		_, err := parseDraft24ForTest(p, "://invalid-uri")
		if err == nil {
			t.Error("Expected error for invalid URI, got nil")
		}
	})
}

// TestOid4vpPresenter_WithRequestObject_TypHeader tests 'typ' header validation
func TestOid4vpPresenter_Draft24_WithRequestObject_TypHeader(t *testing.T) {
	// Setup mock verifier server with proper JWT signing
	verifierServer := mockserver.NewOID4VPVerifierServer(nil)
	defer verifierServer.Close()

	// Create client_metadata with JWKS for JWT verification
	keyPair := verifierServer.GetKeyPair()
	clientMetadata := map[string]any{
		"client_name": "Test Client",
		"jwks":        keyPair.CreateJWKS(),
	}

	// Create test claims
	testClaims := map[string]any{
		"aud":           "test-client",
		"nonce":         "test-nonce",
		"client_id":     "redirect_uri:https://example.com/response",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"state":         "test-state",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{"id": "cred1", "format": "jwt_vc_json", "meta": map[string]any{"type_values": []any{[]any{"VerifiableCredential"}}}},
			},
		},
		"response_uri":    "https://example.com/response",
		"client_metadata": clientMetadata,
	}

	t.Run("Valid 'typ' header should succeed", func(t *testing.T) {
		// Create JWT with correct 'typ' header (done by mockserver by default)
		mockJWT, err := verifierServer.CreateSignedJWT(testClaims)
		if err != nil {
			t.Fatalf("Failed to create signed JWT: %v", err)
		}

		builder := newDraft24RequestBuilder()
		builder = builder.WithRequestObject(mockJWT)

		req, err := builder.Build()
		if err != nil {
			t.Errorf("Expected no error with valid 'typ' header, got: %v", err)
		}
		if req == nil {
			t.Error("Expected valid request object, got nil")
		}
	})

	t.Run("Missing 'typ' header should fail", func(t *testing.T) {
		// Create signer without 'typ' header
		joseKey := keyPair.CreateJWK()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: joseKey}, nil)
		if err != nil {
			t.Fatalf("Failed to create signer: %v", err)
		}

		// Create JWT without 'typ' header
		invalidJWT, err := jwt.Signed(signer).Claims(testClaims).Serialize()
		if err != nil {
			t.Fatalf("Failed to create JWT without 'typ' header: %v", err)
		}

		builder := newDraft24RequestBuilder()
		builder = builder.WithRequestObject(invalidJWT)

		_, err = builder.Build()
		if err == nil {
			t.Error("Expected error for missing 'typ' header, got nil")
		}
		if !strings.Contains(err.Error(), "must include 'typ' header parameter") {
			t.Errorf("Expected error message about missing 'typ' header, got: %v", err)
		}
	})

	t.Run("Invalid 'typ' header should fail", func(t *testing.T) {
		// Create signer with wrong 'typ' header
		joseKey := keyPair.CreateJWK()
		signerOptions := &jose.SignerOptions{}
		signerOptions.WithType("JWT") // Wrong typ header

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: joseKey}, signerOptions)
		if err != nil {
			t.Fatalf("Failed to create signer: %v", err)
		}

		// Create JWT with wrong 'typ' header
		invalidJWT, err := jwt.Signed(signer).Claims(testClaims).Serialize()
		if err != nil {
			t.Fatalf("Failed to create JWT with wrong 'typ' header: %v", err)
		}

		builder := newDraft24RequestBuilder()
		builder = builder.WithRequestObject(invalidJWT)

		_, err = builder.Build()
		if err == nil {
			t.Error("Expected error for invalid 'typ' header, got nil")
		}
		if !strings.Contains(err.Error(), "must be 'oauth-authz-req+jwt'") {
			t.Errorf("Expected error message about invalid 'typ' header, got: %v", err)
		}
	})
}

// TestOid4vpPresenter_WithRequestObject_IssClaimIgnored tests 'iss' claim handling
func TestOid4vpPresenter_Draft24_WithRequestObject_IssClaimIgnored(t *testing.T) {
	// Setup mock verifier server with proper JWT signing
	verifierServer := mockserver.NewOID4VPVerifierServer(nil)
	defer verifierServer.Close()

	// Create client_metadata with JWKS for JWT verification
	keyPair := verifierServer.GetKeyPair()
	clientMetadata := map[string]any{
		"client_name": "Test Client",
		"jwks":        keyPair.CreateJWKS(),
	}

	// Create test claims including 'iss' claim
	testClaims := map[string]any{
		"iss":           "should-be-ignored", // This should be ignored per OID4VP spec
		"aud":           "test-client",
		"nonce":         "test-nonce",
		"client_id":     "redirect_uri:https://example.com/response",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"state":         "test-state",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{"id": "cred1", "format": "jwt_vc_json", "meta": map[string]any{"type_values": []any{[]any{"VerifiableCredential"}}}},
			},
		},
		"response_uri":    "https://example.com/response",
		"client_metadata": clientMetadata,
	}

	t.Run("JWT with 'iss' claim should be processed correctly", func(t *testing.T) {
		// Create JWT with 'iss' claim
		mockJWT, err := verifierServer.CreateSignedJWT(testClaims)
		if err != nil {
			t.Fatalf("Failed to create signed JWT: %v", err)
		}

		builder := newDraft24RequestBuilder()
		builder = builder.WithRequestObject(mockJWT)

		req, err := builder.Build()
		if err != nil {
			t.Fatalf("Expected no error when 'iss' claim is present, got: %v", err)
		}
		if req == nil {
			t.Fatalf("Expected valid request object, got nil")
		}

		// Verify that other claims were processed correctly
		if req.ClientID != "redirect_uri:https://example.com/response" {
			t.Fatalf("Expected ClientID 'redirect_uri:https://example.com/response', got: %s", req.ClientID)
		}
		if req.ResponseType != "vp_token" {
			t.Fatalf("Expected ResponseType 'vp_token', got: %s", req.ResponseType)
		}
	})
}

// TestOid4vpPresenter_WithRequestObject_StandardClaimsValidation tests standard JWT claims validation
func TestOid4vpPresenter_Draft24_WithRequestObject_StandardClaimsValidation(t *testing.T) {
	// Setup mock verifier server with proper JWT signing
	verifierServer := mockserver.NewOID4VPVerifierServer(nil)
	defer verifierServer.Close()

	// Create client_metadata with JWKS for JWT verification
	keyPair := verifierServer.GetKeyPair()
	clientMetadata := map[string]any{
		"client_name": "Test Client",
		"jwks":        keyPair.CreateJWKS(),
	}

	// Helper function to create JWT with custom time claims
	createJWTWithTimeClaims := func(iat, exp int64) (string, error) {
		testClaims := map[string]any{
			"iat":           iat,
			"exp":           exp,
			"aud":           "test-client",
			"nonce":         "test-nonce",
			"client_id":     "redirect_uri:https://example.com/response",
			"response_type": "vp_token",
			"response_mode": "direct_post",
			"state":         "test-state",
			"dcql_query": map[string]any{
				"credentials": []any{
					map[string]any{"id": "cred1", "format": "jwt_vc_json", "meta": map[string]any{"type_values": []any{[]any{"VerifiableCredential"}}}},
				},
			},
			"response_uri":    "https://example.com/response",
			"client_metadata": clientMetadata,
		}

		// Create JWT with custom claims (bypassing mockserver's default time claims)
		joseKey := keyPair.CreateJWK()
		signerOptions := &jose.SignerOptions{}
		signerOptions.WithType("oauth-authz-req+jwt")

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: joseKey}, signerOptions)
		if err != nil {
			return "", err
		}

		token, err := jwt.Signed(signer).Claims(testClaims).Serialize()
		return token, err
	}

	t.Run("Valid time claims should succeed", func(t *testing.T) {
		now := time.Now()
		validJWT, err := createJWTWithTimeClaims(now.Unix(), now.Add(time.Hour).Unix())
		if err != nil {
			t.Fatalf("Failed to create JWT with valid time claims: %v", err)
		}

		builder := newDraft24RequestBuilder()
		builder = builder.WithRequestObject(validJWT)

		req, err := builder.Build()
		if err != nil {
			t.Errorf("Expected no error with valid time claims, got: %v", err)
		}
		if req == nil {
			t.Error("Expected valid request object, got nil")
		}
	})

	t.Run("Expired JWT should fail", func(t *testing.T) {
		now := time.Now()
		expiredJWT, err := createJWTWithTimeClaims(
			now.Add(-2*time.Hour).Unix(), // issued 2 hours ago
			now.Add(-time.Hour).Unix(),   // expired 1 hour ago
		)
		if err != nil {
			t.Fatalf("Failed to create expired JWT: %v", err)
		}

		builder := newDraft24RequestBuilder()
		builder = builder.WithRequestObject(expiredJWT)

		_, err = builder.Build()
		if err == nil {
			t.Error("Expected error for expired JWT, got nil")
		}
		if !strings.Contains(err.Error(), "JWT standard claims validation failed") {
			t.Errorf("Expected error message about JWT claims validation, got: %v", err)
		}
	})

	t.Run("Future iat claim should fail", func(t *testing.T) {
		now := time.Now()
		futureIatJWT, err := createJWTWithTimeClaims(
			now.Add(time.Hour).Unix(),   // issued in the future
			now.Add(2*time.Hour).Unix(), // expires 2 hours from now
		)
		if err != nil {
			t.Fatalf("Failed to create JWT with future iat: %v", err)
		}

		builder := newDraft24RequestBuilder()
		builder = builder.WithRequestObject(futureIatJWT)

		_, err = builder.Build()
		if err == nil {
			t.Error("Expected error for future iat claim, got nil")
		}
		if !strings.Contains(err.Error(), "JWT standard claims validation failed") {
			t.Errorf("Expected error message about JWT claims validation, got: %v", err)
		}
	})

	t.Run("JWT without exp claim should succeed with leeway", func(t *testing.T) {
		// Test JWT without exp claim - should be allowed
		testClaims := map[string]any{
			"aud":           "test-client",
			"nonce":         "test-nonce",
			"client_id":     "redirect_uri:https://example.com/response",
			"response_type": "vp_token",
			"response_mode": "direct_post",
			"state":         "test-state",
			"dcql_query": map[string]any{
				"credentials": []any{
					map[string]any{"id": "cred1", "format": "jwt_vc_json", "meta": map[string]any{"type_values": []any{[]any{"VerifiableCredential"}}}},
				},
			},
			"response_uri":    "https://example.com/response",
			"client_metadata": clientMetadata,
		}

		noExpJWT, err := verifierServer.CreateSignedJWT(testClaims)
		if err != nil {
			t.Fatalf("Failed to create JWT without exp claim: %v", err)
		}

		builder := newDraft24RequestBuilder()
		builder = builder.WithRequestObject(noExpJWT)

		req, err := builder.Build()
		if err != nil {
			t.Errorf("Expected no error for JWT without exp claim, got: %v", err)
		}
		if req == nil {
			t.Error("Expected valid request object, got nil")
		}
	})
}

// Additional validations for query params and builder flows
func TestOid4vpPresenter_ParsePresentationRequest_QueryParamValidations(t *testing.T) {
	p := &Oid4vpPresenter{PreRegisteredClients: map[string]PreRegisteredClient{
		"registered-client": {},
	}}

	p.AllowHTTP = false

	tests := []struct {
		name    string
		uri     string
		wantErr bool
		errSub  string
	}{
		{
			name:    "Missing required params",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb", // missing response_type, nonce, dcql_query, response_mode
			wantErr: true,
			errSub:  "missing required parameters",
		},
		{
			name:    "Multiple values for a single key should error",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment",
			wantErr: true,
			errSub:  "multiple values provided for parameter: response_type",
		},
		// A redirect_uri Client Identifier supplies the Response URI itself
		// (OID4VP 1.0 §5.9.3), so the parameter is only required for a Client
		// Identifier that carries none: here a registered pre-registered one.
		{
			name:    "response_mode=direct_post requires response_uri",
			uri:     "openid4vp://present?client_id=registered-client&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post",
			wantErr: true,
			errSub:  "missing required parameters: response_uri",
		},
		{
			name:    "response_mode=direct_post rejects non-https response_uri",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/response&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&response_uri=http://example.com/response",
			wantErr: true,
			errSub:  "response_uri must use https scheme",
		},
		{
			name:    "presentation_definition is rejected",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&presentation_definition=%7B%22id%22%3A%22def%22%7D&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment",
			wantErr: true,
			errSub:  "presentation_definition is not supported",
		},
		{
			name:    "presentation_definition_uri is rejected",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&presentation_definition_uri=https://example.com/pd&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment",
			wantErr: true,
			errSub:  "presentation_definition_uri is not supported",
		},
		{
			name:    "presentation_submission is rejected",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&presentation_submission=%7B%7D&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment",
			wantErr: true,
			errSub:  "presentation_submission is not supported",
		},
		{
			name:    "non-empty scope is rejected with invalid_scope",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&scope=openid&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment",
			wantErr: true,
			errSub:  "invalid_scope",
		},
		{
			name:    "invalid dcql_query is rejected with invalid_request",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&dcql_query=%7B%22credentials%22%3A%5B%5D%7D&response_mode=fragment",
			wantErr: true,
			errSub:  "dcql_query.credentials must be a non-empty array",
		},
		// redirect_uri matches the client_id-derived value on purpose so the
		// mismatch check (redirectURIFromParam vs redirectURIFromClientID) does
		// not fire first and the new exclusivity check is exercised.
		{
			name:    "redirect_uri and response_uri must not coexist",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&redirect_uri=http://example.com/cb&response_uri=https://example.com/response",
			wantErr: true,
			errSub:  "redirect_uri and response_uri must not both be present",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ParsePresentationRequest(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Fatalf("wantErr=%v got err=%v", tt.wantErr, err)
			}
			if tt.wantErr && tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
				t.Fatalf("expected error to contain %q, got %v", tt.errSub, err)
			}
		})
	}
}

func TestOid4vpPresenter_ParsePresentationRequest_DirectPostJWTWithDCQL(t *testing.T) {
	p := &Oid4vpPresenter{}
	uri := "openid4vp://present?client_id=x509_hash:test-hash&response_type=vp_token&nonce=n&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22pid%22%2C%22format%22%3A%22dc%2Bsd-jwt%22%2C%22meta%22%3A%7B%22vct_values%22%3A%5B%22urn%3Aeudi%3Apid%3A1%22%5D%7D%2C%22claims%22%3A%5B%7B%22path%22%3A%5B%22given_name%22%5D%7D%5D%7D%5D%7D&response_mode=direct_post.jwt&response_uri=https://example.com/response"
	_, err := p.ParsePresentationRequest(uri)
	if !errors.Is(err, ErrRequestObjectSignatureRequired) {
		t.Fatalf("unsigned x509_hash must be rejected: %v", err)
	}
}

func TestOid4vpPresenter_SendsErrorAuthorizationResponse(t *testing.T) {
	p := &Oid4vpPresenter{AllowHTTP: true, SendParseErrorResponses: true}

	newErrorCapturingServer := func(t *testing.T) (*httptest.Server, *url.Values) {
		t.Helper()
		captured := &url.Values{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
			}
			*captured = r.PostForm
			w.WriteHeader(http.StatusOK)
		}))
		return server, captured
	}

	baseURI := func(responseURI, extraParams string) string {
		// OID4VP 1.0 §5.9.3 binds the Response URI of a direct_post request to
		// the redirect_uri Client Identifier, so both name the test server.
		return "openid4vp://present?client_id=" + url.QueryEscape("redirect_uri:"+responseURI) +
			"&response_type=vp_token&nonce=n&state=err-state&response_mode=direct_post&response_uri=" +
			url.QueryEscape(responseURI) + extraParams
	}

	tests := []struct {
		name        string
		extraParams string
		wantError   string
	}{
		{
			name:        "invalid dcql_query posts invalid_request",
			extraParams: "&dcql_query=%7B%22credentials%22%3A%5B%5D%7D",
			wantError:   "invalid_request",
		},
		{
			name:        "non-empty scope posts invalid_scope",
			extraParams: "&scope=openid&dcql_query=" + testDcqlQueryParam,
			wantError:   "invalid_scope",
		},
		{
			name:        "unsupported format posts vp_formats_not_supported",
			extraParams: "&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22c1%22%2C%22format%22%3A%22mso_mdoc%22%2C%22meta%22%3A%7B%7D%7D%5D%7D",
			wantError:   "vp_formats_not_supported",
		},
		{
			name:        "presentation_definition posts invalid_request",
			extraParams: "&presentation_definition=%7B%22id%22%3A%22def%22%7D&dcql_query=" + testDcqlQueryParam,
			wantError:   "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, captured := newErrorCapturingServer(t)
			defer server.Close()

			_, err := p.ParsePresentationRequest(baseURI(server.URL, tt.extraParams))
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if got := captured.Get("error"); got != tt.wantError {
				t.Fatalf("expected error %q to be posted, got %q", tt.wantError, got)
			}
			if captured.Get("error_description") == "" {
				t.Fatal("expected error_description to be posted")
			}
			if got := captured.Get("state"); got != "err-state" {
				t.Fatalf("expected state %q to be posted, got %q", "err-state", got)
			}
			if got := captured.Get("vp_token"); got != "" {
				t.Fatalf("expected no vp_token in error response, got %q", got)
			}
		})
	}

	t.Run("no error response without direct_post", func(t *testing.T) {
		server, captured := newErrorCapturingServer(t)
		defer server.Close()

		uri := "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&response_mode=fragment&dcql_query=%7B%22credentials%22%3A%5B%5D%7D"
		_, err := p.ParsePresentationRequest(uri)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if len(*captured) != 0 {
			t.Fatalf("expected no error response to be sent, got %v", *captured)
		}
	})

	// A Request Object's validation fails before its signature is verified,
	// so its response_uri is unauthenticated and must not receive the error
	// authorization response.
	t.Run("no error response for request object path", func(t *testing.T) {
		server, captured := newErrorCapturingServer(t)
		defer server.Close()

		verifierServer := mockserver.NewOID4VPVerifierServer(nil)
		defer verifierServer.Close()
		keyPair := verifierServer.GetKeyPair()

		claims := map[string]any{
			"aud":           "test-client",
			"nonce":         "n",
			"client_id":     "redirect_uri:http://example.com/cb",
			"response_type": "vp_token",
			"response_mode": "direct_post",
			"state":         "err-state",
			"dcql_query":    map[string]any{"credentials": []any{}},
			"response_uri":  server.URL,
			"client_metadata": map[string]any{
				"client_name": "Test Client",
				"jwks":        keyPair.CreateJWKS(),
			},
		}
		jwtStr, err := verifierServer.CreateSignedJWT(claims)
		if err != nil {
			t.Fatalf("failed to create signed JWT: %v", err)
		}

		_, err = p.ParsePresentationRequest("openid4vp://present?request=" + url.QueryEscape(jwtStr))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if len(*captured) != 0 {
			t.Fatalf("expected no error response for request object path, got %v", *captured)
		}
	})

	// Only the redirect_uri prefix binds the Response URI to the Client
	// Identifier (OID4VP 1.0 §5.9.3). Every other unsigned request names its
	// response_uri in parameters nothing authenticated, so a refusal of it is
	// never posted there, whichever check refuses it.
	for _, unbound := range []struct {
		name     string
		clientID string
		register bool
	}{
		{name: "missing client_id"},
		{name: "decentralized_identifier prefix", clientID: "decentralized_identifier:did:example:123"},
		{name: "registered pre-registered client", clientID: "registered-verifier", register: true},
	} {
		t.Run("no error response for an unbound response_uri: "+unbound.name, func(t *testing.T) {
			server, captured := newErrorCapturingServer(t)
			defer server.Close()

			presenter := &Oid4vpPresenter{AllowHTTP: true, SendParseErrorResponses: true}
			if unbound.register {
				presenter.PreRegisteredClients = map[string]PreRegisteredClient{unbound.clientID: {}}
			}
			query := url.Values{
				"response_type": {"vp_token"},
				"state":         {"err-state"},
				"response_mode": {"direct_post"},
				"response_uri":  {server.URL},
				// The empty credential list is refused as invalid_request.
				"dcql_query": {`{"credentials":[]}`},
				"nonce":      {"n"},
			}
			if unbound.clientID != "" {
				query.Set("client_id", unbound.clientID)
			}
			_, err := presenter.ParsePresentationRequest("openid4vp://present?" + query.Encode())
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if len(*captured) != 0 {
				t.Fatalf("expected no error response to an unbound response_uri, got %v", *captured)
			}
		})
	}

	t.Run("no error response unless the caller opts in; the refusal can be sent later", func(t *testing.T) {
		server, captured := newErrorCapturingServer(t)
		defer server.Close()

		presenter := &Oid4vpPresenter{AllowHTTP: true}
		_, err := presenter.ParsePresentationRequest(baseURI(server.URL, "&dcql_query=%7B%22credentials%22%3A%5B%5D%7D"))
		var authzErr *AuthorizationRequestError
		if !errors.As(err, &authzErr) || authzErr.Code != InvalidRequestError {
			t.Fatalf("expected the invalid_request refusal to be returned, got %v", err)
		}
		if len(*captured) != 0 {
			t.Fatalf("expected no error response to be sent, got %v", *captured)
		}
		if authzErr.ResponseURI() != server.URL {
			t.Fatalf("ResponseURI = %q, want %q", authzErr.ResponseURI(), server.URL)
		}
		if err := authzErr.SendErrorResponse(context.Background(), server.Client()); err != nil {
			t.Fatal(err)
		}
		if captured.Get("error") != "invalid_request" || captured.Get("state") != "err-state" {
			t.Fatalf("unexpected error response %v", *captured)
		}
	})

	t.Run("an unbound refusal has no Response URI to send to", func(t *testing.T) {
		query := url.Values{
			"client_id": {"decentralized_identifier:did:example:123"}, "response_type": {"vp_token"},
			"response_mode": {"direct_post"}, "response_uri": {"https://verifier.example/cb"},
			"dcql_query": {`{"credentials":[]}`}, "nonce": {"n"},
		}
		_, err := (&Oid4vpPresenter{}).ParsePresentationRequest("openid4vp://present?" + query.Encode())
		var authzErr *AuthorizationRequestError
		if errors.As(err, &authzErr) {
			if authzErr.ResponseURI() != "" {
				t.Fatalf("ResponseURI = %q, want none", authzErr.ResponseURI())
			}
			if !errors.Is(authzErr.SendErrorResponse(context.Background(), nil), ErrErrorResponseEndpointUnbound) {
				t.Fatal("SendErrorResponse must refuse an unbound refusal")
			}
		}
	})

	t.Run("send failure is reported alongside the original error", func(t *testing.T) {
		server, _ := newErrorCapturingServer(t)
		server.Close() // unreachable response_uri

		_, err := p.ParsePresentationRequest(baseURI(server.URL, "&dcql_query=%7B%22credentials%22%3A%5B%5D%7D"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid_request") {
			t.Fatalf("expected original error to be preserved, got: %v", err)
		}
		if !strings.Contains(err.Error(), "failed to send error authorization response") {
			t.Fatalf("expected send failure to be reported, got: %v", err)
		}
	})
}

func TestOid4vpPresenter_ParsePresentationRequest_AllowsNonHTTPSResponseURI_WhenValidationDisabled(t *testing.T) {
	p := &Oid4vpPresenter{}

	p.AllowHTTP = true

	uri := "openid4vp://present?client_id=redirect_uri:http://example.com/response&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&response_uri=http://example.com/response"
	req, err := p.ParsePresentationRequest(uri)
	if err != nil {
		t.Fatalf("expected no error when HTTPS validation is disabled, got: %v", err)
	}
	if req == nil {
		t.Fatal("expected non-nil request")
	}
	if req.ResponseURI != "http://example.com/response" {
		t.Fatalf("expected response_uri to be preserved, got: %s", req.ResponseURI)
	}
}

func TestOid4vpPresenter_ClientIDParsingAndRedirectMismatch(t *testing.T) {
	p := &Oid4vpPresenter{}

	t.Run("Unsupported client_id prefix", func(t *testing.T) {
		uri := "openid4vp://present?client_id=openid_federationx:http://example.com/cb&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment"
		_, err := p.ParsePresentationRequest(uri)
		if err == nil {
			t.Fatal("expected error for unsupported client_id prefix")
		}
		if !strings.Contains(err.Error(), `client_id prefix "openid_federationx" is not a supported Client Identifier Prefix`) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("client_id prefix 'origin' is not allowed", func(t *testing.T) {
		uri := "openid4vp://present?client_id=origin:http://example.com/cb&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment"
		_, err := p.ParsePresentationRequest(uri)
		if err == nil {
			t.Fatal("expected error for forbidden 'origin' prefix")
		}
		if !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("redirect_uri mismatch with client_id-derived redirect", func(t *testing.T) {
		// client_id derives redirect_uri=http://a.example, but explicit redirect_uri differs
		uri := "openid4vp://present?client_id=redirect_uri:http://a.example/cb&redirect_uri=http://b.example/cb&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment"
		_, err := p.ParsePresentationRequest(uri)
		if err == nil {
			t.Fatal("expected mismatch error")
		}
		if !strings.Contains(err.Error(), "redirect_uri mismatch") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("client_id with duplicate prefix", func(t *testing.T) {
		// Duplicate prefix: x509_san_dns:x509_san_dns:demo.example.com
		uri := "openid4vp://present?client_id=x509_san_dns:x509_san_dns:demo.example.com&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment"
		_, err := p.ParsePresentationRequest(uri)
		if err == nil {
			t.Fatal("expected error for duplicate prefix in client_id")
		}
		if !strings.Contains(err.Error(), "duplicate prefix") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("client_id with trailing whitespace", func(t *testing.T) {
		// Trailing whitespace should be trimmed
		uri := "openid4vp://present?client_id=redirect_uri:https://example.com/cb%20&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&response_uri=https://example.com/cb"
		req, err := p.ParsePresentationRequest(uri)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should successfully parse after trimming
		if req.ClientID != "redirect_uri:https://example.com/cb" {
			t.Fatalf("expected trimmed client_id, got: %s", req.ClientID)
		}
	})
}

func TestOid4vpPresenter_UnsupportedRequestURIMethod(t *testing.T) {
	p := &Oid4vpPresenter{}
	uri := "openid4vp://present?client_id=redirect_uri:http://example.com/cb&request_uri=https://req.obj/jwt&request_uri_method=PUT"
	_, err := p.ParsePresentationRequest(uri)
	if err == nil {
		t.Fatal("expected error for unsupported request_uri_method")
	}
	if !strings.Contains(err.Error(), "invalid_request_uri_method") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOid4vpPresenter_ClientMetadataParsing_And_ResponseModeConstraint(t *testing.T) {
	// invalid client_metadata shapes when provided directly via query params path
	p := &Oid4vpPresenter{}

	t.Run("client_metadata invalid JSON string", func(t *testing.T) {
		uri := "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment&client_metadata={invalid}"
		_, err := p.ParsePresentationRequest(uri)
		if err == nil {
			t.Fatal("expected error for invalid client_metadata JSON")
		}
		if !strings.Contains(err.Error(), "invalid client_metadata") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("client_metadata wrong type (number)", func(t *testing.T) {
		// numbers will be treated as string via fmt, but setParams path expects string or map; simulate map path by percent-encoding a JSON number
		uri := "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=fragment&client_metadata=1"
		_, err := p.ParsePresentationRequest(uri)
		if err == nil {
			t.Fatal("expected error for invalid client_metadata type")
		}
		if !strings.Contains(err.Error(), "invalid client_metadata") && !strings.Contains(err.Error(), "must be a string or map") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestOid4vpPresenter_Draft24_RequestParameterJWT_Success(t *testing.T) {
	// Setup mock verifier server with proper JWT signing
	verifierServer := mockserver.NewOID4VPVerifierServer(nil)
	defer verifierServer.Close()

	// Create client_metadata with JWKS for JWT verification
	keyPair := verifierServer.GetKeyPair()
	clientMetadata := map[string]any{
		"client_name": "Test Client",
		"jwks":        keyPair.CreateJWKS(),
	}

	// claims inside request parameter
	claims := map[string]any{
		"aud":           "test-client",
		"nonce":         "test-nonce",
		"client_id":     "redirect_uri:https://example.com/response",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"state":         "test-state",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{"id": "cred1", "format": "jwt_vc_json", "meta": map[string]any{"type_values": []any{[]any{"VerifiableCredential"}}}},
			},
		},
		"response_uri":    "https://example.com/response",
		"client_metadata": clientMetadata,
	}

	jwtStr, err := verifierServer.CreateSignedJWT(claims)
	if err != nil {
		t.Fatalf("failed to create signed JWT: %v", err)
	}

	uri := "openid4vp://present?request=" + url.QueryEscape(jwtStr)

	p := &Oid4vpPresenter{}
	req, err := parseDraft24ForTest(p, uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req == nil || req.ClientID == "" || req.DcqlQuery == nil {
		t.Fatalf("expected populated request from 'request' param")
	}
}

// x509_san_dns branch tests
func TestOid4vpPresenter_Draft24_RequestObject_WithX5C_X509SanDNS_SuccessAndFailures(t *testing.T) {
	// A CA-issued leaf certificate with the SAN DNS name; the CA is the anchor.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Verifier CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "verifier.example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"verifier.example.org"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Build JWT with x5c header and claims for x509_san_dns
	claims := map[string]any{
		"aud":           "test-client",
		"nonce":         "n",
		"client_id":     "x509_san_dns:verifier.example.org",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"state":         "s",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{"id": "cred1", "format": "jwt_vc_json", "meta": map[string]any{"type_values": []any{[]any{"VerifiableCredential"}}}},
			},
		},
		"response_uri": "https://verifier.example.org/response",
	}

	signerOpts := &jose.SignerOptions{}
	signerOpts = signerOpts.WithType("oauth-authz-req+jwt").WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(der)})
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, signerOpts)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	jwtStr, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to sign jwt: %v", err)
	}

	// Success: SAN matches client_id and response_uri host
	builder := newDraft24RequestBuilder()
	builder.x509TrustChainRoots = pool
	builder = builder.WithRequestObject(jwtStr)
	if _, err := builder.Build(); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	// Failure: SAN mismatch with client_id
	claims["client_id"] = "x509_san_dns:other.example.org"
	signerOpts2 := &jose.SignerOptions{}
	signerOpts2 = signerOpts2.WithType("oauth-authz-req+jwt").WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(der)})
	signer2, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, signerOpts2)
	badJWT1, _ := jwt.Signed(signer2).Claims(claims).Serialize()
	b := newDraft24RequestBuilder()
	b.x509TrustChainRoots = pool
	b = b.WithRequestObject(badJWT1)
	if _, err := b.Build(); err == nil || !strings.Contains(err.Error(), "SAN") {
		t.Fatalf("expected SAN mismatch error, got: %v", err)
	}

	// Failure: response_uri hostname mismatch
	claims["client_id"] = "x509_san_dns:verifier.example.org"
	claims["response_uri"] = "https://another.example.org/resp"
	signerOpts3 := &jose.SignerOptions{}
	signerOpts3 = signerOpts3.WithType("oauth-authz-req+jwt").WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(der)})
	signer3, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, signerOpts3)
	badJWT2, _ := jwt.Signed(signer3).Claims(claims).Serialize()
	b2 := newDraft24RequestBuilder()
	b2.x509TrustChainRoots = pool
	b2 = b2.WithRequestObject(badJWT2)
	if _, err := b2.Build(); err == nil || !strings.Contains(err.Error(), "client_id (origin) must be same") {
		t.Fatalf("expected hostname mismatch error, got: %v", err)
	}
}

func TestOid4vpPresenter_RequestObject_WithX5C_X509Hash(t *testing.T) {
	f := newRequestObjectFixture(t)
	priv := f.key
	der := f.leaf.Raw
	clientID := f.clientID()
	claims := map[string]any{
		"aud":             "https://self-issued.me/v2",
		"nonce":           "n",
		"client_id":       clientID,
		"response_type":   "vp_token",
		"response_mode":   "direct_post.jwt",
		"response_uri":    "https://example.org/response",
		"client_metadata": responseEncryptionClientMetadataClaim(),
		"dcql_query": map[string]any{
			"credentials": []map[string]any{
				{
					"id":     "pid",
					"format": "dc+sd-jwt",
					"meta": map[string]any{
						"vct_values": []string{"urn:eudi:pid:1"},
					},
					"claims": []map[string]any{
						{"path": []string{"account_number"}, "values": []any{int64(9007199254740993)}},
					},
				},
			},
		},
	}
	signerOpts := (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt").WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(der)})
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, signerOpts)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	jwtStr, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to sign jwt: %v", err)
	}

	builder := NewRequestBuilder().WithRequestObjectValidation(f.options())
	builder.httpClient = f.server.Client()
	builder.expectedClientID = clientID
	builder = builder.WithRequestObject(jwtStr)
	req, err := builder.Build()
	if err != nil {
		t.Fatalf("expected x509_hash request object to verify, got %v", err)
	}
	if req.DcqlQuery == nil || req.DcqlQuery.Credentials[0].ID != "pid" {
		t.Fatalf("expected DCQL query to be parsed, got %#v", req.DcqlQuery)
	}

	if value := req.DcqlQuery.Credentials[0].Claims[0].Values[0]; value != json.Number("9007199254740993") {
		t.Fatalf("signed Request Object rounded a DCQL integer: %#v", value)
	}

	builder = NewRequestBuilder().WithRequestObjectValidation(f.options())
	builder.httpClient = f.server.Client()
	builder.expectedClientID = "x509_hash:wrong"
	builder = builder.WithRequestObject(jwtStr)
	if _, err := builder.Build(); err == nil || !strings.Contains(err.Error(), "outer client_id does not match") {
		t.Fatalf("expected outer client_id mismatch, got %v", err)
	}

	claims["client_id"] = "x509_hash:wrong"
	badJWT, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to sign bad jwt: %v", err)
	}
	builder = NewRequestBuilder().WithRequestObjectValidation(f.options())
	builder.httpClient = f.server.Client()
	builder.expectedClientID = "x509_hash:wrong"
	builder = builder.WithRequestObject(badJWT)
	if _, err := builder.Build(); err == nil || !strings.Contains(err.Error(), "x509_hash client_id mismatch") {
		t.Fatalf("expected x509_hash mismatch, got %v", err)
	}
}

func Test_requestBuilder_WithRequestObjectURI(t *testing.T) {
	// mockserver is HTTP-only; allow http scheme for these tests.

	t.Run("Delete default User-Agent header (GET)", func(t *testing.T) {
		m := mockserver.NewMockServer()
		defer m.Close()

		called := false

		m.HandleFunc("/request-object", func(w http.ResponseWriter, r *http.Request) {
			called = true
			if ua := r.Header.Get("User-Agent"); ua != "" {
				t.Errorf("User-Agent is not empty string, got %q", ua)
			}
			w.WriteHeader(http.StatusOK)
		})

		requestObjectURI, _ := url.Parse(m.URL() + "/request-object")

		rb := NewRequestBuilder().WithHTTPAllowed(true)
		rb.WithRequestObjectURI(requestObjectURI.String(), RequestURIMethodGET)
		if !called {
			t.Fatal("handler was not invoked")
		}
	})

	t.Run("Delete default User-Agent header (POST)", func(t *testing.T) {
		m := mockserver.NewMockServer()
		defer m.Close()

		called := false

		m.HandleFunc("/request-object", func(w http.ResponseWriter, r *http.Request) {
			called = true
			if ua := r.Header.Get("User-Agent"); ua != "" {
				t.Errorf("User-Agent is not empty string, got %q", ua)
			}
			if got := r.Header.Get("Accept"); got != "application/oauth-authz-req+jwt, application/jwt, text/plain, */*" {
				t.Errorf("unexpected Accept header: %q", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
				t.Errorf("unexpected Content-Type header: %q", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse form: %v", err)
			}
			if got := r.Form.Get("wallet_metadata"); got != "{}" {
				t.Errorf("unexpected wallet_metadata body value: %q", got)
			}
			w.WriteHeader(http.StatusOK)
		})

		requestObjectURI, _ := url.Parse(m.URL() + "/request-object")

		rb := newDraft24RequestBuilder()
		rb.allowHTTP = true
		rb.WithRequestObjectURI(requestObjectURI.String(), RequestURIMethodPOST)
		if !called {
			t.Fatal("handler was not invoked")
		}
	})

	// OID4VP draft 24 §5.11: POST request must set the prescribed
	// Content-Type and Accept headers.
	t.Run("POST sets Content-Type and Accept headers", func(t *testing.T) {
		m := mockserver.NewMockServer()
		defer m.Close()

		var gotContentType, gotAccept string
		m.HandleFunc("/request-object", func(w http.ResponseWriter, r *http.Request) {
			gotContentType = r.Header.Get("Content-Type")
			gotAccept = r.Header.Get("Accept")
			w.WriteHeader(http.StatusOK)
		})

		requestObjectURI, _ := url.Parse(m.URL() + "/request-object")

		rb := NewRequestBuilder().WithHTTPAllowed(true)
		rb.WithRequestObjectURI(requestObjectURI.String(), RequestURIMethodPOST)

		if gotContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", gotContentType)
		}
		if gotAccept != "application/oauth-authz-req+jwt" {
			t.Errorf("Accept = %q, want application/oauth-authz-req+jwt", gotAccept)
		}
	})

	// OID4VP draft 24 §5.11: request_uri must use the https scheme.
	// A fresh builder rejects HTTP by default.
	t.Run("rejects http scheme when HTTP policy is false (GET)", func(t *testing.T) {

		rb := requestBuilder{}
		rb.WithRequestObjectURI("http://example.com/request-object", RequestURIMethodGET)
		if rb.errValidation == nil || !strings.Contains(rb.errValidation.Error(), "https required") {
			t.Fatalf("expected https-required error, got: %v", rb.errValidation)
		}
	})

	t.Run("rejects http scheme when HTTP policy is false (POST)", func(t *testing.T) {

		rb := requestBuilder{}
		rb.WithRequestObjectURI("http://example.com/request-object", RequestURIMethodPOST)
		if rb.errValidation == nil || !strings.Contains(rb.errValidation.Error(), "https required") {
			t.Fatalf("expected https-required error, got: %v", rb.errValidation)
		}
	})

	// Non-http(s) schemes must be rejected regardless of HTTP policy.
	t.Run("rejects non-http(s) scheme even when HTTP policy is true", func(t *testing.T) {

		for _, badURI := range []string{
			"ftp://example.com/request-object",
			"file:///etc/passwd",
			"data:text/plain,foo",
		} {
			rb := NewRequestBuilder().WithHTTPAllowed(true)
			rb.WithRequestObjectURI(badURI, RequestURIMethodGET)
			if rb.errValidation == nil || !strings.Contains(rb.errValidation.Error(), "https required") {
				t.Errorf("uri=%q: expected https-required error, got: %v", badURI, rb.errValidation)
			}
		}
	})
}
