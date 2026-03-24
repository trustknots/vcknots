package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

func TestOid4vpPresenter_Present(t *testing.T) {
	testPresentation := []byte("a.valid.jwt")
	testSubmission := types.PresentationSubmission{
		ID:           "12345",
		DefinitionID: "example_jwt_vc",
		DescriptorMap: []types.DescriptorMapItem{
			{ID: "vp_token_jwt", Format: "jwt_vp_json", Path: "$"},
		},
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
			err := p.Present(tt.protocol, endpoint, tt.serializedPresentation, testSubmission, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("Oid4vpPresenter.Present() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
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
		err := p.Present(types.Oid4vp, *hijackURL, testPresentation, testSubmission, nil)

		if err == nil {
			t.Error("Expected error for hijacked connection, got nil")
		}
	})
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL '%s': %v", rawURL, err)
	}
	return u
}

func TestOid4vpPresenter_ParsePresentationRequest(t *testing.T) {
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
		"client_id":     "redirect_uri:http://example.com/callback",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"scope":         "openid",
		"state":         "test-state",
		"presentation_definition": map[string]any{
			"id": "test-def",
		},
		"redirect_uri":    "http://example.com/callback",
		"response_uri":    "http://example.com/response",
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
			name:    "Query parameters",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/callback&response_type=vp_token&nonce=test-nonce&presentation_definition=%7B%22id%22%3A%22test-def%22%7D&response_mode=direct_post&response_uri=http://example.com/response",
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
					uri = "openid4vp://present?client_id=redirect_uri:http://example.com/callback&request_uri=" + server.URL
				case "request_uri with explicit GET method":
					uri = "openid4vp://present?client_id=redirect_uri:http://example.com/callback&request_uri=" + server.URL + "&request_uri_method=GET"
				case "request_uri with POST method":
					uri = "openid4vp://present?client_id=redirect_uri:http://example.com/callback&request_uri=" + server.URL + "&request_uri_method=POST"
				case "request_uri server error":
					uri = "openid4vp://present?client_id=redirect_uri:http://example.com/callback&request_uri=" + server.URL
				}
			}

			p := &Oid4vpPresenter{}
			req, err := p.ParsePresentationRequest(uri)

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
		p := &Oid4vpPresenter{}
		_, err := p.ParsePresentationRequest("://invalid-uri")
		if err == nil {
			t.Error("Expected error for invalid URI, got nil")
		}
	})
}

// TestOid4vpPresenter_WithRequestObject_TypHeader tests 'typ' header validation
func TestOid4vpPresenter_WithRequestObject_TypHeader(t *testing.T) {
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
		"client_id":     "redirect_uri:http://example.com/callback",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"scope":         "openid",
		"state":         "test-state",
		"presentation_definition": map[string]any{
			"id": "test-def",
		},
		"redirect_uri":    "http://example.com/callback",
		"response_uri":    "http://example.com/response",
		"client_metadata": clientMetadata,
	}

	t.Run("Valid 'typ' header should succeed", func(t *testing.T) {
		// Create JWT with correct 'typ' header (done by mockserver by default)
		mockJWT, err := verifierServer.CreateSignedJWT(testClaims)
		if err != nil {
			t.Fatalf("Failed to create signed JWT: %v", err)
		}

		builder := NewRequestBuilder()
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

		builder := NewRequestBuilder()
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

		builder := NewRequestBuilder()
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
func TestOid4vpPresenter_WithRequestObject_IssClaimIgnored(t *testing.T) {
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
		"client_id":     "redirect_uri:http://example.com/callback",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"scope":         "openid",
		"state":         "test-state",
		"presentation_definition": map[string]any{
			"id": "test-def",
		},
		"redirect_uri":    "http://example.com/callback",
		"response_uri":    "http://example.com/response",
		"client_metadata": clientMetadata,
	}

	t.Run("JWT with 'iss' claim should be processed correctly", func(t *testing.T) {
		// Create JWT with 'iss' claim
		mockJWT, err := verifierServer.CreateSignedJWT(testClaims)
		if err != nil {
			t.Fatalf("Failed to create signed JWT: %v", err)
		}

		builder := NewRequestBuilder()
		builder = builder.WithRequestObject(mockJWT)

		req, err := builder.Build()
		if err != nil {
			t.Fatalf("Expected no error when 'iss' claim is present, got: %v", err)
		}
		if req == nil {
			t.Fatalf("Expected valid request object, got nil")
		}

		// Verify that other claims were processed correctly
		if req.ClientID != "redirect_uri:http://example.com/callback" {
			t.Fatalf("Expected ClientID 'redirect_uri:http://example.com/callback', got: %s", req.ClientID)
		}
		if req.ResponseType != "vp_token" {
			t.Fatalf("Expected ResponseType 'vp_token', got: %s", req.ResponseType)
		}
	})
}

// TestOid4vpPresenter_WithRequestObject_StandardClaimsValidation tests standard JWT claims validation
func TestOid4vpPresenter_WithRequestObject_StandardClaimsValidation(t *testing.T) {
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
			"client_id":     "redirect_uri:http://example.com/callback",
			"response_type": "vp_token",
			"response_mode": "direct_post",
			"scope":         "openid",
			"state":         "test-state",
			"presentation_definition": map[string]any{
				"id": "test-def",
			},
			"redirect_uri":    "http://example.com/callback",
			"response_uri":    "http://example.com/response",
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

		builder := NewRequestBuilder()
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

		builder := NewRequestBuilder()
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

		builder := NewRequestBuilder()
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
			"client_id":     "redirect_uri:http://example.com/callback",
			"response_type": "vp_token",
			"response_mode": "direct_post",
			"scope":         "openid",
			"state":         "test-state",
			"presentation_definition": map[string]any{
				"id": "test-def",
			},
			"redirect_uri":    "http://example.com/callback",
			"response_uri":    "http://example.com/response",
			"client_metadata": clientMetadata,
		}

		noExpJWT, err := verifierServer.CreateSignedJWT(testClaims)
		if err != nil {
			t.Fatalf("Failed to create JWT without exp claim: %v", err)
		}

		builder := NewRequestBuilder()
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
	p := &Oid4vpPresenter{}

	tests := []struct {
		name    string
		uri     string
		wantErr bool
		errSub  string
	}{
		{
			name:    "Missing required params",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb", // missing response_type, nonce, presentation_definition, response_mode
			wantErr: true,
			errSub:  "missing required parameters",
		},
		{
			name:    "Multiple values for a single key should error",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&response_type=vp_token&nonce=n&presentation_definition=%7B%22id%22%3A%22def%22%7D&response_mode=fragment",
			wantErr: true,
			errSub:  "multiple values provided for parameter: response_type",
		},
		{
			name:    "response_mode=direct_post requires response_uri",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&presentation_definition=%7B%22id%22%3A%22def%22%7D&response_mode=direct_post",
			wantErr: true,
			errSub:  "missing required parameters: response_uri",
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

func TestOid4vpPresenter_ClientIDParsingAndRedirectMismatch(t *testing.T) {
	p := &Oid4vpPresenter{}

	t.Run("Unsupported client_id prefix", func(t *testing.T) {
		uri := "openid4vp://present?client_id=openid_federationx:http://example.com/cb&response_type=vp_token&nonce=n&presentation_definition=%7B%22id%22%3A%22def%22%7D&response_mode=fragment"
		_, err := p.ParsePresentationRequest(uri)
		if err == nil {
			t.Fatal("expected error for unsupported client_id prefix")
		}
		if !strings.Contains(err.Error(), "unsupported client_id prefix") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("client_id prefix 'origin' is not allowed", func(t *testing.T) {
		uri := "openid4vp://present?client_id=origin:http://example.com/cb&response_type=vp_token&nonce=n&presentation_definition=%7B%22id%22%3A%22def%22%7D&response_mode=fragment"
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
		uri := "openid4vp://present?client_id=redirect_uri:http://a.example/cb&redirect_uri=http://b.example/cb&response_type=vp_token&nonce=n&presentation_definition=%7B%22id%22%3A%22def%22%7D&response_mode=fragment"
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
		uri := "openid4vp://present?client_id=x509_san_dns:x509_san_dns:demo.example.com&response_type=vp_token&nonce=n&presentation_definition=%7B%22id%22%3A%22def%22%7D&response_mode=fragment"
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
		uri := "openid4vp://present?client_id=redirect_uri:http://example.com/cb%20&response_type=vp_token&nonce=n&presentation_definition=%7B%22id%22%3A%22def%22%7D&response_mode=direct_post&response_uri=http://example.com/cb"
		req, err := p.ParsePresentationRequest(uri)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should successfully parse after trimming
		if req.ClientID != "redirect_uri:http://example.com/cb" {
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
	if !strings.Contains(err.Error(), "unsupported request_uri_method") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOid4vpPresenter_ClientMetadataParsing_And_ResponseModeConstraint(t *testing.T) {
	// invalid client_metadata shapes when provided directly via query params path
	p := &Oid4vpPresenter{}

	t.Run("client_metadata invalid JSON string", func(t *testing.T) {
		uri := "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&presentation_definition=%7B%22id%22%3A%22def%22%7D&response_mode=fragment&client_metadata={invalid}"
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
		uri := "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&presentation_definition=%7B%22id%22%3A%22def%22%7D&response_mode=fragment&client_metadata=1"
		_, err := p.ParsePresentationRequest(uri)
		if err == nil {
			t.Fatal("expected error for invalid client_metadata type")
		}
		if !strings.Contains(err.Error(), "invalid client_metadata") && !strings.Contains(err.Error(), "must be a string or map") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestOid4vpPresenter_RequestParameterJWT_Success(t *testing.T) {
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
		"client_id":     "redirect_uri:http://example.com/callback",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"scope":         "openid",
		"state":         "test-state",
		"presentation_definition": map[string]any{
			"id": "test-def",
		},
		"redirect_uri":    "http://example.com/callback",
		"response_uri":    "http://example.com/response",
		"client_metadata": clientMetadata,
	}

	jwtStr, err := verifierServer.CreateSignedJWT(claims)
	if err != nil {
		t.Fatalf("failed to create signed JWT: %v", err)
	}

	uri := "openid4vp://present?request=" + url.QueryEscape(jwtStr)

	p := &Oid4vpPresenter{}
	req, err := p.ParsePresentationRequest(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req == nil || req.ClientID == "" || req.PresentationDefinition == nil {
		t.Fatalf("expected populated request from 'request' param")
	}
}

// x509_san_dns branch tests
func TestOid4vpPresenter_RequestObject_WithX5C_X509SanDNS_SuccessAndFailures(t *testing.T) {
	// Generate a self-signed certificate with SAN DNS name
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"verifier.example.org"},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Trust pool containing our self-signed cert
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	// Build JWT with x5c header and claims for x509_san_dns
	claims := map[string]any{
		"aud":                     "test-client",
		"nonce":                   "n",
		"client_id":               "x509_san_dns:verifier.example.org",
		"response_type":           "vp_token",
		"response_mode":           "direct_post",
		"scope":                   "openid",
		"state":                   "s",
		"presentation_definition": map[string]any{"id": "def"},
		"response_uri":            "https://verifier.example.org/response",
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
	builder := NewRequestBuilder()
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
	b := NewRequestBuilder()
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
	b2 := NewRequestBuilder()
	b2.x509TrustChainRoots = pool
	b2 = b2.WithRequestObject(badJWT2)
	if _, err := b2.Build(); err == nil || !strings.Contains(err.Error(), "client_id (origin) must be same") {
		t.Fatalf("expected hostname mismatch error, got: %v", err)
	}
}
