package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// testDcqlQueryParam is the URL-encoded form of
// {"credentials":[{"id":"cred1","format":"jwt_vc_json","meta":{}}]}
// for use in query-parameter style presentation request URIs.
const testDcqlQueryParam = "%7B%22credentials%22%3A%5B%7B%22id%22%3A%22cred1%22%2C%22format%22%3A%22jwt_vc_json%22%2C%22meta%22%3A%7B%7D%7D%5D%7D"

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

	// vp_token must be a JSON object keyed by the DCQL Credential Query id, and
	// presentation_submission must not be sent.
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

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse URL '%s': %v", rawURL, err)
	}
	return u
}

// signedRequestObjectHost is the dNSName the helper below puts in the certificate and
// in the client_id, so a request object it signs authenticates as x509_san_dns:<host>.
const signedRequestObjectHost = "verifier.example.org"

// newSignedRequestObject builds a request object the wallet can authenticate: signed
// with a self-signed certificate whose dNSName SAN matches the x509_san_dns client_id.
// This is the only shape a signed request object can take, because every other Client
// Identifier Prefix leaves the wallet without a trusted key (OID4VP 1.0 Section 5.9.3).
// Callers override or add claims through extra.
//
// The returned pool trusts the signing certificate, for the tests that exercise real
// chain verification. Tests that skip verification discard it.
func newSignedRequestObject(t *testing.T, extra map[string]any) (string, *x509.CertPool) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{signedRequestObjectHost},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	trustPool := x509.NewCertPool()
	trustPool.AddCert(cert)

	signerOpts := (&jose.SignerOptions{}).
		WithType("oauth-authz-req+jwt").
		WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(der)})
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, signerOpts)
	require.NoError(t, err)

	claims := map[string]any{
		"client_id":     "x509_san_dns:" + signedRequestObjectHost,
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"response_uri":  "https://" + signedRequestObjectHost + "/response",
		"nonce":         "test-nonce",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "pid_credential",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
				},
			},
		},
	}
	for k, v := range extra {
		claims[k] = v
	}

	obj, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return obj, trustPool
}

// newSignedRequestObjectPresenter returns a presenter wired the way the conformance
// runner is: the certificate has no public trust anchor, so the chain is parsed
// rather than verified.
func newSignedRequestObjectPresenter() *Oid4vpPresenter {
	return &Oid4vpPresenter{InsecureSkipX509Verify: true}
}

// buildSignedRequestObject runs a request object through the builder with the same
// wiring as newSignedRequestObjectPresenter, for the tests that drive the builder
// directly instead of going through ParsePresentationRequest.
func buildSignedRequestObject(requestObject string) (*CredentialPresentationRequest, error) {
	builder := NewRequestBuilder()
	builder.insecureSkipX509Verify = true
	return builder.WithRequestObject(requestObject).Build()
}

func TestOid4vpPresenter_ParsePresentationRequest(t *testing.T) {
	// mockserver / httptest.NewServer use http; allow it for these tests.
	t.Setenv(env.HTTP_ALLOWED.String(), "true")

	// The request_uri cases serve a request object the wallet can authenticate, which
	// means x509_san_dns: no other prefix gives it a trusted verification key.
	mockJWT, _ := newSignedRequestObject(t, map[string]any{"state": "test-state"})

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
			uri:     "openid4vp:?client_id=redirect_uri:http://example.com/callback&response_type=vp_token&nonce=test-nonce&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&response_uri=https://example.com/response",
			setup:   nil,
			wantErr: false,
		},
		{
			name:    "Query parameters",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/callback&response_type=vp_token&nonce=test-nonce&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&response_uri=https://example.com/response",
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
				signedClientID := "x509_san_dns:" + signedRequestObjectHost
				switch tt.name {
				case "request_uri with default GET method":
					uri = "openid4vp://present?client_id=" + signedClientID + "&request_uri=" + server.URL
				case "request_uri with explicit GET method":
					uri = "openid4vp://present?client_id=" + signedClientID + "&request_uri=" + server.URL + "&request_uri_method=GET"
				case "request_uri with POST method":
					uri = "openid4vp://present?client_id=" + signedClientID + "&request_uri=" + server.URL + "&request_uri_method=POST"
				case "request_uri server error":
					uri = "openid4vp://present?client_id=" + signedClientID + "&request_uri=" + server.URL
				}
			}

			p := newSignedRequestObjectPresenter()
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

	// Only the signing key is taken from the mock server: the two failing subtests are
	// rejected on the typ header, before any claim or key in client_metadata is read.
	keyPair := verifierServer.GetKeyPair()

	// Create test claims
	testClaims := map[string]any{
		"aud":           "test-client",
		"nonce":         "test-nonce",
		"client_id":     "redirect_uri:http://example.com/callback",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"state":         "test-state",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{"id": "cred1", "format": "jwt_vc_json", "meta": map[string]any{}},
			},
		},
		"response_uri": "https://example.com/response",
	}

	t.Run("Valid 'typ' header should succeed", func(t *testing.T) {
		// The helper sets the typ header, and signs the way a request object has to be
		// signed to be authenticated at all (x509_san_dns with an x5c chain).
		requestObject, _ := newSignedRequestObject(t, nil)
		req, err := buildSignedRequestObject(requestObject)
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
	t.Run("JWT with 'iss' claim should be processed correctly", func(t *testing.T) {
		// 'iss' must be ignored even when it disagrees with client_id (OID4VP 1.0
		// Section 5).
		requestObject, _ := newSignedRequestObject(t, map[string]any{
			"iss":   "should-be-ignored",
			"state": "test-state",
		})

		req, err := buildSignedRequestObject(requestObject)
		if err != nil {
			t.Fatalf("Expected no error when 'iss' claim is present, got: %v", err)
		}
		if req == nil {
			t.Fatalf("Expected valid request object, got nil")
		}

		// Verify that other claims were processed correctly
		if want := "x509_san_dns:" + signedRequestObjectHost; req.ClientID != want {
			t.Fatalf("Expected ClientID %q, got: %s", want, req.ClientID)
		}
		if req.ResponseType != "vp_token" {
			t.Fatalf("Expected ResponseType 'vp_token', got: %s", req.ResponseType)
		}
	})
}

// TestOid4vpPresenter_WithRequestObject_StandardClaimsValidation tests standard JWT claims validation
func TestOid4vpPresenter_WithRequestObject_StandardClaimsValidation(t *testing.T) {
	// Signed request objects are only authenticated through x509_san_dns, so the time
	// claims are exercised on that path.
	newWithTimeClaims := func(iat, exp int64) string {
		requestObject, _ := newSignedRequestObject(t, map[string]any{
			"iat":   iat,
			"exp":   exp,
			"state": "test-state",
		})
		return requestObject
	}

	t.Run("Valid time claims should succeed", func(t *testing.T) {
		now := time.Now()
		req, err := buildSignedRequestObject(newWithTimeClaims(now.Unix(), now.Add(time.Hour).Unix()))
		if err != nil {
			t.Errorf("Expected no error with valid time claims, got: %v", err)
		}
		if req == nil {
			t.Error("Expected valid request object, got nil")
		}
	})

	t.Run("Expired JWT should fail", func(t *testing.T) {
		now := time.Now()
		expiredJWT := newWithTimeClaims(
			now.Add(-2*time.Hour).Unix(), // issued 2 hours ago
			now.Add(-time.Hour).Unix(),   // expired 1 hour ago
		)

		_, err := buildSignedRequestObject(expiredJWT)
		if err == nil {
			t.Error("Expected error for expired JWT, got nil")
		}
		if !strings.Contains(err.Error(), "JWT standard claims validation failed") {
			t.Errorf("Expected error message about JWT claims validation, got: %v", err)
		}
	})

	t.Run("Future iat claim should fail", func(t *testing.T) {
		now := time.Now()
		futureIatJWT := newWithTimeClaims(
			now.Add(time.Hour).Unix(),   // issued in the future
			now.Add(2*time.Hour).Unix(), // expires 2 hours from now
		)

		_, err := buildSignedRequestObject(futureIatJWT)
		if err == nil {
			t.Error("Expected error for future iat claim, got nil")
		}
		if !strings.Contains(err.Error(), "JWT standard claims validation failed") {
			t.Errorf("Expected error message about JWT claims validation, got: %v", err)
		}
	})

	t.Run("JWT without exp claim should succeed with leeway", func(t *testing.T) {
		noExpJWT, _ := newSignedRequestObject(t, map[string]any{"state": "test-state"})

		req, err := buildSignedRequestObject(noExpJWT)
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
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(false)

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
		{
			name:    "response_mode=direct_post requires response_uri",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post",
			wantErr: true,
			errSub:  "missing required parameters: response_uri",
		},
		{
			name:    "response_mode=direct_post rejects non-https response_uri",
			uri:     "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&response_uri=http://example.com/response",
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

// When an Authorization Request is rejected with an OAuth error code and
// response_mode=direct_post, the wallet posts the error authorization response
// (error, error_description, state) to response_uri.
func TestOid4vpPresenter_SendsErrorAuthorizationResponse(t *testing.T) {
	t.Setenv(env.HTTP_ALLOWED.String(), "true")

	p := &Oid4vpPresenter{}

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
		return "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&state=err-state&response_mode=direct_post&response_uri=" +
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

		// A redirect_uri client_id leaves a signed request object unauthenticated, so
		// it is rejected with a code that would be deliverable on the query parameter
		// path. The response_uri it names must still not receive it.
		requestObject, _ := newSignedRequestObject(t, map[string]any{
			"client_id":    "redirect_uri:http://example.com/cb",
			"response_uri": server.URL,
			"state":        "err-state",
		})

		_, err := p.ParsePresentationRequest("openid4vp://present?request=" + url.QueryEscape(requestObject))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if len(*captured) != 0 {
			t.Fatalf("expected no error response for request object path, got %v", *captured)
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
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	uri := "openid4vp://present?client_id=redirect_uri:http://example.com/cb&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&response_uri=http://example.com/response"
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
		if !strings.Contains(err.Error(), "unsupported client_id prefix") {
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
		uri := "openid4vp://present?client_id=redirect_uri:http://example.com/cb%20&response_type=vp_token&nonce=n&dcql_query=" + testDcqlQueryParam + "&response_mode=direct_post&response_uri=https://example.com/cb"
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

func TestOid4vpPresenter_RequestParameterJWT_Success(t *testing.T) {
	// A request object passed inline still has to be authenticated, so it carries the
	// same x509_san_dns shape as one fetched from a request_uri.
	jwtStr, _ := newSignedRequestObject(t, map[string]any{"state": "test-state"})

	uri := "openid4vp://present?request=" + url.QueryEscape(jwtStr)

	p := newSignedRequestObjectPresenter()
	req, err := p.ParsePresentationRequest(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req == nil || req.ClientID == "" || req.DcqlQuery == nil {
		t.Fatalf("expected populated request from 'request' param")
	}
}

// TestOid4vpPresenter_RequestObject_RejectsSelfAssertedKey pins that a signed request
// object is refused when the Client Identifier Prefix gives the wallet no trusted key.
// It used to be accepted, verified with a key the request itself published in
// client_metadata.jwks, which OID4VP 1.0 Section 5.1 forbids and which authenticated
// nothing: signing with an attacker's key and publishing its public half passed.
func TestOid4vpPresenter_RequestObject_RejectsSelfAssertedKey(t *testing.T) {
	attacker, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	published := jose.JSONWebKey{Key: attacker.Public(), KeyID: "attacker", Algorithm: "ES256", Use: "sig"}
	signerOpts := (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt").WithHeader("kid", "attacker")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: attacker}, signerOpts)
	require.NoError(t, err)

	requestObject, err := jwt.Signed(signer).Claims(map[string]any{
		"client_id":     "redirect_uri:https://attacker.example/collect",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"response_uri":  "https://attacker.example/collect",
		"nonce":         "attacker-nonce",
		"dcql_query": map[string]any{
			"credentials": []any{
				map[string]any{
					"id":     "credential-request",
					"format": "dc+sd-jwt",
					"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
				},
			},
		},
		"client_metadata": map[string]any{
			"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{published}},
		},
	}).Serialize()
	require.NoError(t, err)

	_, err = buildSignedRequestObject(requestObject)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id prefix that names its verification key")
}

// TestOid4vpPresenter_RequestObject_WithX5C_X509SanDNS_SuccessAndFailures is the only
// test that verifies the x5c chain for real instead of skipping it, so it trusts the
// certificate the request object was signed with.
func TestOid4vpPresenter_RequestObject_WithX5C_X509SanDNS_SuccessAndFailures(t *testing.T) {
	build := func(extra map[string]any) error {
		requestObject, trustPool := newSignedRequestObject(t, extra)
		builder := NewRequestBuilder()
		builder.x509TrustChainRoots = trustPool
		_, err := builder.WithRequestObject(requestObject).Build()
		return err
	}

	// The SAN matches both the client_id and the response_uri host.
	require.NoError(t, build(nil))

	// The client_id must name a dNSName the leaf certificate carries.
	err := build(map[string]any{"client_id": "x509_san_dns:other.example.org"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SAN")

	// direct_post delivers the response to response_uri, so its host is bound too.
	err = build(map[string]any{"response_uri": "https://another.example.org/resp"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id (origin) must be same")

	// The same request object has to be accepted through the presenter, which is the
	// only way a caller reaches this path. The cases above set the builder field
	// directly, so they stay green even if the presenter stops handing its trust roots
	// over; with x509_san_dns now the only prefix a signed request object can use,
	// losing that one assignment would reject every signed request in production.
	requestObject, trustPool := newSignedRequestObject(t, nil)
	presented, err := (&Oid4vpPresenter{X509TrustChainRoots: trustPool}).
		ParsePresentationRequest("openid4vp://present?request=" + url.QueryEscape(requestObject))
	require.NoError(t, err)
	assert.Equal(t, "x509_san_dns:"+signedRequestObjectHost, presented.ClientID)
}

func Test_requestBuilder_WithRequestObjectURI(t *testing.T) {
	// mockserver is HTTP-only; allow http scheme for these tests.
	t.Setenv(env.HTTP_ALLOWED.String(), "true")

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

		rb := requestBuilder{}
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
			w.WriteHeader(http.StatusOK)
		})

		requestObjectURI, _ := url.Parse(m.URL() + "/request-object")

		rb := requestBuilder{}
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

		rb := requestBuilder{}
		rb.WithRequestObjectURI(requestObjectURI.String(), RequestURIMethodPOST)

		if gotContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", gotContentType)
		}
		if gotAccept != "application/oauth-authz-req+jwt" {
			t.Errorf("Accept = %q, want application/oauth-authz-req+jwt", gotAccept)
		}
	})

	// OID4VP draft 24 §5.11: request_uri must use the https scheme.
	// IsHTTPAllowed() short-circuits on DEBUG, so clear both env vars.
	t.Run("rejects http scheme when HTTP_ALLOWED is false (GET)", func(t *testing.T) {
		t.Setenv(env.HTTP_ALLOWED.String(), "")
		t.Setenv(env.DEBUG.String(), "")

		rb := requestBuilder{}
		rb.WithRequestObjectURI("http://example.com/request-object", RequestURIMethodGET)
		if rb.errValidation == nil || !strings.Contains(rb.errValidation.Error(), "https required") {
			t.Fatalf("expected https-required error, got: %v", rb.errValidation)
		}
	})

	t.Run("rejects http scheme when HTTP_ALLOWED is false (POST)", func(t *testing.T) {
		t.Setenv(env.HTTP_ALLOWED.String(), "")
		t.Setenv(env.DEBUG.String(), "")

		rb := requestBuilder{}
		rb.WithRequestObjectURI("http://example.com/request-object", RequestURIMethodPOST)
		if rb.errValidation == nil || !strings.Contains(rb.errValidation.Error(), "https required") {
			t.Fatalf("expected https-required error, got: %v", rb.errValidation)
		}
	})

	// Non-http(s) schemes must be rejected regardless of HTTP_ALLOWED.
	t.Run("rejects non-http(s) scheme even when HTTP_ALLOWED is true", func(t *testing.T) {
		t.Setenv(env.HTTP_ALLOWED.String(), "true")

		for _, badURI := range []string{
			"ftp://example.com/request-object",
			"file:///etc/passwd",
			"data:text/plain,foo",
		} {
			rb := requestBuilder{}
			rb.WithRequestObjectURI(badURI, RequestURIMethodGET)
			if rb.errValidation == nil || !strings.Contains(rb.errValidation.Error(), "https required") {
				t.Errorf("uri=%q: expected https-required error, got: %v", badURI, rb.errValidation)
			}
		}
	})
}

// TestConformanceShapeRequestURISignedDirectPost pins the combination the conformance test
// plan uses: client_id prefix x509_san_dns, a Request Object fetched from a request_uri, and
// response_mode direct_post.
func TestConformanceShapeRequestURISignedDirectPost(t *testing.T) {
	t.Setenv(env.HTTP_ALLOWED.String(), "true")

	requestObject, _ := newSignedRequestObject(t, map[string]any{
		"aud":   "https://self-issued.me/v2",
		"nonce": "conformance-nonce",
		"state": "conformance-state",
	})

	requestURIServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(requestObject))
	}))
	defer requestURIServer.Close()

	// Same wiring as examples/conformance_sdjwt.
	p := newSignedRequestObjectPresenter()
	req, err := p.ParsePresentationRequest(
		"openid4vp://authorize?client_id=x509_san_dns:" + signedRequestObjectHost +
			"&request_uri=" + url.QueryEscape(requestURIServer.URL),
	)
	require.NoError(t, err)

	assert.Equal(t, OAuthAuthzReqResponseModeDirectPost, req.ResponseMode)
	assert.Equal(t, "https://"+signedRequestObjectHost+"/response", req.ResponseURI)
	assert.Equal(t, "conformance-nonce", req.Nonce)
	assert.Equal(t, "conformance-state", req.State)
	require.NotNil(t, req.DcqlQuery)
	require.Len(t, req.DcqlQuery.Credentials, 1)
	assert.Equal(t, "pid_credential", req.DcqlQuery.Credentials[0].ID)
}

// transactionDataEntry encodes a transaction data object the way a request carries it.
func transactionDataEntry(t *testing.T, object map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(object)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// TestValidateTransactionData pins OID4VP 1.0 Section 5.1: a request carrying even one
// transaction data type the wallet does not support is refused, with the
// invalid_transaction_data code Section 8.5 defines. Nothing is presented.
func TestValidateTransactionData(t *testing.T) {
	req := func(entries ...string) *CredentialPresentationRequest {
		return &CredentialPresentationRequest{
			DcqlQuery:       &DcqlQuery{Credentials: []CredentialQuery{{ID: "pid_credential", Format: "dc+sd-jwt"}}},
			TransactionData: entries,
		}
	}
	supported := []string{"sample_type"}
	entry := func(object map[string]any) string { return transactionDataEntry(t, object) }
	referencingPID := map[string]any{"type": "sample_type", "credential_ids": []string{"pid_credential"}}

	t.Run("no transaction_data is nothing to check", func(t *testing.T) {
		assert.Nil(t, validateTransactionData(req(), nil))
	})

	t.Run("an unsupported type is refused", func(t *testing.T) {
		err := validateTransactionData(req(entry(map[string]any{"type": "unknown_type", "credential_ids": []string{"pid_credential"}})), supported)
		require.NotNil(t, err)
		assert.Equal(t, InvalidTransactionDataError, err.Code)
	})

	// The default configuration supports no type, so transaction_data is refused
	// outright until SupportedTransactionDataTypes names one.
	t.Run("every type is refused while none is supported", func(t *testing.T) {
		err := validateTransactionData(req(entry(referencingPID)), nil)
		require.NotNil(t, err)
		assert.Equal(t, InvalidTransactionDataError, err.Code)
	})

	t.Run("a supported type referencing the request is accepted", func(t *testing.T) {
		assert.Nil(t, validateTransactionData(req(entry(referencingPID)), supported))
	})

	t.Run("credential_ids must name a dc+sd-jwt Credential Query of the request", func(t *testing.T) {
		err := validateTransactionData(req(entry(map[string]any{"type": "sample_type", "credential_ids": []string{"other"}})), supported)
		require.NotNil(t, err)
		assert.Equal(t, InvalidTransactionDataError, err.Code)
	})

	t.Run("credential_ids is required", func(t *testing.T) {
		err := validateTransactionData(req(entry(map[string]any{"type": "sample_type"})), supported)
		require.NotNil(t, err)
		assert.Equal(t, InvalidTransactionDataError, err.Code)
	})

	t.Run("an entry that is not base64url is refused", func(t *testing.T) {
		err := validateTransactionData(req("not base64!"), supported)
		require.NotNil(t, err)
		assert.Equal(t, InvalidTransactionDataError, err.Code)
	})

	t.Run("an entry that is not a JSON object is refused", func(t *testing.T) {
		err := validateTransactionData(req(base64.RawURLEncoding.EncodeToString([]byte(`"a string"`))), supported)
		require.NotNil(t, err)
		assert.Equal(t, InvalidTransactionDataError, err.Code)
	})
}

// TestCheckTransactionDataFor pins that transaction data has to reference the
// Credential the wallet actually presents: the Wallet must use one of the referenced
// Credentials for transaction authorization (Sections 5.1 and 8.5).
func TestCheckTransactionDataFor(t *testing.T) {
	req := &CredentialPresentationRequest{TransactionData: []string{
		transactionDataEntry(t, map[string]any{"type": "sample_type", "credential_ids": []string{"pid_credential"}}),
	}}

	assert.Nil(t, req.CheckTransactionDataFor("pid_credential"))

	err := req.CheckTransactionDataFor("other_credential")
	require.NotNil(t, err)
	assert.Equal(t, InvalidTransactionDataError, err.Code)
}
