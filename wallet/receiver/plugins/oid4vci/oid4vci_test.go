package oid4vci

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/common"
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

	t.Run("Happy path", func(t *testing.T) {
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

	t.Run("Happy path", func(t *testing.T) {
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

	serverURL, _ := url.Parse(issuer.URL())
	endpoint := common.URIField(*serverURL)

	t.Run("Happy path", func(t *testing.T) {
		token, err := receiver.FetchAccessToken(types.Oid4vci, endpoint, "test-code")
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

	t.Run("Server error", func(t *testing.T) {
		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/token", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*errorURL), "test-code")
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/token", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.FetchAccessToken(types.Oid4vci, common.URIField(*invalidJSONURL), "test-code")
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})
}

func TestOid4vciReceiver_ReceiveCredential(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	accessToken := types.CredentialIssuanceAccessToken{Token: "test_token", TokenType: "bearer"}

	// Create mock OID4VCI issuer server (which serves credential endpoint)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL() + "/credential")
	endpoint := common.URIField(*serverURL)

	t.Run("Happy path", func(t *testing.T) {
		credential, err := receiver.ReceiveCredential(types.Oid4vci, endpoint, "jwt_vc_json", accessToken, nil, nil)
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

	t.Run("Server error", func(t *testing.T) {
		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/credential", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*errorURL), "jwt_vc_json", accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/credential", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*invalidJSONURL), "jwt_vc_json", accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})

	t.Run("No credential in response", func(t *testing.T) {
		noCredServer := mockserver.NewMockServer()
		defer noCredServer.Close()

		// Return valid JSON but without credential field
		noCredServer.SetJSONResponse("/credential", http.StatusOK, map[string]string{"status": "success"})

		noCredURL, _ := url.Parse(noCredServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*noCredURL), "jwt_vc_json", accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error when no credential is in the response")
		}
	})
}
