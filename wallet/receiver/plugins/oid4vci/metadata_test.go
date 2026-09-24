package oid4vci

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// Existing tests

func TestOid4vciReceiver_FetchIssuerMetadata(t *testing.T) {

	// Create mock OID4VCI issuer server
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL())
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = false

		_, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
		if err == nil {
			t.Fatal("FetchIssuerMetadata should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}
		_, err := receiver.FetchIssuerMetadata(common.URIField{}, types.SupportedReceivingTypes(999))
		if err == nil {
			t.Fatal("Expected error for unsupported receiving type")
		}
	})

	t.Run("Server error", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		var metadata types.CredentialIssuerMetadata
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
		// §12.2.4 makes credential_issuer identical to the requested identifier,
		// which drops the endpoint's trailing slash.
		metadata.CredentialIssuer = server.URL + "/"

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		var metadata types.CredentialIssuerMetadata
		// Use a raw handler to bypass ServeMux's automatic path cleaning and redirects
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.RequestURI, "//") {
				http.Error(w, "Double slash detected: "+r.RequestURI, http.StatusBadRequest)
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, metadata)
		}))
		defer server.Close()
		// §12.2.4 makes credential_issuer identical to the requested identifier,
		// which drops the endpoint's trailing slash.
		metadata.CredentialIssuer = server.URL + "/issuer/"

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

// OpenID4VCI 1.0 §12.2.4: "The value MUST be identical to the Credential
// Issuer's identifier value into which the well-known URI string was inserted
// to create the URL used to retrieve the metadata. If these values are not
// identical (when compared using a simple string comparison with no
// normalization), the data contained in the response MUST NOT be used." These
// cases drive the mock issuer's configurable identifier.
func TestOid4vciReceiver_FetchIssuerMetadataCredentialIssuerIdentity(t *testing.T) {
	t.Run("exact match is accepted", func(t *testing.T) {
		issuer := mockserver.NewOID4VCIIssuerServer(nil)
		defer issuer.Close()

		receiver := &Oid4vciReceiver{AllowHTTP: true}
		metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, issuer.URL()), types.Oid4vci)
		require.NoError(t, err)
		require.Equal(t, issuer.IssuerIdentifier(), metadata.CredentialIssuer)
	})

	t.Run("a different credential_issuer is rejected", func(t *testing.T) {
		config := mockserver.DefaultOID4VCIIssuerConfig()
		config.CredentialIssuerIdentifier = "https://other-issuer.example"
		issuer := mockserver.NewOID4VCIIssuerServer(config)
		defer issuer.Close()

		receiver := &Oid4vciReceiver{AllowHTTP: true}
		metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, issuer.URL()), types.Oid4vci)
		require.ErrorIs(t, err, ErrIssuerIdentifierMismatch)
		require.Nil(t, metadata)
	})

	t.Run("a trailing-slash difference is rejected", func(t *testing.T) {
		config := mockserver.DefaultOID4VCIIssuerConfig()
		issuer := mockserver.NewOID4VCIIssuerServer(config)
		defer issuer.Close()
		// The requested identifier has no trailing slash; the document names
		// the same characters plus one, which the no-normalization rule makes a
		// different identifier.
		config.CredentialIssuerIdentifier = issuer.URL() + "/"

		receiver := &Oid4vciReceiver{AllowHTTP: true}
		metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, issuer.URL()), types.Oid4vci)
		require.ErrorIs(t, err, ErrIssuerIdentifierMismatch)
		require.Nil(t, metadata)
	})
}

func TestOid4vciReceiver_FetchAuthorizationServerMetadata(t *testing.T) {
	// Create mock OID4VCI issuer server (which also serves auth server metadata)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	serverURL, _ := url.Parse(issuer.URL())
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = false

		_, err := receiver.FetchAuthorizationServerMetadata(endpoint, types.Oid4vci)
		if err == nil {
			t.Fatal("FetchAuthorizationServerMetadata should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

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
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

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
			expectedPath: "/.well-known/oauth-authorization-server/tenant1",
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

	receiver.AllowHTTP = true

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tt.expectedPath {
					// The credential_issuer must be byte-identical to the
					// identifier the wallet requested (VCI 1.0 §12.2.4): the
					// request origin with the well-known prefix removed and any
					// trailing slash kept.
					// RFC 8414 §3.3 holds the authorization server issuer
					// to the same rule.
					credentialIssuer := "http://" + r.Host + tt.identifier
					mockserver.JSONResponse(w, http.StatusOK, map[string]string{
						"issuer":            credentialIssuer,
						"credential_issuer": credentialIssuer,
					})
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
