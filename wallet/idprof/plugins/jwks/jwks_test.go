package jwks

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/trustknots/vcknots/wallet/idprof/types"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
)

func TestNewJWKSPlugin(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		jwksPlugin := NewJWKSPlugin()
		if jwksPlugin == nil {
			t.Fatalf("NewJWKSPlugin() returned nil")
		}
		if jwksPlugin.httpClient == nil {
			t.Fatalf("httpClient is nil")
		}
	})
}

func TestNewJWKSPluginWithClient(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		httpClient := http.Client{Timeout: 100 * time.Second}
		jwksPlugin, err := NewJWKSPluginWithClient(&httpClient)
		if err != nil {
			t.Fatalf("NewJWKSPluginWithClient() returned error")
		}
		if jwksPlugin == nil {
			t.Fatalf("NewJWKSPluginWithClient() returned nil")
		}
		if !reflect.DeepEqual(jwksPlugin.httpClient, &httpClient) {
			t.Fatalf("Generated plugin has different httpClient %v, expected: %v", jwksPlugin.httpClient, &httpClient)
		}
	})

	t.Run("httpClient is nil", func(t *testing.T) {
		_, err := NewJWKSPluginWithClient(nil)
		if err == nil {
			t.Errorf("NewJWKSPluginWithClient() should return error when httpClient is nil")
		}
	})
}

func TestCreate(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		jwksPlugin := NewJWKSPlugin()
		_, err := jwksPlugin.Create()
		if err == nil {
			t.Fatalf("Basically, JWK cannot be created")
		}
	})
}

func TestResolve(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v2/keys" {
			return
		}

		w.Write([]byte(`{"keys":[{"use":"sig","kty":"RSA","kid":"333882310849986562","alg":"RS256","n":"zleHTfhx7jOd6J3bNUjz76Gl-nutQroXzGyMtORKnfhj2mFfu2K2arFplMV7L7hK1Py-zvEcDncvk9Uo7DXitEP3OZnS9CdbmSQdMV8ok_zVKOU6LSZh2oGzFz423GWGmjxhZMqeWLtMzdaRNCzRfTrQtfEBnXCKSMc4dWlH54hWQlviCr3Mk0XJMSKrofk3EashMlNi0J-FRseKMaLMtLHi0RDfeOylT5aJfP9BEW33tCnyTdGtVwMjNq3EK5P4IIh1vQdn-1aB-omWznkHHUgeKPNcPOlHO8aThQKCjp4IofjnMwFxheL2gjxdWpk0djFSTPY_GWDAkyG7TqGXCw","e":"AQAB"},{"use":"sig","kty":"RSA","kid":"333996739130294274","alg":"RS256","n":"z72ahg8iWdCYS2yvvJHEOyL5Muz9Krza_yXMYwrJLEhQmI5TbruT87JEM757B821K726qf8owj-ub9p-4_qnCd-nU966dTVgKkSgnaYrdtm7YS63VzgQ51-2DgCASqV4zpSbVHlRBwGKGynV8lVIkbjg4hBCf-Nvm1nuqwxlggPTTPXIY-e9Y6T8GJhl1MxHRcCps3S0FLf5RvhHJ4z5sOUX8qu-jXa5zh5p28wn4hpLeq4cJdcz6yV8DXuzkJWVpkN_NavbcIfPeJFoNspMQLtNqPNmAapTOBmpwxkOBCPV73L49UZowzYexlb8-3BNiKS2JlxyrF5TZWTZGefHbQ","e":"AQAB"}]}`))
	}))
	invalidServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v2/keys" {
			return
		}

		w.Write([]byte(`thisisnotjwk`))
	}))
	defer server.Close()
	defer invalidServer.Close()

	t.Run("Normal case", func(t *testing.T) {
		jwksPlugin := NewJWKSPlugin()
		jwksURL := server.URL + "/oauth/v2/keys"
		profile, err := jwksPlugin.Resolve(jwksURL)
		if err != nil {
			t.Errorf("Failed to resolve JWKS")
		}
		if profile == nil {
			t.Errorf("Profile is nil")
		}
	})

	t.Run("Invalid URL", func(t *testing.T) {
		jwksPlugin := NewJWKSPlugin()
		_, err := jwksPlugin.Resolve("thisisnoturl")
		if err == nil {
			t.Errorf("Resole() should return error when the argument is not URL")
		}
	})

	t.Run("Invalid server", func(t *testing.T) {
		jwksPlugin := NewJWKSPlugin()
		jwksURL := invalidServer.URL + "/oauth/v2/keys"
		_, err := jwksPlugin.Resolve(jwksURL)
		if err == nil {
			t.Errorf("Resolve() should return error when failed to fetch")
		}
	})
}

func TestUpdate(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		jwksPlugin := NewJWKSPlugin()
		_, err := jwksPlugin.Update(nil)
		if err == nil {
			t.Fatalf("Basically, JWK cannot be created")
		}
	})
}

func TestValidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v2/keys" {
			return
		}

		w.Write([]byte(`{"keys":[{"use":"sig","kty":"RSA","kid":"333882310849986562","alg":"RS256","n":"zleHTfhx7jOd6J3bNUjz76Gl-nutQroXzGyMtORKnfhj2mFfu2K2arFplMV7L7hK1Py-zvEcDncvk9Uo7DXitEP3OZnS9CdbmSQdMV8ok_zVKOU6LSZh2oGzFz423GWGmjxhZMqeWLtMzdaRNCzRfTrQtfEBnXCKSMc4dWlH54hWQlviCr3Mk0XJMSKrofk3EashMlNi0J-FRseKMaLMtLHi0RDfeOylT5aJfP9BEW33tCnyTdGtVwMjNq3EK5P4IIh1vQdn-1aB-omWznkHHUgeKPNcPOlHO8aThQKCjp4IofjnMwFxheL2gjxdWpk0djFSTPY_GWDAkyG7TqGXCw","e":"AQAB"},{"use":"sig","kty":"RSA","kid":"333996739130294274","alg":"RS256","n":"z72ahg8iWdCYS2yvvJHEOyL5Muz9Krza_yXMYwrJLEhQmI5TbruT87JEM757B821K726qf8owj-ub9p-4_qnCd-nU966dTVgKkSgnaYrdtm7YS63VzgQ51-2DgCASqV4zpSbVHlRBwGKGynV8lVIkbjg4hBCf-Nvm1nuqwxlggPTTPXIY-e9Y6T8GJhl1MxHRcCps3S0FLf5RvhHJ4z5sOUX8qu-jXa5zh5p28wn4hpLeq4cJdcz6yV8DXuzkJWVpkN_NavbcIfPeJFoNspMQLtNqPNmAapTOBmpwxkOBCPV73L49UZowzYexlb8-3BNiKS2JlxyrF5TZWTZGefHbQ","e":"AQAB"}]}`))
	}))
	defer server.Close()

	t.Run("Normal case", func(t *testing.T) {
		jWKSPlugin := NewJWKSPlugin()
		jwksURL := server.URL + "/oauth/v2/keys"
		profile, err := jWKSPlugin.Resolve(jwksURL)
		if err != nil {
			t.Errorf("Failed to resolve JWKS")
		}

		err = jWKSPlugin.Validate(profile)
		if err != nil {
			t.Errorf("Failed to validate. error = %v", err)
		}
	})

	t.Run("Invalid profile", func(t *testing.T) {
		jWKSPlugin := NewJWKSPlugin()
		err := jWKSPlugin.Validate(nil)
		if err == nil {
			t.Errorf("Validate() should return error when profile is nil")
		}
	})

	t.Run("Different profile type", func(t *testing.T) {
		jWKSPlugin := NewJWKSPlugin()
		profile := types.IdentityProfile{ID: "hoge", TypeID: "fuga", Keys: nil}
		err := jWKSPlugin.Validate(&profile)
		if err == nil {
			t.Errorf("Validate() should return error when profile has invalid TypeID")
		}
	})

	t.Run("Profile key is nil", func(t *testing.T) {
		jWKSPlugin := NewJWKSPlugin()
		profile := types.IdentityProfile{ID: "hoge", TypeID: "jwks", Keys: nil}
		err := jWKSPlugin.Validate(&profile)
		if err == nil {
			t.Errorf("Validate() should return error when profile key is nil")
		}
	})

	t.Run("Invalid key", func(t *testing.T) {
		jWKSPlugin := NewJWKSPlugin()
		jwksURL := server.URL + "/oauth/v2/keys"
		profile, err := jWKSPlugin.Resolve(jwksURL)
		if err != nil {
			t.Errorf("Failed to resolve JWKS")
		}
		profile.Keys.Keys[0].Key = nil
		err = jWKSPlugin.Validate(profile)
		if err == nil {
			t.Errorf("Failed to validate. error = %v", err)
		}
	})
}

func TestGetTypeID(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		jWKSPlugin := NewJWKSPlugin()
		typeID := jWKSPlugin.GetTypeID()
		if typeID != "jwks" {
			t.Errorf("GetTypeID() returns %v, expected = %v", typeID, "jwks")
		}
	})
}

// TODO: Detailed JWKS Parse testing is done with fetchJWKS
func TestFetchJWKS(t *testing.T) {
	t.Run("Normal case with ECDSA keys", func(t *testing.T) {
		// Create JWKS server with ECDSA keys (which is what our system uses)
		config := mockserver.DefaultJWKSConfig()
		config.KeyPairs = []*mockserver.KeyPair{
			mockserver.MustGenerateKeyPair("333882310849986562"),
			mockserver.MustGenerateKeyPair("333996739130294274"),
		}

		jwksServer := mockserver.NewJWKSServer(config)
		defer jwksServer.Close()

		jwksPlugin := NewJWKSPlugin()
		keySet, err := jwksPlugin.fetchJWKS(jwksServer.JWKSEndpoint())
		if err != nil {
			t.Fatalf("Failed to resolve JWKS: %v", err)
		}
		if keySet == nil {
			t.Fatalf("FetchJWKS() returns nil")
		}

		// Should have 2 keys
		if len(keySet.Keys) != 2 {
			t.Fatalf("Expected 2 keys, got %d", len(keySet.Keys))
		}

		// Check key IDs match what we set
		keyIDs := make([]string, len(keySet.Keys))
		for i, key := range keySet.Keys {
			keyIDs[i] = key.KeyID
		}

		expectedIDs := []string{"333882310849986562", "333996739130294274"}
		for _, expectedID := range expectedIDs {
			found := false
			for _, actualID := range keyIDs {
				if actualID == expectedID {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("Expected key ID %s not found in response", expectedID)
			}
		}
	})

	t.Run("Plugin doesn't have httpClient", func(t *testing.T) {
		jwksServer := mockserver.NewJWKSServer(nil)
		defer jwksServer.Close()

		jwksPlugin := JWKSPlugin{httpClient: nil}
		_, err := jwksPlugin.fetchJWKS(jwksServer.JWKSEndpoint())
		if err == nil {
			t.Errorf("fetchJWKS() should return error when plugin doesn't have httpClient")
		}
	})

	t.Run("Server returns 400", func(t *testing.T) {
		jwksServer := mockserver.NewJWKSServer(nil)
		defer jwksServer.Close()

		// Configure server to return error
		jwksServer.SetErrorResponse("/.well-known/jwks.json", http.StatusBadRequest)

		jwksPlugin := NewJWKSPlugin()
		_, err := jwksPlugin.fetchJWKS(jwksServer.JWKSEndpoint())
		if err == nil {
			t.Errorf("fetchJWKS() should return error when server returns 400")
		}
	})
}

// TestFetchJWKS_WithMockServer tests JWKS fetching using the new mockserver package
func TestFetchJWKS_WithMockServer(t *testing.T) {
	// This test has been integrated into TestFetchJWKS
	t.Skip("Integrated into TestFetchJWKS")
}
