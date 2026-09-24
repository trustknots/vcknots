package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
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
	"github.com/trustknots/vcknots/wallet/credential"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/jwtvc"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func TestController_PresentCredential_InvalidID_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test with invalid URI that should fail during parsing
	mockURI := "invalid://uri/with/malformed/parameters"

	// Create a mock key entry for the test
	mockKey := newMockKeyEntry()

	// This should fail when trying to parse the invalid URI
	_, err := controller.PresentCredential(mockURI, mockKey, nil)
	if err == nil {
		t.Error("Expected PresentCredential to fail with invalid URI")
		return
	}

	// Verify the error is related to URI parsing
	if !strings.Contains(err.Error(), "failed to parse request URI") {
		t.Errorf("Expected URI parsing error, got: %v", err)
	}
}

func TestController_PresentCredential_ErrorPaths_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name    string
		uri     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty URI",
			uri:     "",
			wantErr: true,
			errMsg:  "failed to parse request URI",
		},
		{
			name:    "invalid URI format",
			uri:     "invalid-uri-format",
			wantErr: true,
			errMsg:  "failed to parse request URI",
		},
		{
			name:    "malformed URI with invalid characters",
			uri:     "openid4vp://present?invalid[query",
			wantErr: true,
			errMsg:  "failed to parse request URI",
		},
		{
			name:    "URI with unsupported scheme",
			uri:     "http://example.com/present",
			wantErr: true,
			errMsg:  "failed to parse request URI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKey := newMockKeyEntry()
			_, err := controller.PresentCredential(tt.uri, mockKey, nil)
			if tt.wantErr && err == nil {
				t.Errorf("PresentCredential() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("PresentCredential() unexpected error: %v", err)
			}
			if tt.wantErr && err != nil {
				errStr := err.Error()
				if len(tt.errMsg) > 0 && len(errStr) >= len(tt.errMsg) {
					found := false
					for i := 0; i <= len(errStr)-len(tt.errMsg); i++ {
						if errStr[i:i+len(tt.errMsg)] == tt.errMsg {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("PresentCredential() error = %v, expected to contain %v", err, tt.errMsg)
					}
				}
			}
		})
	}
}

func TestController_ParsePresentationRequest_RejectsNonHTTPSResponseURI(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(false)
	controller := createTestControllerWithDefaults(t)

	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"cred1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`)
	// VP §5.9.3: with response_mode direct_post the redirect_uri: Client
	// Identifier is the Response URI, so the two must be the same value.
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:http://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post&response_uri=http://example.com/response",
		dcqlQuery,
	)

	_, err := controller.ParsePresentationRequest(t.Context(), uri)
	require.Error(t, err)
	assert.ErrorContains(t, err, "response_uri must use https scheme")
}

func TestController_ParsePresentationRequest_AllowsNonHTTPSResponseURI_WhenValidationDisabled(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"cred1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:http://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post&response_uri=http://example.com/response",
		dcqlQuery,
	)

	request, err := controller.ParsePresentationRequest(t.Context(), uri)
	require.NoError(t, err)
	endpoint := request.ResponseEndpoint()
	require.NotNil(t, endpoint)
	assert.Equal(t, "http", endpoint.Scheme)
}

func TestController_ParsePresentationRequest_DirectPostJWTUsesResponseURI(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`)
	// direct_post.jwt is refused while parsing when the Verifier leaves no key
	// to encrypt the response to, so the request carries one.
	encryptionKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientMetadata, err := json.Marshal(map[string]any{
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &encryptionKey.PublicKey, KeyID: "enc", Algorithm: "ECDH-ES", Use: "enc"}}},
	})
	require.NoError(t, err)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:https://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post.jwt&response_uri=https://example.com/response&client_metadata=%s",
		dcqlQuery, url.QueryEscape(string(clientMetadata)),
	)

	request, err := controller.ParsePresentationRequest(t.Context(), uri)
	require.NoError(t, err)
	endpoint := request.ResponseEndpoint()
	require.NotNil(t, endpoint)
	req := request.Request()
	require.NotNil(t, req.DcqlQuery)
	// VP §5.9.3: the Client Identifier binds response_uri, and the wallet
	// keeps the value there rather than in redirect_uri.
	assert.Equal(t, "https://example.com/response", req.ResponseURI)
	assert.Empty(t, req.RedirectURI)
	assert.Equal(t, "https://example.com/response", endpoint.String())
	assert.Equal(t, oid4vp.OAuthAuthzReqResponseModeDirectPostJWT, req.ResponseMode)
}

func TestWallet_SelectCredentialsForConsent(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key := &realSigningKeyEntry{id: "holder-key-1", key: privateKey}

	rawCredential := buildTestSDJWTVC(t, key.PublicKey(), map[string]string{
		"given_name":  "TARO",
		"family_name": "TEST",
		"birthdate":   "2000-01-01",
	})
	err = controller.credStore.SaveCredentialEntry(credstoreTypes.CredentialEntry{
		Id:         "credential-1",
		ReceivedAt: time.Now(),
		Raw:        []byte(rawCredential),
		MimeType:   string(credential.SDJwtVC),
	}, 0)
	require.NoError(t, err)

	// direct_post.jwt is refused while parsing unless client_metadata names a
	// key the response can be encrypted to, so the request carries one.
	encryptionKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientMetadata, err := json.Marshal(map[string]any{
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &encryptionKey.PublicKey,
			KeyID:     "enc-key-1",
			Use:       "enc",
			Algorithm: "ECDH-ES",
		}}},
		"encrypted_response_enc_values_supported": []string{"A128GCM", "A256GCM"},
	})
	require.NoError(t, err)

	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]}`)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:https://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post.jwt&response_uri=https://example.com/response&state=state-1&client_metadata=%s",
		dcqlQuery, url.QueryEscape(string(clientMetadata)),
	)

	request, err := controller.ParsePresentationRequest(t.Context(), uri)
	require.NoError(t, err)
	selections, err := controller.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	// The consent screen shows what SubmitPresentation would disclose: the
	// requested claims, and not birthdate.
	require.Equal(t, []CredentialSelection{{
		CredentialID:    "credential-1",
		QueryIDs:        []string{"pid"},
		DisclosedClaims: []string{"given_name", "family_name"},
	}}, selections)
}

func TestWallet_PresentCredentialDirectPostJWT(t *testing.T) {
	httpAllowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)
	holderPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderKey := &realSigningKeyEntry{id: "holder-key-1", key: holderPrivateKey}

	rawCredential := buildTestSDJWTVC(t, holderKey.PublicKey(), map[string]string{
		"given_name":  "TARO",
		"family_name": "TEST",
		"birthdate":   "2000-01-01",
	})
	err = controller.credStore.SaveCredentialEntry(credstoreTypes.CredentialEntry{
		Id:         "credential-1",
		ReceivedAt: time.Now(),
		Raw:        []byte(rawCredential),
		MimeType:   string(credential.SDJwtVC),
	}, 0)
	require.NoError(t, err)

	encryptionPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	obs := newServerObservations(t, "response_uri")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs.called("response_uri")
		if !assert.Equal(obs, http.MethodPost, r.Method) {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		if !assert.NoError(obs, r.ParseForm()) {
			http.Error(w, "malformed authorization response form", http.StatusBadRequest)
			return
		}
		encryptedResponse := r.Form.Get("response")
		if !assert.NotEmpty(obs, encryptedResponse) {
			http.Error(w, "missing response parameter", http.StatusBadRequest)
			return
		}

		jwe, err := jose.ParseEncrypted(encryptedResponse, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM})
		if !assert.NoError(obs, err) {
			http.Error(w, "response is not a JWE the verifier accepts", http.StatusBadRequest)
			return
		}
		plaintext, err := jwe.Decrypt(encryptionPrivateKey)
		if !assert.NoError(obs, err) {
			http.Error(w, "response cannot be decrypted", http.StatusBadRequest)
			return
		}
		var payload map[string]any
		if !assert.NoError(obs, json.Unmarshal(plaintext, &payload)) {
			http.Error(w, "response payload is not JSON", http.StatusBadRequest)
			return
		}
		obs.set("decrypted_payload", payload)
		_, _ = w.Write([]byte(`{"redirect_uri":"https://example.com/done"}`))
	}))
	defer server.Close()

	clientMetadataBytes, err := json.Marshal(map[string]any{
		"jwks": map[string]any{
			"keys": []jose.JSONWebKey{{
				Key:       &encryptionPrivateKey.PublicKey,
				KeyID:     "enc-key-1",
				Algorithm: "ECDH-ES",
				Use:       "enc",
			}},
		},
		"encrypted_response_enc_values_supported": []string{"A128GCM"},
	})
	require.NoError(t, err)

	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}`)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=%s&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post.jwt&response_uri=%s&state=state-1&client_metadata=%s",
		url.QueryEscape("redirect_uri:"+server.URL),
		dcqlQuery,
		url.QueryEscape(server.URL),
		url.QueryEscape(string(clientMetadataBytes)),
	)

	redirect, err := controller.PresentCredential(uri, holderKey, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/done", redirect)
	decryptedPayload, _ := obs.get("decrypted_payload").(map[string]any)
	assert.Equal(t, "state-1", decryptedPayload["state"])
	vpToken, ok := decryptedPayload["vp_token"].(map[string]any)
	require.True(t, ok)
	require.NotEmpty(t, vpToken["pid"])
}

func TestController_PresentCredential_MissingRequiredFields_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test cases for missing required fields in PresentCredential function
	// These should trigger various error paths in the function logic
	tests := []struct {
		name           string
		setupMockURI   func() string
		expectedErrors []string
	}{
		{
			name: "URI with missing credential IDs",
			setupMockURI: func() string {
				return "openid4vp://present?presentation_definition_id=test-def&client_id=test-client"
			},
			expectedErrors: []string{"no credential IDs specified", "failed to parse request URI"},
		},
		{
			name: "URI with missing endpoint",
			setupMockURI: func() string {
				return "openid4vp://present?credential_id=test-cred&presentation_definition_id=test-def"
			},
			expectedErrors: []string{"endpoint is not specified", "failed to parse request URI"},
		},
		{
			name: "URI with missing presentation definition",
			setupMockURI: func() string {
				return "openid4vp://present?credential_id=test-cred&client_id=test-client"
			},
			expectedErrors: []string{"dcql_query is not specified", "failed to parse request URI"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockURI := tt.setupMockURI()
			mockKey := newMockKeyEntry()
			_, err := controller.PresentCredential(mockURI, mockKey, nil)

			if err == nil {
				t.Errorf("PresentCredential() expected error but got none")
				return
			}

			errStr := err.Error()
			foundExpectedError := false
			for _, expectedErr := range tt.expectedErrors {
				if len(errStr) >= len(expectedErr) {
					for i := 0; i <= len(errStr)-len(expectedErr); i++ {
						if errStr[i:i+len(expectedErr)] == expectedErr {
							foundExpectedError = true
							break
						}
					}
					if foundExpectedError {
						break
					}
				}
			}

			if !foundExpectedError {
				t.Errorf("PresentCredential() error = %v, expected one of %v", err, tt.expectedErrors)
			}
		})
	}
}

func TestController_PresentCredential_CallsRedirectHandler(t *testing.T) {
	controller, mockKey := receiveCredentialForPresentationTest(t)
	redirectTarget := "https://example.com/redirect"
	responseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"redirect_uri":"%s"}`, redirectTarget)
	}))
	defer responseServer.Close()

	// Step 2: Present the credential and verify redirect handler execution
	dcqlQuery := `{"credentials":[{"id":"cred1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`
	clientID := "redirect_uri:" + responseServer.URL
	presentationURI := fmt.Sprintf(
		"openid4vp://present?dcql_query=%s&client_id=%s&response_type=vp_token&response_mode=direct_post&response_uri=%s&nonce=test-nonce-123&state=test-state-456",
		url.QueryEscape(dcqlQuery),
		url.QueryEscape(clientID),
		url.QueryEscape(responseServer.URL),
	)

	called := false
	var captured string
	options := &PresentCredentialOptions{
		OnRedirect: func(uri string) error {
			called = true
			captured = uri
			return nil
		},
	}

	redirectURI, err := controller.PresentCredentialWithOptions(presentationURI, mockKey, options)
	require.NoError(t, err)
	require.Equal(t, redirectTarget, redirectURI)
	require.True(t, called, "expected redirect handler to be called")
	require.Equal(t, redirectTarget, captured)
}

func TestController_PresentCredential_DetailedErrorPaths_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test scenarios that exercise different parts of PresentCredential logic
	tests := []struct {
		name             string
		mockURIString    string
		expectParseError bool
		expectCredError  bool
		description      string
	}{
		{
			name:             "valid URI format but credential not found",
			mockURIString:    "openid4vp://present?credential_id=non-existent-credential&presentation_definition_id=test&endpoint=https://example.com",
			expectParseError: false,
			expectCredError:  true,
			description:      "Should fail when getting credential entry",
		},
		{
			name:             "multiple credential IDs scenario",
			mockURIString:    "openid4vp://present?credential_id=cred1&credential_id=cred2&presentation_definition_id=test&endpoint=https://example.com",
			expectParseError: false,
			expectCredError:  true,
			description:      "Should attempt to process multiple credentials",
		},
		{
			name:             "credential with special characters in ID",
			mockURIString:    "openid4vp://present?credential_id=cred%20with%20spaces&presentation_definition_id=test&endpoint=https://example.com",
			expectParseError: false,
			expectCredError:  true,
			description:      "Should handle URL-encoded credential IDs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKey := newMockKeyEntry()
			_, err := controller.PresentCredential(tt.mockURIString, mockKey, nil)

			if !tt.expectParseError && !tt.expectCredError && err != nil {
				t.Errorf("PresentCredential() unexpected error: %v", err)
			} else if (tt.expectParseError || tt.expectCredError) && err == nil {
				t.Errorf("PresentCredential() expected error but got none for %s", tt.description)
			}
		})
	}

	// Test with scenarios that exercise validation logic
	t.Run("presenter parsing success but missing fields", func(t *testing.T) {
		testCases := []struct {
			name string
			uri  string
		}{
			{"missing credential IDs", "openid4vp://present?presentation_definition_id=test&endpoint=https://example.com"},
			{"missing endpoint", "openid4vp://present?credential_id=test&presentation_definition_id=test"},
			{"missing presentation definition", "openid4vp://present?credential_id=test&endpoint=https://example.com"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				mockKey := newMockKeyEntry()
				_, err := controller.PresentCredential(tc.uri, mockKey, nil)
				if err == nil {
					t.Errorf("Expected error for %s but got none", tc.name)
				}
				// Expected error occurred - test passes
			})
		}
	})
}

func TestApplyOID4VPRequestOptions(t *testing.T) {
	req := &oid4vp.CredentialPresentationRequest{
		OAuthAuthzRequest: &oid4vp.OAuthAuthzRequest{
			ClientID: "x509_san_dns:localhost",
			Nonce:    "request-nonce",
		},
	}

	t.Run("copies oid4vp request values into jwt-vc options", func(t *testing.T) {
		opts := &jwtvc.JwtVcPresentationOptions{
			Audience: "old-audience",
			Nonce:    "old-nonce",
		}

		applyOID4VPRequestOptions(req, opts)

		if opts.Audience != req.ClientID {
			t.Fatalf("expected audience %q, got %q", req.ClientID, opts.Audience)
		}
		if opts.Nonce != req.Nonce {
			t.Fatalf("expected nonce %q, got %q", req.Nonce, opts.Nonce)
		}
	})

	t.Run("copies oid4vp request values into sd-jwt options", func(t *testing.T) {
		opts := &sdjwtvc.SdJwtVcPresentationOptions{
			RequireKeyBinding: false,
			Audience:          "old-audience",
			Nonce:             "old-nonce",
		}

		applyOID4VPRequestOptions(req, opts)

		if opts.Audience != req.ClientID {
			t.Fatalf("expected audience %q, got %q", req.ClientID, opts.Audience)
		}
		if opts.Nonce != req.Nonce {
			t.Fatalf("expected nonce %q, got %q", req.Nonce, opts.Nonce)
		}
	})
}

func TestNewestCredentials_SelectsMostRecentEntries(t *testing.T) {
	now := time.Now()
	entries := []*SavedCredential{
		{Entry: &credstoreTypes.CredentialEntry{Id: "oldest", ReceivedAt: now.Add(-2 * time.Hour)}},
		{Entry: &credstoreTypes.CredentialEntry{Id: "newest", ReceivedAt: now}},
		{Entry: &credstoreTypes.CredentialEntry{Id: "middle", ReceivedAt: now.Add(-time.Hour)}},
	}

	selected := newestCredentials(entries, 1)
	require.Len(t, selected, 1)
	require.NotNil(t, selected[0])
	require.NotNil(t, selected[0].Entry)
	assert.Equal(t, "newest", selected[0].Entry.Id)
}

func TestNewestCredentials_ReturnsEntriesInDescendingReceivedAtOrder(t *testing.T) {
	now := time.Now()
	entries := []*SavedCredential{
		{Entry: &credstoreTypes.CredentialEntry{Id: "first", ReceivedAt: now.Add(-time.Minute)}},
		{Entry: &credstoreTypes.CredentialEntry{Id: "third", ReceivedAt: now.Add(-3 * time.Minute)}},
		{Entry: &credstoreTypes.CredentialEntry{Id: "second", ReceivedAt: now.Add(-2 * time.Minute)}},
	}

	selected := newestCredentials(entries, 2)
	require.Len(t, selected, 2)
	assert.Equal(t, "first", selected[0].Entry.Id)
	assert.Equal(t, "second", selected[1].Entry.Id)
}

func receiveCredentialForPresentationTest(t *testing.T) (*Wallet, *mockKeyEntry) {
	t.Helper()
	t.Setenv(env.DEBUG.String(), "")
	t.Setenv(env.HTTP_ALLOWED.String(), "true")
	controller := createTestControllerWithDefaults(t)
	issuer, _, closeServer := newReceiveCredentialTestServer(t)
	t.Cleanup(closeServer)
	key := newMockKeyEntry()
	saved, err := controller.ReceiveCredential(ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer: issuer, CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {PreAuthorizedCode: "test-code"}},
		}, Type: receiverTypes.Oid4vci, Key: key,
	})
	require.NoError(t, err, "presentation test must receive and store a real signed credential")
	require.NotNil(t, saved)
	require.NotEmpty(t, saved.Entry.Raw)
	return controller, key
}

func TestController_ReceiveAndPresentCredential_ProfileWire(t *testing.T) {
	for _, draft := range []bool{false, true} {
		name := "final"
		if draft {
			name = "draft24"
		}
		t.Run(name, func(t *testing.T) {
			controller, key := receiveCredentialForPresentationTest(t)
			captured := make(chan url.Values, 1)
			obs := newServerObservations(t, "response_uri")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				obs.called("response_uri")
				if !assert.NoError(obs, r.ParseForm()) {
					http.Error(w, "malformed authorization response form", http.StatusBadRequest)
					return
				}
				captured <- r.PostForm
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
			}))
			defer server.Close()
			params := url.Values{
				"client_id": {"redirect_uri:" + server.URL}, "response_uri": {server.URL},
				"response_type": {"vp_token"}, "response_mode": {"direct_post"},
				"nonce": {"test-nonce"}, "state": {"test-state"},
			}
			if draft {
				params.Set("scope", "openid")
				params.Set("presentation_definition", `{"id":"definition","input_descriptors":[{"id":"identity","format":{"jwt_vp_json":{"alg":["ES256"]}}}]}`)
			} else {
				params.Set("dcql_query", `{"credentials":[{"id":"identity","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`)
			}
			uri := "openid4vp://present?" + params.Encode()
			if draft {
				request, err := controller.Draft24().ParsePresentationRequest(t.Context(), uri)
				require.NoError(t, err)
				selections, err := controller.SelectCredentials(t.Context(), request)
				require.NoError(t, err)
				result, err := controller.SubmitPresentation(t.Context(), request, Presentation{Key: key, Credentials: selections})
				require.NoError(t, err)
				require.Equal(t, "https://verifier.example/done", result.RedirectURI)
			} else {
				redirect, err := controller.PresentCredential(uri, key, nil)
				require.NoError(t, err)
				require.Equal(t, "https://verifier.example/done", redirect)
			}
			var form url.Values
			select {
			case form = <-captured:
			default:
				t.Fatal("verifier received no presentation")
			}
			require.Equal(t, "test-state", form.Get("state"))
			var serialized string
			if draft {
				serialized = form.Get("vp_token")
				var submission struct {
					DefinitionID string `json:"definition_id"`
				}
				require.NoError(t, json.Unmarshal([]byte(form.Get("presentation_submission")), &submission))
				require.Equal(t, "definition", submission.DefinitionID)
			} else {
				require.NotContains(t, form, "presentation_submission")
				var response map[string][]string
				require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &response))
				require.Len(t, response["identity"], 1)
				serialized = response["identity"][0]
			}
			signed, err := jwt.ParseSigned(serialized, []jose.SignatureAlgorithm{jose.ES256})
			require.NoError(t, err)
			var claims map[string]any
			require.NoError(t, signed.Claims(key.PublicKey().Key, &claims))
			require.Equal(t, "test-nonce", claims["nonce"])
			vp, ok := claims["vp"].(map[string]any)
			require.True(t, ok)
			require.Len(t, vp["verifiableCredential"], 1)
		})
	}
}
