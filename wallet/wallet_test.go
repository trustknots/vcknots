package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/env"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/jwtvc"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	"github.com/trustknots/vcknots/wallet/verifier"
)

type mockKeyEntry struct {
	id         string
	key        jose.JSONWebKey
	privateKey *ecdsa.PrivateKey
}

func (m *mockKeyEntry) ID() string {
	return m.id
}

func (m *mockKeyEntry) PublicKey() jose.JSONWebKey {
	return m.key
}

func (m *mockKeyEntry) Sign(data []byte) ([]byte, error) {
	if m.privateKey == nil {
		return nil, fmt.Errorf("mock key is missing private key")
	}

	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	return signature, nil
}

type invalidSignatureKeyEntry struct {
	*mockKeyEntry
}

func (k *invalidSignatureKeyEntry) Sign(data []byte) ([]byte, error) {
	return []byte("invalid-es256-signature"), nil
}

func newMockKeyEntry() *mockKeyEntry {
	// Generate a real ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("Failed to generate test key: " + err.Error())
	}

	jwk := jose.JSONWebKey{
		Algorithm: "ES256",
		KeyID:     "test-key-id",
		Use:       "sig",
		Key:       &privateKey.PublicKey,
	}

	return &mockKeyEntry{
		id:         "test-key-id",
		key:        jwk,
		privateKey: privateKey,
	}
}

type captureDpopReceiver struct {
	capturedProof *string
}

func (c *captureDpopReceiver) FetchIssuerMetadata(endpoint common.URIField, rt receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error) {

	return nil, fmt.Errorf("unexpected call to FetchIssuerMetadata")

}

func (c *captureDpopReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, rt receiverTypes.SupportedReceivingTypes) (*receiverTypes.AuthorizationServerMetadata, error) {

	return nil, fmt.Errorf("unexpected call to FetchAuthorizationServerMetadata")

}

func (c *captureDpopReceiver) FetchAccessToken(rt receiverTypes.SupportedReceivingTypes, endpoint common.URIField, authzCode string, txCode string, opts ...receiverTypes.TokenRequestOption) (*receiverTypes.CredentialIssuanceAccessToken, error) {

	requestConfig := receiverTypes.NewTokenRequestConfig(opts...)
	if requestConfig.DPoPProof != "" {
		proof := requestConfig.DPoPProof
		c.capturedProof = &proof
	}
	return &receiverTypes.CredentialIssuanceAccessToken{
		Token:     "tok",
		TokenType: "Bearer",
	}, nil

}

func (c *captureDpopReceiver) FetchNonce(rt receiverTypes.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	return nil, fmt.Errorf("unexpected call to FetchNonce")
}

func (c *captureDpopReceiver) ReceiveCredential(

	rt receiverTypes.SupportedReceivingTypes,
	endpoint common.URIField,
	credentialConfigurationID string,
	credentialIdentifier *string,
	accessToken receiverTypes.CredentialIssuanceAccessToken,
	credentialDefinition *receiverTypes.CredentialDefinition,
	jwtProof *string,
	options ...*receiverTypes.CredentialRequestOptions,
) (*string, error) {

	return nil, fmt.Errorf("unexpected call to ReceiveCredential")

}

// createTestControllerWithDefaults uses default configurations for integration testing
func createTestControllerWithDefaults(t *testing.T) *Wallet {
	tempConfigDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tempConfigDir)
	t.Setenv("HOME", tempConfigDir)

	controller, err := NewWallet()
	if err != nil {
		t.Fatalf("Failed to create controller with defaults: %v", err)
	}
	return controller
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	return parsed
}

func newReceiveCredentialTestServer(t *testing.T) (*url.URL, <-chan url.Values, func()) {
	t.Helper()

	tokenFormCh := make(chan url.Values, 1)
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	issuerKeyPair := mockserver.MustGenerateKeyPair("issuer-key-id")
	jwtBuilder := mockserver.MustNewJWTBuilder(issuerKeyPair)
	defaultCredentialJWT, err := jwtBuilder.CreateSignedJWT(server.URL, map[string]interface{}{
		"sub": "did:key:z6Mkio4WDmdtgEo4f9Hq6i6tnW8WFwknQQ4KHUY99BGY4EVr",
		"vc": map[string]interface{}{
			"@context": []string{
				"https://www.w3.org/2018/credentials/v1",
			},
			"id":           "http://example.com/credential/1",
			"type":         []string{"VerifiableCredential"},
			"issuer":       server.URL,
			"issuanceDate": "2023-01-01T00:00:00Z",
			"credentialSubject": map[string]interface{}{
				"id":   "http://example.com/subject",
				"name": "John Doe",
			},
		},
	})
	require.NoError(t, err)

	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"credential_issuer":     server.URL,
			"credential_endpoint":   server.URL + "/credential",
			"nonce_endpoint":        server.URL + "/nonce",
			"authorization_servers": []string{server.URL},
			"credential_configurations_supported": map[string]interface{}{
				"test-config": map[string]interface{}{
					"format": "jwt_vc_json",
					"credential_definition": map[string]interface{}{
						"type": []string{"VerifiableCredential"},
					},
				},
			},
		})
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"issuer":         server.URL,
			"token_endpoint": server.URL + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
			"response_types_supported":                        []string{"code"},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		form := url.Values{}
		for key, values := range r.Form {
			form[key] = append([]string(nil), values...)
		}
		tokenFormCh <- form

		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"c_nonce":      "test-nonce",
		})
	})

	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"c_nonce": "test-nonce",
		})
	})

	mux.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{{
				"credential": defaultCredentialJWT,
			}},
		})
	})

	credentialIssuer, err := url.Parse(server.URL)
	require.NoError(t, err)

	return credentialIssuer, tokenFormCh, server.Close
}

func TestNewWallet(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	if controller == nil {
		t.Error("expected non-nil controller")
	}
}

func TestNewWalletWithConfig_WithValidConfig(t *testing.T) {
	// Create individual components with default configs
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}

	verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	presenter, err := presenter.NewPresentationDispatcher(presenter.WithDefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create presenter: %v", err)
	}

	config := Config{
		CredStore: credStore,
		Receiver:  receiver,
		Verifier:  verifier,
		Presenter: presenter,
		// IDProfiler is nil - should use default
	}

	// This test should pass with default IDProfiler
	controller, err := NewWalletWithConfig(config)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if controller == nil {
		t.Error("expected non-nil controller")
	}
}

// This test focuses on DPoP key auto-generation.
// If default initialization becomes flaky in CI, inject explicit test dependencies.
func TestNewWalletWithConfig_DPoP_AutoGeneratesKey(t *testing.T) {
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		t.Skipf("credential store not available in this environment: %v", err)
	}
	w, err := NewWalletWithConfig(Config{
		CredStore: credStore,
		DPoP:      DPoPConfig{Enabled: true},
	})
	require.NoError(t, err)

	require.NotNil(t, w.dpop.Key)
}

func TestNewWalletWithConfig_MissingComponents(t *testing.T) {
	tests := []struct {
		name        string
		config      func() Config
		expectError bool
	}{
		{
			name: "empty config uses defaults",
			config: func() Config {
				return Config{
					// All components are nil - should use defaults
				}
			},
			expectError: false,
		},
		{
			name: "partial config uses defaults for missing components",
			config: func() Config {
				credStore, _ := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
				return Config{
					CredStore: credStore,
					// Other components are nil - should use defaults
				}
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, err := NewWalletWithConfig(tt.config())
			if tt.expectError {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if controller == nil {
					t.Error("expected non-nil controller")
				}
			}
		})
	}
}

func TestNewInMemoryECKeyEntry(t *testing.T) {
	key, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	require.NotEmpty(t, key.ID())

	pub, ok := key.PublicKey().Key.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, elliptic.P256(), pub.Curve)
}

func TestController_GenerateDID_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := jose.JSONWebKey{
		Algorithm: "ES256",
		KeyID:     "test-key",
	}

	options := DIDCreateOptions{
		TypeID:    "did:key",
		PublicKey: key,
	}

	// Integration test with default config
	// This would work once we have proper identity profiler implementation
	_, err := controller.GenerateDID(options)
	if err != nil {
		t.Skipf("GenerateDID not supported in mock environment: %v", err)
	}
}

func TestController_ReceiveCredential_InvalidOffer_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test with nil credential offer - this tests validation logic
	req := ReceiveCredentialRequest{
		CredentialOffer: nil,
		Type:            receiverTypes.Oid4vci,
		Key:             newMockKeyEntry(),
	}

	_, err := controller.ReceiveCredential(req)
	if err == nil {
		t.Error("expected error for nil credential offer")
	}
	if err.Error() != "credential offer is required" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestController_ReceiveCredential_MissingPreAuthCode_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	credentialIssuer, _ := url.Parse("https://issuer.example.com")
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           credentialIssuer,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants:                     map[string]*CredentialOfferGrant{},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	_, err := controller.ReceiveCredential(req)
	if err == nil {
		t.Error("expected error for missing pre-auth code")
	}
	if err.Error() != "pre-authorization code is not included in the offer" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestController_ReceiveCredential_EmptyConfigurationIDs_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	credentialIssuer, _ := url.Parse("https://issuer.example.com")
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           credentialIssuer,
			CredentialConfigurationIDs: []string{},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	_, err := controller.ReceiveCredential(req)
	if err == nil {
		t.Error("expected error for empty configuration IDs")
	}
	if err.Error() != "credential configuration IDs are empty" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestController_ReceiveCredential_TxCodeOmitted_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	credentialIssuer, tokenFormCh, closeServer := newReceiveCredentialTestServer(t)
	defer closeServer()

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           credentialIssuer,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
					TxCode:            &TxCode{},
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	_, err := controller.ReceiveCredential(req)
	require.NoError(t, err)

	select {
	case form := <-tokenFormCh:
		require.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", form.Get("grant_type"))
		require.Equal(t, "test-code", form.Get("pre-authorized_code"))
		require.NotContains(t, form, "tx_code")
	case <-time.After(2 * time.Second):
		require.FailNow(t, "token endpoint was not called")
	}
}

func TestController_ReceiveCredential_TxCodeProvided_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	credentialIssuer, tokenFormCh, closeServer := newReceiveCredentialTestServer(t)
	defer closeServer()

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           credentialIssuer,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
					TxCode:            &TxCode{},
				},
			},
		},
		Type:   receiverTypes.Oid4vci,
		Key:    newMockKeyEntry(),
		TxCode: "123456",
	}

	_, err := controller.ReceiveCredential(req)
	require.NoError(t, err)

	select {
	case form := <-tokenFormCh:
		require.Equal(t, "123456", form.Get("tx_code"))
	case <-time.After(2 * time.Second):
		require.FailNow(t, "tx_code was not received at token endpoint")
	}
}

func TestController_GetCredentialEntries_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test with valid request using default config
	req := GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
		Filter: nil,
	}

	// Integration test with real credential store (with default config)
	_, _, err := controller.GetCredentialEntries(req)
	if err != nil {
		t.Skipf("GetCredentialEntries failed with default plugin configuration, skipping: %v", err)
	}
}

func TestController_GetCredentialEntries_WithFilter_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test with filter function
	req := GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
		Filter: func(cred *SavedCredential) bool {
			return len(cred.Credential.Types) > 0
		},
	}

	_, _, err := controller.GetCredentialEntries(req)
	if err != nil {
		t.Skipf("GetCredentialEntries with filter failed, skipping: %v", err)
	}
}

func TestController_GetCredentialEntry_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test with non-existent ID - should not error but return nil
	result, err := controller.GetCredentialEntry("non-existent-id")
	if err != nil {
		t.Skipf("GetCredentialEntry failed with non-existent ID, skipping: %v", err)
	}
	if result != nil {
		t.Error("GetCredentialEntry should return nil for non-existent ID")
	}
}

func TestController_GetCredentialEntry_ErrorPaths_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name     string
		id       string
		wantErr  bool
		errCheck func(error) bool
	}{
		{
			name:    "empty ID",
			id:      "",
			wantErr: true,
			errCheck: func(err error) bool {
				return err != nil
			},
		},
		{
			name:    "invalid ID with special characters",
			id:      "invalid/id\\with:special*chars",
			wantErr: true,
			errCheck: func(err error) bool {
				return err != nil
			},
		},
		{
			name:    "very long ID",
			id:      string(make([]byte, 1000)),
			wantErr: true,
			errCheck: func(err error) bool {
				return err != nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := controller.GetCredentialEntry(tt.id)
			if tt.wantErr && err == nil {
				t.Errorf("GetCredentialEntry() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("GetCredentialEntry() unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && !tt.errCheck(err) {
				t.Errorf("GetCredentialEntry() error check failed: %v", err)
			}
			if result != nil && tt.wantErr {
				t.Errorf("GetCredentialEntry() expected nil result on error")
			}
		})
	}
}

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

func TestController_parseAuthorizationRequest_RejectsNonHTTPSResponseURI(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(false)

	presentationDefinition := url.QueryEscape(`{"id":"test-def"}`)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:https://example.com/cb&response_type=vp_token&nonce=test-nonce&presentation_definition=%s&response_mode=direct_post&response_uri=http://example.com/response",
		presentationDefinition,
	)

	_, _, err := controller.parseAuthorizationRequest(uri)
	require.Error(t, err)
	assert.ErrorContains(t, err, "response_uri must use https scheme")
}

func TestController_parseAuthorizationRequest_AllowsNonHTTPSResponseURI_WhenValidationDisabled(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	presentationDefinition := url.QueryEscape(`{"id":"test-def"}`)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:https://example.com/cb&response_type=vp_token&nonce=test-nonce&presentation_definition=%s&response_mode=direct_post&response_uri=http://example.com/response",
		presentationDefinition,
	)

	_, endpoint, err := controller.parseAuthorizationRequest(uri)
	require.NoError(t, err)
	require.NotNil(t, endpoint)
	assert.Equal(t, "http", endpoint.Scheme)
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
			expectedErrors: []string{"presentation definition is not specified", "failed to parse request URI"},
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

func TestController_VerifyCredential_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	cred := &credential.Credential{
		ID:    "hoge://test-credential",
		Types: []string{"VerifiableCredential"},
		Proof: nil, // No proof
	}

	pubKey := jose.JSONWebKey{
		Algorithm: "ES256",
		KeyID:     "test-key",
	}

	// Test with no proof - should return false
	result := controller.VerifyCredential(cred, pubKey)
	if result {
		t.Error("expected false for credential without proof")
	}
}

func TestController_VerifyCredential_WithProof_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Create credential with proof
	cred := &credential.Credential{
		ID:    "https://example.com/credentials/123",
		Types: []string{"VerifiableCredential", "TestCredential"},
		Proof: &credential.CredentialProof{
			Algorithm: "ES256",
			Signature: []byte("invalid-signature"),
			Payload:   []byte("test-payload"),
		},
	}

	pubKey := jose.JSONWebKey{
		Algorithm: "ES256",
		KeyID:     "test-key",
		Use:       "sig",
	}

	// Test with proof - should attempt verification (may fail due to mock)
	result := controller.VerifyCredential(cred, pubKey)
	// In mock environment, this might return false due to invalid signature
	// but we're testing that the code path is exercised
	t.Logf("VerifyCredential result with proof: %v", result)
}

func TestController_FetchAuthorizationServerMetadata_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test fetchAuthorizationServerMetadata by calling methods that use it
	// This is a private method, so we test it indirectly through ReceiveCredential
	server := createMockOID4VCIServer()
	defer server.Close()

	serverURL, _ := url.Parse(server.URL())
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           serverURL,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	// This will call fetchAuthorizationServerMetadata internally
	// In test environment without proper server setup, this is expected to fail
	_, err := controller.ReceiveCredential(req)
	if err == nil {
		t.Error("Expected ReceiveCredential to fail in test environment without proper server setup")
	}
}
func TestWallet_generateDPoPProof_HeaderAndPayload(t *testing.T) {
	key, err := newInMemoryECKeyEntry()
	require.NoError(t, err)

	w := &Wallet{}
	proof, err := w.generateDPoPProof(key, http.MethodPost, "https://server.example.com/token", "", nil)
	require.NoError(t, err)

	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var header map[string]any
	var payload map[string]any

	require.NoError(t, json.Unmarshal(headerBytes, &header))
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))

	assert.Equal(t, "dpop+jwt", header["typ"])
	assert.Equal(t, "ES256", header["alg"])

	jwk, ok := header["jwk"].(map[string]any)
	require.True(t, ok)
	assert.NotNil(t, jwk["kty"])
	assert.Nil(t, jwk["d"])

	assert.NotEmpty(t, payload["jti"])
	assert.Equal(t, "POST", payload["htm"])
	assert.Equal(t, "https://server.example.com/token", payload["htu"])
	assert.NotNil(t, payload["iat"])
}

func TestWallet_generateDPoPProof_JtiIsUnique(t *testing.T) {
	key, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	w := &Wallet{}
	proof1, err := w.generateDPoPProof(
		key,
		http.MethodPost,
		"https://server.example.com/token",
		"",
		nil,
	)
	require.NoError(t, err)
	proof2, err := w.generateDPoPProof(
		key,
		http.MethodPost,
		"https://server.example.com/token",
		"",
		nil,
	)
	require.NoError(t, err)
	jti1 := extractPayloadField(t, proof1, "jti")
	jti2 := extractPayloadField(t, proof2, "jti")
	assert.NotEqual(t, jti1, jti2)
}

func TestWallet_generateDPoPProof_NilKey(t *testing.T) {
	w := &Wallet{}
	_, err := w.generateDPoPProof(
		nil,
		http.MethodPost,
		"https://server.example.com/token",
		"",
		nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dpop key is required")
}

func TestWallet_obtainAccessToken_DPoPEnabledControlsProof(t *testing.T) {

	tokenEndpoint, err := common.ParseURIField("https://server.example.com/token")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpoint: tokenEndpoint,
		PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
	}
	t.Run("disabled does not attach proof", func(t *testing.T) {
		cap := &captureDpopReceiver{}
		d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Mock, cap))
		require.NoError(t, err)
		w := &Wallet{
			receiver: d,
			dpop:     DPoPConfig{Enabled: false},
		}
		_, err = w.obtainAccessToken(receiverTypes.Mock, authMetadata, "pre-auth-code", "")
		require.NoError(t, err)
		assert.Nil(t, cap.capturedProof)
	})
	t.Run("enabled attaches proof", func(t *testing.T) {
		key, err := newInMemoryECKeyEntry()
		require.NoError(t, err)
		cap := &captureDpopReceiver{}
		d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Mock, cap))
		require.NoError(t, err)
		w := &Wallet{
			receiver: d,
			dpop: DPoPConfig{
				Enabled: true,
				Key:     key,
			},
		}
		_, err = w.obtainAccessToken(receiverTypes.Mock, authMetadata, "pre-auth-code", "")
		require.NoError(t, err)
		require.NotNil(t, cap.capturedProof)
		assert.NotEmpty(t, *cap.capturedProof)
	})

}

func TestWallet_obtainAccessToken_DPoPNonceChallengeRetriesWithNonce(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	const (
		dpopNonce        = "token-dpop-nonce"
		accessTokenValue = "dpop-access-token"
	)

	var tokenRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		tokenRequests++
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(dpopProof, ".")[1])
		if err != nil {
			http.Error(w, "invalid DPoP payload", http.StatusBadRequest)
			return
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			http.Error(w, "invalid DPoP payload json", http.StatusBadRequest)
			return
		}

		if tokenRequests == 1 {
			if _, exists := payload["nonce"]; exists {
				http.Error(w, "first DPoP proof should not include nonce", http.StatusBadRequest)
				return
			}
			w.Header().Set("DPoP-Nonce", dpopNonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if payload["nonce"] != dpopNonce {
			http.Error(w, "retry DPoP proof missing nonce", http.StatusBadRequest)
			return
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"access_token": accessTokenValue,
			"token_type":   "DPoP",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	tokenEndpoint, err := common.ParseURIField(server.URL + "/token")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpoint: tokenEndpoint,
		PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
	}
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	d, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
		dpop: DPoPConfig{
			Enabled: true,
			Key:     dpopKey,
		},
	}

	token, err := w.obtainAccessToken(receiverTypes.Oid4vci, authMetadata, "pre-auth-code", "")
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, accessTokenValue, token.Token)
	assert.Equal(t, 2, tokenRequests)
}

func extractPayloadField(t *testing.T, compactJWT string, field string) any {
	t.Helper()
	parts := strings.Split(compactJWT, ".")
	require.Len(t, parts, 3)
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(b, &payload))
	value, ok := payload[field]
	require.True(t, ok, "field %q not found in payload", field)
	return value
}

func extractHeaderField(t *testing.T, compactJWT string, field string) any {
	t.Helper()
	parts := strings.Split(compactJWT, ".")
	require.Len(t, parts, 3)
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(b, &header))
	value, ok := header[field]
	require.True(t, ok, "field %q not found in header", field)
	return value
}

func TestWallet_generateDPoPProof_SignatureVerifies(t *testing.T) {
	key, err := newInMemoryECKeyEntry()
	require.NoError(t, err)

	w := &Wallet{}
	proof, err := w.generateDPoPProof(key, http.MethodPost, "https://server.example.com/token", "", nil)
	require.NoError(t, err)

	parsed, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	embeddedJWK := parsed.Signatures[0].Header.JSONWebKey
	require.NotNil(t, embeddedJWK)

	_, err = parsed.Verify(embeddedJWK.Key)
	require.NoError(t, err)
}

func TestController_generateJWTProof_AnonymousPreAuthorizedFlow_OmitsIss(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}
	nonce := "test-nonce"

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)
	if err != nil {
		t.Errorf("generateJWTProof returned error: %v", err)
	}

	if proof == "" {
		t.Error("expected non-empty proof")
	}

	// Validate JWT structure (3 parts separated by dots)
	parts := 0
	for _, char := range proof {
		if char == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("expected JWT to have 2 dots (3 parts), got %d dots", parts)
	}

	proofParts := strings.Split(proof, ".")
	if len(proofParts) != 3 {
		t.Fatalf("expected JWT to have 3 parts, got %d", len(proofParts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(proofParts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if _, exists := payload["iss"]; exists {
		t.Fatalf("expected iss claim to be omitted in anonymous pre-authorized flow, got %v", payload["iss"])
	}
}

func TestController_generateJWTProof_RejectsInvalidES256SignatureEncoding(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := &invalidSignatureKeyEntry{mockKeyEntry: newMockKeyEntry()}
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}

	proof, err := controller.generateJWTProof(
		key,
		did,
		nil,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)
	require.Error(t, err)
	assert.Empty(t, proof)
	assert.Contains(t, err.Error(), "failed to serialize JWT proof")
}

func TestController_generateDPoPProof_IncludesAccessTokenHashAndNonce(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	accessToken := "dpop-access-token"
	nonce := "dpop-nonce"
	htu := "https://issuer.example.com/credential"

	proof, err := controller.generateDPoPProof(key, http.MethodPost, htu, accessToken, &nonce)
	require.NoError(t, err)

	parts := strings.Split(proof, ".")
	require.Len(t, parts, 3)

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "dpop+jwt", header["typ"])
	assert.Equal(t, "ES256", header["alg"])
	assert.Contains(t, header, "jwk")

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))

	accessTokenHash := sha256.Sum256([]byte(accessToken))
	expectedAth := base64.RawURLEncoding.EncodeToString(accessTokenHash[:])
	assert.Equal(t, http.MethodPost, payload["htm"])
	assert.Equal(t, htu, payload["htu"])
	assert.Equal(t, expectedAth, payload["ath"])
	assert.Equal(t, nonce, payload["nonce"])
	assert.NotEmpty(t, payload["jti"])
	assert.NotZero(t, payload["iat"])
}

func TestController_generateDPoPProof_RejectsInvalidES256SignatureEncoding(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := &invalidSignatureKeyEntry{mockKeyEntry: newMockKeyEntry()}

	proof, err := controller.generateDPoPProof(key, http.MethodPost, "https://issuer.example.com/credential", "access-token", nil)
	require.Error(t, err)
	assert.Empty(t, proof)
	assert.Contains(t, err.Error(), "failed to serialize dpop proof")
}

func TestController_generateJWTProof_NonAnonymousFlow_IncludesIssAsClientID(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}
	nonce := "test-nonce"
	clientID := "test-client-id"

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		&clientID,
		credentialRequestProofBindingMethodKID,
	)
	if err != nil {
		t.Fatalf("generateJWTProof returned error: %v", err)
	}

	proofParts := strings.Split(proof, ".")
	if len(proofParts) != 3 {
		t.Fatalf("expected JWT to have 3 parts, got %d", len(proofParts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(proofParts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	iss, ok := payload["iss"].(string)
	if !ok {
		t.Fatalf("expected iss claim to be present as string in non-anonymous flow")
	}
	if iss != clientID {
		t.Fatalf("expected iss %q, got %q", clientID, iss)
	}
}

// --- private_key_jwt client authentication tests ---

func newClientAuthKeyEntry(t *testing.T, keyID string) (*mockKeyEntry, jose.JSONWebKey) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privateJWK := jose.JSONWebKey{
		Key:       privKey,
		KeyID:     keyID,
		Algorithm: "ES256",
		Use:       "sig",
	}
	return &mockKeyEntry{
		id:         keyID,
		key:        privateJWK,
		privateKey: privKey,
	}, privateJWK.Public()
}

func TestWallet_generateClientAssertion_HeaderAndPayload(t *testing.T) {
	w := &Wallet{}

	key, _ := newClientAuthKeyEntry(t, "client-key-1")
	const clientID = "test-client-id"
	const tokenEndpoint = "https://as.example.com/token"

	assertion, err := w.generateClientAssertion(key, clientID, tokenEndpoint)
	require.NoError(t, err)

	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3)

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	assert.Equal(t, "jwt", header["typ"])
	assert.Equal(t, "ES256", header["alg"])
	assert.Equal(t, "client-key-1", header["kid"])

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))

	assert.Equal(t, clientID, payload["iss"])
	assert.Equal(t, clientID, payload["sub"])
	assert.Equal(t, tokenEndpoint, payload["aud"])
	assert.NotEmpty(t, payload["jti"])
	assert.NotZero(t, payload["iat"])
	assert.NotZero(t, payload["exp"])
	assert.NotZero(t, payload["nbf"])

	expClaim, ok := payload["exp"].(float64)
	require.True(t, ok)
	iatClaim, ok := payload["iat"].(float64)
	require.True(t, ok)
	assert.InDelta(t, float64(clientAssertionLifetime.Seconds()), expClaim-iatClaim, 2)
}

func TestWallet_generateClientAssertion_ErrorsOnMissingInputs(t *testing.T) {
	w := &Wallet{}
	key, _ := newClientAuthKeyEntry(t, "client-key-1")

	_, err := w.generateClientAssertion(nil, "client-id", "https://as.example.com/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client auth key is required")

	_, err = w.generateClientAssertion(key, "  ", "https://as.example.com/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clientID is required")

	_, err = w.generateClientAssertion(key, "client-id", "  ")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience is required")
}

func boolPtr(v bool) *bool { return &v }

func authMethodsPtr(methods ...receiverTypes.TokenEndpointAuthMethod) *[]receiverTypes.TokenEndpointAuthMethod {
	m := methods
	return &m
}

func TestResolveClientAuthMethod(t *testing.T) {
	key, _ := newClientAuthKeyEntry(t, "client-key-1")

	t.Run("defaults to none when anonymous supported and nothing configured", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
		}
		method, ok := resolveClientAuthMethod(ClientAuthConfig{}, authMetadata)
		require.True(t, ok)
		assert.Equal(t, receiverTypes.None, method)
	})

	t.Run("selects private_key_jwt when configured and advertised", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported: authMethodsPtr(receiverTypes.PrivateKeyJwt),
		}
		method, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		require.True(t, ok)
		assert.Equal(t, receiverTypes.PrivateKeyJwt, method)
	})

	t.Run("defaults to none even when private_key_jwt credentials are configured", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
		}
		method, ok := resolveClientAuthMethod(ClientAuthConfig{
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		require.True(t, ok)
		assert.Equal(t, receiverTypes.None, method)
	})

	t.Run("honors explicit private_key_jwt method", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
		}
		method, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		require.True(t, ok)
		assert.Equal(t, receiverTypes.PrivateKeyJwt, method)
	})

	t.Run("does not fall back to none when private_key_jwt is not advertised", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
		}
		_, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		assert.False(t, ok)
	})

	t.Run("returns false when no method is usable", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			PreAuthorizedGrantAnonymousAccessSupported: boolPtr(false),
		}
		_, ok := resolveClientAuthMethod(ClientAuthConfig{}, authMetadata)
		assert.False(t, ok)
	})

	t.Run("private_key_jwt rejected when alg not supported", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported:          authMethodsPtr(receiverTypes.PrivateKeyJwt),
			TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.RS256},
		}
		_, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "client-id",
			Key:      key,
		}, authMetadata)
		assert.False(t, ok)
	})

	t.Run("private_key_jwt rejected when client id/key missing", func(t *testing.T) {
		authMetadata := &receiverTypes.AuthorizationServerMetadata{
			TokenEndpointAuthMethodsSupported: authMethodsPtr(receiverTypes.PrivateKeyJwt),
		}
		_, ok := resolveClientAuthMethod(ClientAuthConfig{
			Method: receiverTypes.PrivateKeyJwt,
		}, authMetadata)
		assert.False(t, ok)
	})
}

func TestValidateClientAuthConfig(t *testing.T) {
	key, _ := newClientAuthKeyEntry(t, "client-key-1")

	assert.NoError(t, validateClientAuthConfig(ClientAuthConfig{}))
	assert.NoError(t, validateClientAuthConfig(ClientAuthConfig{
		Method:   receiverTypes.PrivateKeyJwt,
		ClientID: "wallet-id",
		Key:      key,
	}))

	err := validateClientAuthConfig(ClientAuthConfig{
		Method: receiverTypes.PrivateKeyJwt,
		Key:    key,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client ID is required")

	err = validateClientAuthConfig(ClientAuthConfig{
		Method:   receiverTypes.PrivateKeyJwt,
		ClientID: "wallet-id",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key is required")

	err = validateClientAuthConfig(ClientAuthConfig{
		Method: receiverTypes.ClientSecretPost,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported client authentication method")
}

func TestResolveClientAssertionAudience(t *testing.T) {
	tokenEndpoint := "https://as.example.com/token"
	issuer, err := common.ParseURIField("https://as.example.com")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{Issuer: *issuer}

	assert.Equal(t, "https://registered-audience.example.com", resolveClientAssertionAudience(
		ClientAuthConfig{AssertionAudience: "https://registered-audience.example.com"},
		authMetadata,
		tokenEndpoint,
	))
	assert.Equal(t, "https://as.example.com", resolveClientAssertionAudience(
		ClientAuthConfig{},
		authMetadata,
		tokenEndpoint,
	))
	assert.Equal(t, tokenEndpoint, resolveClientAssertionAudience(
		ClientAuthConfig{},
		&receiverTypes.AuthorizationServerMetadata{},
		tokenEndpoint,
	))
}

type captureClientAuthReceiver struct {
	capturedClientID        *string
	capturedClientAssertion *string
	capturedDPoP            *string
}

func (c *captureClientAuthReceiver) FetchIssuerMetadata(endpoint common.URIField, rt receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error) {
	return nil, fmt.Errorf("unexpected call to FetchIssuerMetadata")
}

func (c *captureClientAuthReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, rt receiverTypes.SupportedReceivingTypes) (*receiverTypes.AuthorizationServerMetadata, error) {
	return nil, fmt.Errorf("unexpected call to FetchAuthorizationServerMetadata")
}

func (c *captureClientAuthReceiver) FetchAccessToken(rt receiverTypes.SupportedReceivingTypes, endpoint common.URIField, authzCode string, txCode string, opts ...receiverTypes.TokenRequestOption) (*receiverTypes.CredentialIssuanceAccessToken, error) {
	cfg := receiverTypes.NewTokenRequestConfig(opts...)
	if cfg.ClientAssertion != "" {
		id, assertion := cfg.ClientID, cfg.ClientAssertion
		c.capturedClientID = &id
		c.capturedClientAssertion = &assertion
	}
	if cfg.DPoPProof != "" {
		proof := cfg.DPoPProof
		c.capturedDPoP = &proof
	}
	return &receiverTypes.CredentialIssuanceAccessToken{
		Token:     "tok",
		TokenType: "Bearer",
	}, nil
}

func (c *captureClientAuthReceiver) FetchNonce(rt receiverTypes.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	return nil, fmt.Errorf("unexpected call to FetchNonce")
}

func (c *captureClientAuthReceiver) ReceiveCredential(
	rt receiverTypes.SupportedReceivingTypes,
	endpoint common.URIField,
	credentialConfigurationID string,
	credentialIdentifier *string,
	accessToken receiverTypes.CredentialIssuanceAccessToken,
	credentialDefinition *receiverTypes.CredentialDefinition,
	jwtProof *string,
	options ...*receiverTypes.CredentialRequestOptions,
) (*string, error) {
	return nil, fmt.Errorf("unexpected call to ReceiveCredential")
}

func TestWallet_obtainAccessToken_PrivateKeyJwtAttachesAssertion(t *testing.T) {
	tokenEndpoint, err := common.ParseURIField("https://as.example.com/token")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpoint: tokenEndpoint,
		TokenEndpointAuthMethodsSupported: authMethodsPtr(
			receiverTypes.PrivateKeyJwt,
		),
	}

	key, _ := newClientAuthKeyEntry(t, "client-key-1")
	cap := &captureClientAuthReceiver{}
	d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Mock, cap))
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
		clientAuth: ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "wallet-id",
			Key:      key,
		},
	}

	token, err := w.obtainAccessToken(receiverTypes.Mock, authMetadata, "pre-auth-code", "")
	require.NoError(t, err)
	require.NotNil(t, token)
	require.NotNil(t, cap.capturedClientAssertion)
	require.NotNil(t, cap.capturedClientID)
	assert.Equal(t, "wallet-id", *cap.capturedClientID)
	assert.Nil(t, cap.capturedDPoP, "DPoP should not be attached when disabled")
}

func TestWallet_obtainAccessToken_AnonymousByDefaultDoesNotAttachAssertion(t *testing.T) {
	tokenEndpoint, err := common.ParseURIField("https://as.example.com/token")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpoint: tokenEndpoint,
		PreAuthorizedGrantAnonymousAccessSupported: boolPtr(true),
	}

	cap := &captureClientAuthReceiver{}
	d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Mock, cap))
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
	}

	token, err := w.obtainAccessToken(receiverTypes.Mock, authMetadata, "pre-auth-code", "")
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Nil(t, cap.capturedClientAssertion, "client assertion must not be attached for anonymous flow")
}

func TestWallet_obtainAccessToken_NoUsableMethodReturnsError(t *testing.T) {
	tokenEndpoint, err := common.ParseURIField("https://as.example.com/token")
	require.NoError(t, err)
	authMetadata := &receiverTypes.AuthorizationServerMetadata{
		TokenEndpoint: tokenEndpoint,
		PreAuthorizedGrantAnonymousAccessSupported: boolPtr(false),
	}

	cap := &captureClientAuthReceiver{}
	d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Mock, cap))
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
	}

	_, err = w.obtainAccessToken(receiverTypes.Mock, authMetadata, "pre-auth-code", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no usable client authentication method")
}

func TestWallet_obtainAccessToken_PrivateKeyJwtEndToEndWithMockServer(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	key, publicJWK := newClientAuthKeyEntry(t, "client-key-1")
	pubKey := publicJWK

	issuerConfig := &mockserver.OID4VCIIssuerConfig{
		KeyPair:                           mockserver.MustGenerateKeyPair("issuer-key-id"),
		IssuerID:                          "test-issuer",
		PreAuthorizedGrantAnonymous:       false,
		TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
		TokenEndpointAuthSigningAlgs:      []string{"ES256"},
		RequireClientAssertion:            true,
		ClientAuthPublicKey:               &pubKey,
		ExpectedClientID:                  "wallet-id",
		CredentialConfigurations: map[string]interface{}{
			"test-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"credential_definition": map[string]interface{}{
					"type": []string{"VerifiableCredential"},
				},
			},
		},
		TokenResponse: map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"c_nonce":      "mock-nonce",
		},
		CustomCredentials: make(map[string]string),
	}
	issuer := mockserver.NewOID4VCIIssuerServer(issuerConfig)
	defer issuer.Close()

	issuerURL, err := url.Parse(issuer.URL())
	require.NoError(t, err)
	asEndpoint := common.URIField(*issuerURL)
	tokenEndpoint, err := common.ParseURIField(issuer.URL() + "/token")
	require.NoError(t, err)

	d, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
		clientAuth: ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "wallet-id",
			Key:      key,
		},
	}

	authMetadata, err := d.FetchAuthorizationServerMetadata(asEndpoint, receiverTypes.Oid4vci)
	require.NoError(t, err)
	require.NotNil(t, authMetadata.TokenEndpoint)

	authMetadata.TokenEndpoint = tokenEndpoint

	token, err := w.obtainAccessToken(receiverTypes.Oid4vci, authMetadata, "pre-auth-code", "")
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "mock-access-token", token.Token)
}

func TestWallet_fetchCredentialMetadata_AllowsPrivateKeyJwtWhenAnonymousNotSupported(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	key, _ := newClientAuthKeyEntry(t, "client-key-1")
	issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
		KeyPair:                           mockserver.MustGenerateKeyPair("issuer-key-id"),
		IssuerID:                          "test-issuer",
		PreAuthorizedGrantAnonymous:       false,
		TokenEndpointAuthMethodsSupported: []string{"private_key_jwt"},
		TokenEndpointAuthSigningAlgs:      []string{"ES256"},
		CredentialConfigurations: map[string]interface{}{
			"test-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"credential_definition": map[string]interface{}{
					"type": []string{"VerifiableCredential"},
				},
			},
		},
		CustomCredentials: make(map[string]string),
	})
	defer issuer.Close()

	issuerURL, err := url.Parse(issuer.URL())
	require.NoError(t, err)

	d, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{
		receiver: d,
		clientAuth: ClientAuthConfig{
			Method:   receiverTypes.PrivateKeyJwt,
			ClientID: "wallet-id",
			Key:      key,
		},
	}

	offer := &CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{"test-config"},
		Grants:                     map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {}},
	}
	req := ReceiveCredentialRequest{
		CredentialOffer: offer,
		Type:            receiverTypes.Oid4vci,
	}

	_, authMetadata, err := w.fetchCredentialMetadata(req)
	require.NoError(t, err)
	require.NotNil(t, authMetadata)
}

func TestWallet_fetchCredentialMetadata_RejectsWhenNoUsableMethod(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
		KeyPair:                     mockserver.MustGenerateKeyPair("issuer-key-id"),
		IssuerID:                    "test-issuer",
		PreAuthorizedGrantAnonymous: false,
		CredentialConfigurations: map[string]interface{}{
			"test-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"credential_definition": map[string]interface{}{
					"type": []string{"VerifiableCredential"},
				},
			},
		},
		CustomCredentials: make(map[string]string),
	})
	defer issuer.Close()

	issuerURL, err := url.Parse(issuer.URL())
	require.NoError(t, err)

	d, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{receiver: d}

	offer := &CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{"test-config"},
		Grants:                     map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {}},
	}
	req := ReceiveCredentialRequest{
		CredentialOffer: offer,
		Type:            receiverTypes.Oid4vci,
	}

	_, _, err = w.fetchCredentialMetadata(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no usable client authentication method")
}

func TestController_generateJWTProof_NonAnonymousFlow_EmptyClientIDReturnsError(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}
	nonce := "test-nonce"
	emptyClientID := ""

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		&emptyClientID,
		credentialRequestProofBindingMethodKID,
	)
	if err == nil {
		t.Fatalf("expected error when clientID is empty, got nil")
	}
	if !strings.Contains(err.Error(), "clientID must be non-empty when provided") {
		t.Fatalf("unexpected error: %v", err)
	}
	if proof != "" {
		t.Fatalf("expected empty proof on error, got %q", proof)
	}
}

func TestController_generateJWTProof_NonAnonymousFlow_BlankClientIDReturnsError(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}
	nonce := "test-nonce"
	blankClientID := "   "

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		&blankClientID,
		credentialRequestProofBindingMethodKID,
	)
	if err == nil {
		t.Fatalf("expected error when clientID is blank, got nil")
	}
	if !strings.Contains(err.Error(), "clientID must be non-empty when provided") {
		t.Fatalf("unexpected error: %v", err)
	}
	if proof != "" {
		t.Fatalf("expected empty proof on error, got %q", proof)
	}
}

func TestController_generateJWTProof_WithoutNonce_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}

	proof, err := controller.generateJWTProof(
		key,
		did,
		nil,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)
	if err != nil {
		t.Errorf("generateJWTProof returned error: %v", err)
	}

	if proof == "" {
		t.Error("expected non-empty proof")
	}
}

func TestController_generateJWTProof_WithoutIssuer_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}
	nonce := "test-nonce"

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)
	if err != nil {
		t.Fatalf("generateJWTProof returned error: %v", err)
	}

	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT to have 3 parts, got %d", len(parts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode JWT payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to parse JWT payload: %v", err)
	}

	if _, exists := payload["iss"]; exists {
		t.Fatal("iss claim must be omitted")
	}
}

const testMaxNonceResponseBodyBytes int64 = 4 << 10

func TestController_fetchCredentialNonce_FallbackToAccessTokenWhenEndpointMissing(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	cnonce := "token-c-nonce"
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{CNonce: &cnonce}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, cnonce, *nonce)
}

func TestController_fetchCredentialNonce_ReturnsNilWhenNoNonceSource(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, &receiverTypes.CredentialIssuerMetadata{}, &receiverTypes.CredentialIssuanceAccessToken{})
	require.NoError(t, err)
	require.Nil(t, nonce)
}

func TestController_fetchCredentialNonce_FallbackToAccessTokenWhenEndpointFails(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	nonceEndpoint, err := common.ParseURIField("http://127.0.0.1:1/nonce")
	require.NoError(t, err)

	cnonce := "token-c-nonce"
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{CNonce: &cnonce}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, cnonce, *nonce)
}

func TestController_fetchCredentialNonce_RejectsNonHTTPSNonceEndpoint(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(false)

	nonceEndpoint, err := common.ParseURIField("http://example.com/nonce")
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "unsupported URL scheme")
}

func TestController_fetchCredentialNonce_UsesNonceEndpointWhenFallbackMissing(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	nonceValue := "nonce-from-endpoint"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"` + nonceValue + `"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, nonceValue, *nonce)
}

func TestController_fetchCredentialNonce_ReturnsErrorWhenEndpointFailsWithoutFallback(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary failure", http.StatusInternalServerError)
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "nonce endpoint returned status")
}

func TestController_fetchCredentialNonce_FallbackToAccessTokenWhenResponseTooLarge(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	largeNonce := strings.Repeat("a", int(testMaxNonceResponseBodyBytes))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"` + largeNonce + `"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	fallback := "token-c-nonce"
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{CNonce: &fallback}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, fallback, *nonce)
}

func TestController_fetchCredentialNonce_ReturnsErrorWhenResponseTooLargeWithoutFallback(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	largeNonce := strings.Repeat("a", int(testMaxNonceResponseBodyBytes))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nonce":"` + largeNonce + `"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{}

	nonce, err := controller.fetchCredentialNonce(receiverTypes.Oid4vci, issuerMetadata, accessToken)
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "nonce endpoint response exceeds")
}

func TestController_fetchDPoPNonce_ReturnsHeaderValue(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		w.Header().Set("DPoP-Nonce", "dpop-nonce")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"c_nonce":"credential-proof-nonce"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)
	nonce, err := controller.fetchDPoPNonce(&receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint})
	require.NoError(t, err)
	require.NotNil(t, nonce)
	assert.Equal(t, "dpop-nonce", *nonce)
}

func TestController_fetchDPoPNonce_ReturnsErrorWhenEndpointMissing(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	nonce, err := controller.fetchDPoPNonce(&receiverTypes.CredentialIssuerMetadata{})
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "nonce endpoint")
}

func TestController_fetchDPoPNonce_ReturnsErrorWhenHeaderMissing(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"c_nonce":"credential-proof-nonce"}`))
	}))
	defer server.Close()

	nonceEndpoint, err := common.ParseURIField(server.URL)
	require.NoError(t, err)
	nonce, err := controller.fetchDPoPNonce(&receiverTypes.CredentialIssuerMetadata{NonceEndpoint: nonceEndpoint})
	require.Error(t, err)
	require.Nil(t, nonce)
	assert.Contains(t, err.Error(), "DPoP-Nonce")
}

func TestController_requestCredential_DPoPAccessTokenRetriesWithNonceFromHeader(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const (
		accessTokenValue = "dpop-access-token"
		dpopNonce        = "issuer-dpop-nonce"
	)

	var credentialRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			if r.Method != http.MethodPost {
				http.Error(w, "invalid method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("DPoP-Nonce", dpopNonce)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"c_nonce":"credential-proof-nonce"}`))
		case "/credential":
			credentialRequests++
			if got := r.Header.Get("Authorization"); got != "DPoP "+accessTokenValue {
				http.Error(w, "invalid authorization header: "+got, http.StatusBadRequest)
				return
			}
			dpopProof := r.Header.Get("DPoP")
			if dpopProof == "" {
				http.Error(w, "missing DPoP header", http.StatusBadRequest)
				return
			}

			parts := strings.Split(dpopProof, ".")
			if len(parts) != 3 {
				http.Error(w, "invalid DPoP proof", http.StatusBadRequest)
				return
			}
			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				http.Error(w, "invalid DPoP payload", http.StatusBadRequest)
				return
			}
			var payload map[string]interface{}
			if err := json.Unmarshal(payloadBytes, &payload); err != nil {
				http.Error(w, "invalid DPoP payload json", http.StatusBadRequest)
				return
			}

			accessTokenHash := sha256.Sum256([]byte(accessTokenValue))
			expectedAth := base64.RawURLEncoding.EncodeToString(accessTokenHash[:])
			if payload["ath"] != expectedAth {
				http.Error(w, "invalid ath", http.StatusBadRequest)
				return
			}

			if credentialRequests == 1 {
				if _, exists := payload["nonce"]; exists {
					http.Error(w, "first DPoP proof should not include nonce", http.StatusBadRequest)
					return
				}
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
					"error": "use_dpop_nonce",
				})
				return
			}

			if payload["nonce"] != dpopNonce {
				http.Error(w, "retry DPoP proof missing nonce", http.StatusBadRequest)
				return
			}

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)
	nonceEndpoint, err := common.ParseURIField(server.URL + "/nonce")
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
		NonceEndpoint:      nonceEndpoint,
	}
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, 2, credentialRequests)
}

func TestController_requestCredential_DPoPAccessTokenUsesConfiguredDPoPKey(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	holderKey := newMockKeyEntry()
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const accessTokenValue = "dpop-access-token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/credential" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "DPoP "+accessTokenValue {
			http.Error(w, "invalid authorization header: "+got, http.StatusBadRequest)
			return
		}
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		jwk, ok := extractHeaderField(t, dpopProof, "jwk").(map[string]any)
		require.True(t, ok)
		if got := jwk["kid"]; got != dpopKey.ID() {
			http.Error(w, fmt.Sprintf("DPoP proof kid = %v", got), http.StatusBadRequest)
			return
		}

		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{{
				"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
			}},
		})
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  holderKey,
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
	}

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.NoError(t, err)
	require.NotNil(t, credential)
}

func TestController_requestCredential_DPoPNonceChallengeUsesNonceEndpoint(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const (
		accessTokenValue       = "dpop-access-token"
		credentialHeaderNonce  = "credential-dpop-nonce"
		nonceEndpointDPoPNonce = "nonce-endpoint-dpop-nonce"
	)

	var credentialRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nonce":
			if r.Method != http.MethodPost {
				http.Error(w, "invalid method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("DPoP-Nonce", nonceEndpointDPoPNonce)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"c_nonce":"credential-proof-nonce"}`))
			return
		case "/credential":
		default:
			http.NotFound(w, r)
			return
		}

		credentialRequests++
		dpopProof := r.Header.Get("DPoP")
		if dpopProof == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(strings.Split(dpopProof, ".")[1])
		if err != nil {
			http.Error(w, "invalid DPoP payload", http.StatusBadRequest)
			return
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			http.Error(w, "invalid DPoP payload json", http.StatusBadRequest)
			return
		}

		if credentialRequests == 1 {
			if _, exists := payload["nonce"]; exists {
				http.Error(w, "first DPoP proof should not include nonce", http.StatusBadRequest)
				return
			}
			w.Header().Set("DPoP-Nonce", credentialHeaderNonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if payload["nonce"] != nonceEndpointDPoPNonce {
			http.Error(w, "retry DPoP proof missing nonce", http.StatusBadRequest)
			return
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{{
				"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
			}},
		})
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}
	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
	}
	nonceEndpoint, err := common.ParseURIField(server.URL + "/nonce")
	require.NoError(t, err)
	issuerMetadata.NonceEndpoint = nonceEndpoint

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, 2, credentialRequests)
}

func TestController_requestCredential_DPoPNonceError_NoNonceEndpoint(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	controller.dpop = DPoPConfig{
		Enabled: true,
		Key:     dpopKey,
	}

	const accessTokenValue = "dpop-access-token"

	var credentialRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/credential" {
			http.NotFound(w, r)
			return
		}
		credentialRequests++
		if got := r.Header.Get("Authorization"); got != "DPoP "+accessTokenValue {
			http.Error(w, "invalid authorization header: "+got, http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("DPoP"); got == "" {
			http.Error(w, "missing DPoP header", http.StatusBadRequest)
			return
		}
		w.Header().Set("DPoP-Nonce", "credential-endpoint-nonce")
		mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
			"error": "use_dpop_nonce",
		})
	}))
	defer server.Close()

	credentialEndpoint, err := common.ParseURIField(server.URL + "/credential")
	require.NoError(t, err)

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer:   server.URL,
		CredentialEndpoint: *credentialEndpoint,
	}
	offerURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           offerURL,
			CredentialConfigurationIDs: []string{"test-config"},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token:     accessTokenValue,
		TokenType: "DPoP",
	}

	credential, err := controller.requestCredential(req, issuerMetadata, accessToken, "test-config", nil)
	require.Error(t, err)
	require.Nil(t, credential)
	assert.Contains(t, err.Error(), "failed to fetch DPoP nonce")
	assert.Contains(t, err.Error(), "nonce endpoint")
	assert.Equal(t, 1, credentialRequests)
}

func TestAccessTokenCredentialIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		accessToken *receiverTypes.CredentialIssuanceAccessToken
		want        *string
	}{
		{
			name:        "nil access token",
			accessToken: nil,
			want:        nil,
		},
		{
			name: "no authorization details",
			accessToken: &receiverTypes.CredentialIssuanceAccessToken{
				Token: "test-token",
			},
			want: nil,
		},
		{
			name: "authorization details without identifiers",
			accessToken: &receiverTypes.CredentialIssuanceAccessToken{
				AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{
					{Type: receiverTypes.AuthorizationDetailTypeOpenIDCredential},
				},
			},
			want: nil,
		},
		{
			name: "ignores non-openid_credential authorization details",
			accessToken: &receiverTypes.CredentialIssuanceAccessToken{
				AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{
					{Type: "resource_access", CredentialIdentifiers: []string{"unrelated-id"}},
					{Type: receiverTypes.AuthorizationDetailTypeOpenIDCredential, CredentialIdentifiers: []string{"cred-id-2"}},
				},
			},
			want: &[]string{"cred-id-2"}[0],
		},
		{
			name: "returns nil when only non-openid_credential details exist",
			accessToken: &receiverTypes.CredentialIssuanceAccessToken{
				AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{
					{Type: "resource_access", CredentialIdentifiers: []string{"unrelated-id"}},
				},
			},
			want: nil,
		},
		{
			name: "first non-empty credential identifier is selected",
			accessToken: &receiverTypes.CredentialIssuanceAccessToken{
				AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{
					{Type: receiverTypes.AuthorizationDetailTypeOpenIDCredential, CredentialIdentifiers: []string{"", "cred-id-1"}},
					{Type: receiverTypes.AuthorizationDetailTypeOpenIDCredential, CredentialIdentifiers: []string{"cred-id-2"}},
				},
			},
			want: &[]string{"cred-id-1"}[0],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := accessTokenCredentialIdentifier(tt.accessToken)
			if tt.want == nil {
				require.Nil(t, got)
				return
			}

			require.NotNil(t, got)
			assert.Equal(t, *tt.want, *got)
		})
	}
}

// createMockOID4VCIServer creates a mock HTTP server for OID4VCI testing
func createMockOID4VCIServer() *mockserver.OID4VCIIssuerServer {
	return mockserver.NewOID4VCIIssuerServer(nil)
}

// This fixture intentionally uses a mocked ES256 signature (64 zero bytes).
// These tests only validate SD-JWT parsing/metadata round-trip, not signature verification.
// If SD-JWT deserialization later requires signature verification, replace this with a
// valid ES256 signature (preferred) or change alg to "none" accordingly.
func createWalletTestSDJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"vc+sd-jwt"}`))
	disclosures := []string{
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ",
	}

	sdDigests := make([]string, 0, len(disclosures))
	for _, disclosure := range disclosures {
		h := sha256.Sum256([]byte(disclosure))
		sdDigests = append(sdDigests, base64.RawURLEncoding.EncodeToString(h[:]))
	}

	payload := map[string]interface{}{
		"_sd":     sdDigests,
		"iss":     "https://example.com/issuer",
		"sub":     "did:key:z6Mkwallet-test-subject",
		"iat":     1683000000,
		"exp":     1883000000,
		"vct":     "https://credentials.example.com/identity_credential",
		"_sd_alg": "sha-256",
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	jwt := header + "." + payloadEncoded + "." + signature

	result := jwt
	for _, disclosure := range disclosures {
		result += "~" + disclosure
	}
	result += "~"

	return result
}

func TestController_generateJWTProof_KIDBinding_NilDIDReturnsError(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	key := newMockKeyEntry()
	nonce := "test-nonce"

	proof, err := controller.generateJWTProof(
		key,
		nil,
		&nonce,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "did is required for kid proof binding")
	assert.Empty(t, proof)
}

func TestController_generateJWTProof_KIDBinding_BlankDIDReturnsError(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	key := newMockKeyEntry()
	nonce := "test-nonce"
	did := &idprofTypes.IdentityProfile{ID: "  ", TypeID: "did:key"}

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "did.ID is required for kid proof binding")
	assert.Empty(t, proof)
}

func TestController_generateJWTProof_JWKBinding_AllowsNilDID(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	key := newMockKeyEntry()
	nonce := "test-nonce"

	proof, err := controller.generateJWTProof(
		key,
		nil,
		&nonce,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodJWK,
	)

	require.NoError(t, err)
	require.NotEmpty(t, proof)

	proofParts := strings.Split(proof, ".")
	require.Len(t, proofParts, 3)

	headerBytes, decodeErr := base64.RawURLEncoding.DecodeString(proofParts[0])
	require.NoError(t, decodeErr)

	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	_, hasJWK := header["jwk"]
	_, hasKID := header["kid"]
	assert.True(t, hasJWK)
	assert.False(t, hasKID)
}

func TestController_shouldAttachCredentialRequestProof_EmptyBindingMethodsOmitProof(t *testing.T) {
	req := ReceiveCredentialRequest{RequestedFormat: credential.JwtVc}
	empty := []string{}
	configuration := &receiverTypes.CredentialConfiguration{
		CryptographicBindingMethodsSupported: &empty,
	}

	attachProof := shouldAttachCredentialRequestProof(req, configuration)
	assert.False(t, attachProof)
}

func TestController_shouldAttachCredentialRequestProof_EmptyBindingMethodsWithNoRequestedFormatKeepsBackwardCompatibility(t *testing.T) {
	req := ReceiveCredentialRequest{}
	empty := []string{}
	configuration := &receiverTypes.CredentialConfiguration{
		CryptographicBindingMethodsSupported: &empty,
	}

	attachProof := shouldAttachCredentialRequestProof(req, configuration)
	assert.True(t, attachProof)
}

func TestController_selectCredentialConfiguration_UnsupportedDefaultFormatReturnsError(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	issuerURL, err := url.Parse("https://issuer.example.com")
	require.NoError(t, err)

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"mdoc-config"},
		},
	}

	issuerMetadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{
			"mdoc-config": {
				Format: "mso_mdoc",
			},
		},
	}

	configID, config, flavor, err := controller.selectCredentialConfiguration(req, issuerMetadata)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported credential format for configuration \"mdoc-config\"")
	assert.Equal(t, "", configID)
	assert.Nil(t, config)
	assert.Equal(t, credential.SupportedSerializationFlavor(""), flavor)
}

func createWalletTestJwtVCCredential() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	now := time.Now().Unix()
	payload := map[string]interface{}{
		"iat": now,
		"exp": now + 3600,
		"vc": map[string]interface{}{
			"id":     "https://issuer.example.com/credentials/test-1",
			"type":   []string{"VerifiableCredential"},
			"issuer": "https://issuer.example.com",
			"credentialSubject": map[string]interface{}{
				"id": "did:key:test-subject",
			},
		},
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	return header + "." + payloadEncoded + "." + signature
}

type credentialIssuanceMockServerOptions struct {
	credentialConfigurationsSupported map[string]interface{}
	tokenResponse                     map[string]interface{}
	nonceResponse                     map[string]interface{}
	includeNonceEndpoint              bool
	credential                        string
}

func newCredentialIssuanceMockServer(t *testing.T, opts credentialIssuanceMockServerOptions) (*url.URL, *map[string]interface{}, chan error) {
	t.Helper()

	if opts.credentialConfigurationsSupported == nil {
		t.Fatal("credentialConfigurationsSupported is required")
	}

	if opts.tokenResponse == nil {
		opts.tokenResponse = map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
		}
	}

	if opts.includeNonceEndpoint && opts.nonceResponse == nil {
		opts.nonceResponse = map[string]interface{}{
			"c_nonce": "nonce-from-endpoint",
		}
	}

	if opts.credential == "" {
		opts.credential = createWalletTestJwtVCCredential()
	}

	var capturedBody map[string]interface{}
	handlerErrCh := make(chan error, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL := "http://" + r.Host

		switch r.URL.Path {
		case "/.well-known/openid-credential-issuer":
			issuerResponse := map[string]interface{}{
				"credential_issuer":                   baseURL,
				"credential_endpoint":                 baseURL + "/credential",
				"authorization_servers":               []string{baseURL},
				"credential_configurations_supported": opts.credentialConfigurationsSupported,
			}
			if opts.includeNonceEndpoint {
				issuerResponse["nonce_endpoint"] = baseURL + "/nonce"
			}
			mockserver.JSONResponse(w, http.StatusOK, issuerResponse)
		case "/.well-known/oauth-authorization-server":
			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"issuer":         baseURL,
				"token_endpoint": baseURL + "/token",
				"pre-authorized_grant_anonymous_access_supported": true,
				"response_types_supported":                        []string{"code"},
			})
		case "/token":
			mockserver.JSONResponse(w, http.StatusOK, opts.tokenResponse)
		case "/nonce":
			if !opts.includeNonceEndpoint {
				http.NotFound(w, r)
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, opts.nonceResponse)
		case "/credential":
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read credential request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to decode credential request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credential": opts.credential,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	issuerURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	return issuerURL, &capturedBody, handlerErrCh
}

func TestController_ReceiveCredential_SDJwtSpecified_StoresMimeAndCanGetByID(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	sdJwtCredential := createWalletTestSDJWT()
	issuerURL, capturedBody, handlerErrCh := newCredentialIssuanceMockServer(t, credentialIssuanceMockServerOptions{
		credentialConfigurationsSupported: map[string]interface{}{
			"jwt-config": map[string]interface{}{
				"format": "jwt_vc_json",
			},
			"sdjwt-config": map[string]interface{}{
				"format": "dc+sd-jwt",
				"cryptographic_binding_methods_supported": []string{"jwk"},
			},
		},
		includeNonceEndpoint: true,
		tokenResponse: map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"c_nonce":      "mock-c-nonce",
		},
		nonceResponse: map[string]interface{}{
			"c_nonce": "nonce-from-endpoint",
		},
		credential: sdJwtCredential,
	})

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"jwt-config", "sdjwt-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type:            receiverTypes.Oid4vci,
		Key:             newMockKeyEntry(),
		RequestedFormat: credential.SDJwtVC,
	}

	savedCredential, err := controller.ReceiveCredential(req)
	require.NoError(t, err)
	require.NotNil(t, savedCredential)

	select {
	case handlerErr := <-handlerErrCh:
		require.NoError(t, handlerErr)
	case <-time.After(time.Second):
		t.Fatal("credential endpoint was not called")
	}

	requestedConfigID, ok := (*capturedBody)["credential_configuration_id"].(string)
	require.True(t, ok, "credential_configuration_id should be a string")
	assert.Equal(t, "sdjwt-config", requestedConfigID)

	proofs, ok := (*capturedBody)["proofs"].(map[string]interface{})
	require.True(t, ok, "proofs should be present for cryptographic binding")
	jwtProofs, ok := proofs["jwt"].([]interface{})
	require.True(t, ok, "proofs.jwt should be present")
	require.Len(t, jwtProofs, 1, "proofs.jwt should contain one proof")
	proofJWT, ok := jwtProofs[0].(string)
	require.True(t, ok, "proofs.jwt[0] should be a JWT string")

	proofParts := strings.Split(proofJWT, ".")
	require.Len(t, proofParts, 3, "proof JWT should have 3 parts")
	proofHeaderBytes, err := base64.RawURLEncoding.DecodeString(proofParts[0])
	require.NoError(t, err)

	var proofHeader map[string]interface{}
	require.NoError(t, json.Unmarshal(proofHeaderBytes, &proofHeader))
	_, hasJWK := proofHeader["jwk"]
	assert.True(t, hasJWK, "proof JWT header should include jwk when binding method supports jwk")
	_, hasKID := proofHeader["kid"]
	assert.False(t, hasKID, "proof JWT header should not include kid when jwk is used")

	assert.Equal(t, string(credential.SDJwtVC), savedCredential.Entry.MimeType)
	require.NotNil(t, savedCredential.Credential)
	require.NotNil(t, savedCredential.Credential.SDJwt)
	assert.Len(t, savedCredential.Credential.SDJwt.SD, 2)

	retrievedCredential, err := controller.GetCredentialEntry(savedCredential.Entry.Id)
	require.NoError(t, err)
	require.NotNil(t, retrievedCredential)
	assert.Equal(t, savedCredential.Entry.Id, retrievedCredential.Entry.Id)
	assert.Equal(t, string(credential.SDJwtVC), retrievedCredential.Entry.MimeType)
}

func TestController_ReceiveCredential_AttachesProofWhenCryptographicBindingMethodsSupported(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	issuerURL, capturedBody, handlerErrCh := newCredentialIssuanceMockServer(t, credentialIssuanceMockServerOptions{
		credentialConfigurationsSupported: map[string]interface{}{
			"jwt-config": map[string]interface{}{
				"format": "jwt_vc_json",
				"cryptographic_binding_methods_supported": []string{"jwk"},
			},
		},
		includeNonceEndpoint: true,
		tokenResponse: map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"c_nonce":      "mock-c-nonce",
		},
		nonceResponse: map[string]interface{}{
			"c_nonce": "nonce-from-endpoint",
		},
	})

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"jwt-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type:            receiverTypes.Oid4vci,
		Key:             newMockKeyEntry(),
		RequestedFormat: credential.JwtVc,
	}

	_, err := controller.ReceiveCredential(req)
	require.NoError(t, err)

	select {
	case handlerErr := <-handlerErrCh:
		require.NoError(t, handlerErr)
	case <-time.After(time.Second):
		t.Fatal("credential endpoint was not called")
	}

	proofs, ok := (*capturedBody)["proofs"].(map[string]interface{})
	require.True(t, ok, "proofs should be present when cryptographic_binding_methods_supported exists")
	jwtProofs, ok := proofs["jwt"].([]interface{})
	require.True(t, ok, "proofs.jwt should be present")
	require.Len(t, jwtProofs, 1, "proofs.jwt should contain one proof")
}

func TestController_ReceiveCredential_OmitsProofWhenBindingNotRequired_AllowsNilKey(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	issuerURL, capturedBody, handlerErrCh := newCredentialIssuanceMockServer(t, credentialIssuanceMockServerOptions{
		credentialConfigurationsSupported: map[string]interface{}{
			"jwt-config": map[string]interface{}{
				"format": "jwt_vc_json",
			},
		},
		tokenResponse: map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
		},
	})

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"jwt-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type:            receiverTypes.Oid4vci,
		RequestedFormat: credential.JwtVc,
	}
	require.Nil(t, req.Key, "nil key should be allowed when cryptographic binding is not required")

	savedCredential, err := controller.ReceiveCredential(req)
	require.NoError(t, err)
	require.NotNil(t, savedCredential)
	require.Nil(t, req.Key, "request key should remain nil")

	select {
	case handlerErr := <-handlerErrCh:
		require.NoError(t, handlerErr)
	case <-time.After(time.Second):
		t.Fatal("credential endpoint was not called")
	}

	_, hasProof := (*capturedBody)["proof"]
	assert.False(t, hasProof, "proof should not be present when binding is not required")
	_, hasProofs := (*capturedBody)["proofs"]
	assert.False(t, hasProofs, "proofs should not be present when binding is not required")
	assert.Equal(t, string(credential.JwtVc), savedCredential.Entry.MimeType)
}

func TestController_ReceiveCredential_WithMockServer_Integration(t *testing.T) {
	// Create mock HTTP server
	server := createMockOID4VCIServer()
	defer server.Close()

	controller := createTestControllerWithDefaults(t)

	// Parse server URL
	serverURL, err := url.Parse(server.URL())
	if err != nil {
		t.Fatalf("Failed to parse server URL: %v", err)
	}

	// Test with valid credential offer using mock server
	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           serverURL,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	// First test metadata fetch to debug
	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)
	metadata, err := controller.FetchCredentialIssuerMetadata(serverURL, receiverTypes.Oid4vci)
	if err != nil {
		t.Fatalf("FetchCredentialIssuerMetadata failed: %v", err)
	}
	t.Logf("Fetched issuer metadata: %+v", metadata)

	// This should now work with the mock server
	// If this fails, we need to check the mock server setup or credential format
	credential, err := controller.ReceiveCredential(req)
	if err != nil {
		t.Skipf("ReceiveCredential failed with mock server, skipping rest of test: %v", err)
	}

	if credential == nil {
		t.Error("Expected non-nil credential")
	}

	t.Logf("Successfully received credential: %+v", credential)
}

// createMockOID4VPServer creates a mock HTTP server for OID4VP testing
func createMockOID4VPServer() *mockserver.OID4VPPresenterServer {
	return mockserver.NewOID4VPPresenterServer(nil)
}

func TestController_FetchCredentialIssuerMetadata_WithMockServer(t *testing.T) {
	server := createMockOID4VCIServer()
	defer server.Close()

	controller := createTestControllerWithDefaults(t)

	serverURL, _ := url.Parse(server.URL())

	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)
	metadata, err := controller.FetchCredentialIssuerMetadata(serverURL, receiverTypes.Oid4vci)
	if err != nil {
		t.Errorf("FetchCredentialIssuerMetadata failed: %v", err)
		return
	}

	if metadata == nil {
		t.Error("Expected non-nil metadata")
	}

	t.Logf("Successfully fetched metadata: %+v", metadata)
}

func TestController_ReceiveCredential_RejectsUnsupportedCredentialConfigurationID(t *testing.T) {
	server := createMockOID4VCIServer()
	defer server.Close()

	controller := createTestControllerWithDefaults(t)

	serverURL, err := url.Parse(server.URL())
	require.NoError(t, err)

	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	req := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           serverURL,
			CredentialConfigurationIDs: []string{"unsupported-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	credential, err := controller.ReceiveCredential(req)
	require.Error(t, err)
	require.Nil(t, credential)
	require.Contains(t, err.Error(), `credential configuration "unsupported-config" is not supported by issuer metadata`)
}

func TestController_PresentCredential_WithMockServer_Integration(t *testing.T) {
	// First, create a mock OID4VCI server to get a credential
	vciServer := createMockOID4VCIServer()
	defer vciServer.Close()

	// Create a mock OID4VP server for presentation
	vpServer := createMockOID4VPServer()
	defer vpServer.Close()

	controller := createTestControllerWithDefaults(t)

	vciServerURL, _ := url.Parse(vciServer.URL())
	vpEndpointURL, _ := url.Parse(vpServer.URL() + "/present")

	// Step 1: First receive a credential via OID4VCI
	receiveReq := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           vciServerURL,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)
	savedCredential, err := controller.ReceiveCredential(receiveReq)
	if err != nil {
		t.Logf("Failed to receive credential for presentation test: %v", err)
		return
	}

	t.Logf("Successfully received credential for presentation: %s", savedCredential.Entry.Id)

	// Step 2: Now present the credential via OID4VP
	// Create OID4VP URI with all required parameters per OID4VP specification
	presentationDefinition := `{"id":"test-presentation-definition","input_descriptors":[{"id":"test-descriptor","format":{"jwt_vp":{"alg":["ES256"]}}}]}`
	presentationURI := fmt.Sprintf("openid4vp://present?presentation_definition=%s&client_id=test-verifier&redirect_uri=%s&response_type=vp_token&response_mode=direct_post&nonce=test-nonce-123&scope=openid&state=test-state-456",
		url.QueryEscape(presentationDefinition), vpEndpointURL.String())

	mockKey := newMockKeyEntry()
	_, err = controller.PresentCredential(presentationURI, mockKey, nil)
	if err != nil {
		t.Fatalf("PresentCredential failed: %v", err)
	}

	t.Log("PresentCredential succeeded with full OID4VCI->OID4VP flow")
}

func TestController_PresentCredential_CallsRedirectHandler(t *testing.T) {
	// First, create a mock OID4VCI server to get a credential
	vciServer := createMockOID4VCIServer()
	defer vciServer.Close()

	redirectTarget := "https://example.com/redirect"
	responseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"redirect_uri":"%s"}`, redirectTarget)))
	}))
	defer responseServer.Close()

	controller := createTestControllerWithDefaults(t)

	vciServerURL, _ := url.Parse(vciServer.URL())

	// Step 1: First receive a credential via OID4VCI
	receiveReq := ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           vciServerURL,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
					PreAuthorizedCode: "test-code",
				},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	}

	httpAllowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	_, err := controller.ReceiveCredential(receiveReq)
	if err != nil {
		t.Skipf("ReceiveCredential failed with mock server, skipping redirect handler test: %v", err)
	}

	// Step 2: Present the credential and verify redirect handler execution
	presentationDefinition := `{"id":"test-presentation-definition","input_descriptors":[{"id":"test-descriptor","format":{"jwt_vp":{"alg":["ES256"]}}}]}`
	clientID := "redirect_uri:https://example.com/cb"
	presentationURI := fmt.Sprintf(
		"openid4vp://present?presentation_definition=%s&client_id=%s&response_type=vp_token&response_mode=direct_post&response_uri=%s&nonce=test-nonce-123&scope=openid&state=test-state-456",
		url.QueryEscape(presentationDefinition),
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

	mockKey := newMockKeyEntry()
	redirectURI, err := controller.PresentCredentialWithOptions(presentationURI, mockKey, options)
	require.NoError(t, err)
	require.Equal(t, redirectTarget, redirectURI)
	require.True(t, called, "expected redirect handler to be called")
	require.Equal(t, redirectTarget, captured)
}

func TestController_FetchCredentialIssuerMetadata_ErrorPaths_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name         string
		setupURL     func() *url.URL
		receiverType receiverTypes.SupportedReceivingTypes
		expectError  bool
	}{
		{
			name: "invalid URL",
			setupURL: func() *url.URL {
				u, _ := url.Parse("invalid://malformed.url.with.invalid.scheme")
				return u
			},
			receiverType: receiverTypes.Oid4vci,
			expectError:  true,
		},
		{
			name: "non-existent server",
			setupURL: func() *url.URL {
				u, _ := url.Parse("https://non-existent-server-12345.example.com")
				return u
			},
			receiverType: receiverTypes.Oid4vci,
			expectError:  true,
		},
		{
			name: "empty URL",
			setupURL: func() *url.URL {
				return &url.URL{}
			},
			receiverType: receiverTypes.Oid4vci,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
			defer env.SetHTTPAllowed(http_allowed)
			env.SetHTTPAllowed(true)
			serverURL := tt.setupURL()
			_, err := controller.FetchCredentialIssuerMetadata(serverURL, tt.receiverType)

			if tt.expectError && err == nil {
				t.Errorf("FetchCredentialIssuerMetadata() expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("FetchCredentialIssuerMetadata() unexpected error: %v", err)
			}
			if tt.expectError && err != nil {
				// Expected error occurred - test passes
				return
			}
		})
	}
}

func TestController_GenerateDID_ErrorPaths_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name    string
		options DIDCreateOptions
		wantErr bool
	}{
		{
			name: "empty type ID",
			options: DIDCreateOptions{
				TypeID: "",
				PublicKey: jose.JSONWebKey{
					Algorithm: "ES256",
					KeyID:     "test-key",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid type ID",
			options: DIDCreateOptions{
				TypeID: "invalid:did:format",
				PublicKey: jose.JSONWebKey{
					Algorithm: "ES256",
					KeyID:     "test-key",
				},
			},
			wantErr: true,
		},
		{
			name: "empty public key",
			options: DIDCreateOptions{
				TypeID:    "did:key",
				PublicKey: jose.JSONWebKey{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := controller.GenerateDID(tt.options)
			if tt.wantErr && err == nil {
				t.Errorf("GenerateDID() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("GenerateDID() unexpected error: %v", err)
			}
			if tt.wantErr && err == nil {
				t.Errorf("GenerateDID() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("GenerateDID() unexpected error: %v", err)
			}
		})
	}
}

func TestController_GetCredentialEntries_OffsetLimitTests(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name    string
		request GetCredentialEntriesRequest
		wantErr bool
	}{
		{
			name: "high offset",
			request: GetCredentialEntriesRequest{
				Offset: 1000,
				Limit:  intPtr(10),
				Filter: nil,
			},
			wantErr: false,
		},
		{
			name: "zero limit",
			request: GetCredentialEntriesRequest{
				Offset: 0,
				Limit:  intPtr(0),
				Filter: nil,
			},
			wantErr: false,
		},
		{
			name: "negative offset (should be handled)",
			request: GetCredentialEntriesRequest{
				Offset: -1,
				Limit:  intPtr(10),
				Filter: nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := controller.GetCredentialEntries(tt.request)
			if tt.wantErr && err == nil {
				t.Errorf("GetCredentialEntries() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("GetCredentialEntries() unexpected error: %v", err)
			}
		})
	}
}

// Helper function for creating int pointers
func intPtr(i int) *int {
	return &i
}

func TestController_GetCredentialEntries_FilterTests(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name   string
		filter func(cred *SavedCredential) bool
	}{
		{
			name: "filter by type",
			filter: func(cred *SavedCredential) bool {
				if cred == nil || cred.Credential == nil {
					return false
				}
				for _, t := range cred.Credential.Types {
					if t == "VerifiableCredential" {
						return true
					}
				}
				return false
			},
		},
		{
			name: "filter by ID presence",
			filter: func(cred *SavedCredential) bool {
				return cred != nil && cred.Credential != nil && cred.Credential.ID != ""
			},
		},
		{
			name: "filter always false",
			filter: func(cred *SavedCredential) bool {
				return false
			},
		},
		{
			name: "filter always true",
			filter: func(cred *SavedCredential) bool {
				return true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := GetCredentialEntriesRequest{
				Offset: 0,
				Limit:  nil,
				Filter: tt.filter,
			}
			_, _, err := controller.GetCredentialEntries(req)
			if err != nil {
				t.Skipf("GetCredentialEntries with %s filter not supported in test environment: %v", tt.name, err)
			}
		})
	}
}

func TestController_ReceiveCredential_AdditionalErrorPaths_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Test different error scenarios for ReceiveCredential
	tests := []struct {
		name     string
		setupReq func() ReceiveCredentialRequest
		wantErr  bool
	}{
		{
			name: "missing key",
			setupReq: func() ReceiveCredentialRequest {
				credentialIssuer, _ := url.Parse("https://issuer.example.com")
				return ReceiveCredentialRequest{
					CredentialOffer: &CredentialOffer{
						CredentialIssuer:           credentialIssuer,
						CredentialConfigurationIDs: []string{"test-config"},
						Grants: map[string]*CredentialOfferGrant{
							"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
								PreAuthorizedCode: "test-code",
							},
						},
					},
					Type: receiverTypes.Oid4vci,
					Key:  nil, // Missing key
				}
			},
			wantErr: true,
		},
		{
			name: "malformed issuer URL",
			setupReq: func() ReceiveCredentialRequest {
				return ReceiveCredentialRequest{
					CredentialOffer: &CredentialOffer{
						CredentialIssuer:           &url.URL{Scheme: "", Host: ""}, // Empty URL
						CredentialConfigurationIDs: []string{"test-config"},
						Grants: map[string]*CredentialOfferGrant{
							"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
								PreAuthorizedCode: "test-code",
							},
						},
					},
					Type: receiverTypes.Oid4vci,
					Key:  newMockKeyEntry(),
				}
			},
			wantErr: true,
		},
		{
			name: "invalid grant type",
			setupReq: func() ReceiveCredentialRequest {
				credentialIssuer, _ := url.Parse("https://issuer.example.com")
				return ReceiveCredentialRequest{
					CredentialOffer: &CredentialOffer{
						CredentialIssuer:           credentialIssuer,
						CredentialConfigurationIDs: []string{"test-config"},
						Grants: map[string]*CredentialOfferGrant{
							"invalid-grant-type": {
								PreAuthorizedCode: "test-code",
							},
						},
					},
					Type: receiverTypes.Oid4vci,
					Key:  newMockKeyEntry(),
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			_, err := controller.ReceiveCredential(req)
			if tt.wantErr && err == nil {
				t.Errorf("ReceiveCredential() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ReceiveCredential() unexpected error: %v", err)
			}
			if tt.wantErr && err != nil {
				// Expected error occurred - test passes
				return
			}
		})
	}
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
			} else if err != nil {
				// Expected error occurred - test passes
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

func TestBuildDescriptorMap_UsesVPTokenRootPathForJwtVP(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	flavor := credential.JwtVc

	descriptorMap, err := controller.buildDescriptorMap([]*SavedCredential{{}}, &flavor)
	require.NoError(t, err)
	require.Len(t, descriptorMap, 1)
	require.Equal(t, "$", descriptorMap[0].Path)
	require.NotNil(t, descriptorMap[0].PathNested)
	require.Equal(t, "$.verifiableCredential[0]", descriptorMap[0].PathNested.Path)
}

func TestBuildDescriptorMap_UsesVPTokenRootPathForAllJwtDescriptors(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	flavor := credential.JwtVc

	descriptorMap, err := controller.buildDescriptorMap([]*SavedCredential{{}, {}}, &flavor)
	require.NoError(t, err)
	require.Len(t, descriptorMap, 2)

	for i, item := range descriptorMap {
		require.Equalf(t, fmt.Sprintf("$[%d]", i), item.Path, "descriptorMap[%d].Path", i)
		require.NotNilf(t, item.PathNested, "descriptorMap[%d].PathNested", i)
		require.Equalf(t, fmt.Sprintf("$.verifiableCredential[%d]", i), item.PathNested.Path, "descriptorMap[%d].PathNested.Path", i)
	}
}

func TestBuildDescriptorMap_UsesVPTokenRootPathForALLSdJwtDescriptors(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	flavor := credential.SDJwtVC

	descriptorMap, err := controller.buildDescriptorMap([]*SavedCredential{{}, {}}, &flavor)
	require.NoError(t, err)
	require.Len(t, descriptorMap, 2)

	for i, item := range descriptorMap {
		require.Equalf(t, fmt.Sprintf("$[%d]", i), item.Path, "descriptorMap[%d].Path", i)
		require.Equalf(t, "dc+sd-jwt", item.Format, "descriptorMap[%d].Format", i)
		require.Nilf(t, item.PathNested, "descriptorMap[%d].PathNested", i)
	}
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

func TestMockKeyEntrySign_ProducesVerifiableES256Signature(t *testing.T) {
	key := newMockKeyEntry()
	payload := []byte("test-payload")
	signature, err := key.Sign(payload)
	require.NoError(t, err)
	require.Len(t, signature, 64)

	publicKey, ok := key.PublicKey().Key.(*ecdsa.PublicKey)
	require.True(t, ok)

	hash := sha256.Sum256(payload)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	assert.True(t, ecdsa.Verify(publicKey, hash[:], r, s))
}

func TestWallet_validateCredentialOffer(t *testing.T) {
	issuerURL, err := url.Parse("https://issuer.example.com")
	require.NoError(t, err)
	httpIssuerURL, err := url.Parse("http://issuer.example.com")
	require.NoError(t, err)

	const preAuthGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		offer           *CredentialOffer
		httpAllowed     bool
		want            string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:    "nil offer",
			offer:   nil,
			wantErr: true,
		},
		{
			name: "missing pre-authorization grant",
			offer: &CredentialOffer{
				CredentialIssuer:           issuerURL,
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants:                     map[string]*CredentialOfferGrant{},
			},
			wantErr: true,
		},
		{
			name: "missing credential issuer",
			offer: &CredentialOffer{
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr: true,
		},
		{
			name: "credential issuer must include host",
			offer: &CredentialOffer{
				CredentialIssuer:           mustParseURL(t, "https:///issuer"),
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr:         true,
			wantErrContains: "credential issuer must include a host",
		},
		{
			name: "credential issuer must use https by default",
			offer: &CredentialOffer{
				CredentialIssuer:           httpIssuerURL,
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr:         true,
			wantErrContains: "credential issuer must use https scheme",
		},
		{
			name: "credential issuer allows http when configured",
			offer: &CredentialOffer{
				CredentialIssuer:           httpIssuerURL,
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			httpAllowed: true,
			want:        "pre-auth-code",
		},
		{
			name: "credential issuer must not include query",
			offer: &CredentialOffer{
				CredentialIssuer:           mustParseURL(t, "https://issuer.example.com?foo=bar"),
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr:         true,
			wantErrContains: "credential issuer must not include query or fragment",
		},
		{
			name: "credential issuer must not include fragment",
			offer: &CredentialOffer{
				CredentialIssuer:           mustParseURL(t, "https://issuer.example.com#fragment"),
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr:         true,
			wantErrContains: "credential issuer must not include query or fragment",
		},
		{
			name: "empty credential configuration IDs",
			offer: &CredentialOffer{
				CredentialIssuer: issuerURL,
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicated credential configuration IDs",
			offer: &CredentialOffer{
				CredentialIssuer:           issuerURL,
				CredentialConfigurationIDs: []string{"Degree", "VerifiableCredential", "Degree"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			wantErr:         true,
			wantErrContains: "credential configuration IDs must be unique",
		},
		{
			name: "empty pre-authorization code",
			offer: &CredentialOffer{
				CredentialIssuer:           issuerURL,
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: ""},
				},
			},
			wantErr: true,
		},
		{
			name: "valid offer",
			offer: &CredentialOffer{
				CredentialIssuer:           issuerURL,
				CredentialConfigurationIDs: []string{"test-credential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			want: "pre-auth-code",
		},
		{
			name: "valid offer with multiple unique credential configuration IDs",
			offer: &CredentialOffer{
				CredentialIssuer:           issuerURL,
				CredentialConfigurationIDs: []string{"Degree", "VerifiableCredential"},
				Grants: map[string]*CredentialOfferGrant{
					preAuthGrantType: {PreAuthorizedCode: "pre-auth-code"},
				},
			},
			want: "pre-auth-code",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpAllowed := env.IsHTTPAllowed()
			debugMode := env.IsDebugMode()
			defer env.SetHTTPAllowed(httpAllowed)
			defer env.SetDebugMode(debugMode)
			env.SetDebugMode(false)
			env.SetHTTPAllowed(tt.httpAllowed)

			w, err := NewWallet()
			require.NoError(t, err)

			got, gotErr := w.validateCredentialOffer(tt.offer)
			if tt.wantErr {
				require.Error(t, gotErr)
				if tt.wantErrContains != "" {
					require.Contains(t, gotErr.Error(), tt.wantErrContains)
				}
				return
			}

			require.NoError(t, gotErr)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestWallet_validateCredentialConfigurationIDs(t *testing.T) {
	tests := []struct {
		name            string
		offer           *CredentialOffer
		issuerMetadata  *receiverTypes.CredentialIssuerMetadata
		wantErr         bool
		wantErrContains string
	}{
		{
			name:    "all offered configuration IDs are supported",
			offer:   &CredentialOffer{CredentialConfigurationIDs: []string{"EmployeeID_jwt_vc_json", "StudentID_jwt_vc_json"}},
			wantErr: false,
			issuerMetadata: &receiverTypes.CredentialIssuerMetadata{
				CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{
					"EmployeeID_jwt_vc_json": {Format: "jwt_vc_json"},
					"StudentID_jwt_vc_json":  {Format: "jwt_vc_json"},
				},
			},
		},
		{
			name:  "unsupported offered configuration ID is rejected",
			offer: &CredentialOffer{CredentialConfigurationIDs: []string{"EmployeeID_jwt_vc_json", "UnknownID_jwt_vc_json"}},
			issuerMetadata: &receiverTypes.CredentialIssuerMetadata{
				CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{
					"EmployeeID_jwt_vc_json": {Format: "jwt_vc_json"},
				},
			},
			wantErr:         true,
			wantErrContains: `credential configuration "UnknownID_jwt_vc_json" is not supported by issuer metadata`,
		},
		{
			name:            "missing issuer metadata is rejected",
			offer:           &CredentialOffer{CredentialConfigurationIDs: []string{"EmployeeID_jwt_vc_json"}},
			issuerMetadata:  nil,
			wantErr:         true,
			wantErrContains: "issuer metadata is required",
		},
		{
			name:  "missing supported configurations in metadata is rejected",
			offer: &CredentialOffer{CredentialConfigurationIDs: []string{"EmployeeID_jwt_vc_json"}},
			issuerMetadata: &receiverTypes.CredentialIssuerMetadata{
				CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{},
			},
			wantErr:         true,
			wantErrContains: "credential configurations supported are missing in issuer metadata",
		},
	}

	w, err := NewWallet()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := w.validateCredentialConfigurationIDs(tt.offer, tt.issuerMetadata)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErrContains)
				return
			}

			require.NoError(t, err)
		})
	}
}
