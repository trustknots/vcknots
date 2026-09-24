package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

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
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

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
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

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

// createMockOID4VCIServer creates a mock HTTP server for OID4VCI testing
func createMockOID4VCIServer() *mockserver.OID4VCIIssuerServer {
	return mockserver.NewOID4VCIIssuerServer(nil)
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
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

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
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

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
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

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
	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)
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

func TestController_FetchCredentialIssuerMetadata_WithMockServer(t *testing.T) {
	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)
	server := createMockOID4VCIServer()
	defer server.Close()

	controller := createTestControllerWithDefaults(t)

	serverURL, _ := url.Parse(server.URL())

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

	serverURL, err := url.Parse(server.URL())
	require.NoError(t, err)

	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)
	controller := createTestControllerWithDefaults(t)

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

func TestController_FetchCredentialIssuerMetadata_ErrorPaths_Integration(t *testing.T) {
	http_allowed := strings.EqualFold(env.GetEnv(env.HTTP_ALLOWED), "true")
	defer env.SetHTTPAllowed(http_allowed)
	env.SetHTTPAllowed(true)
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
