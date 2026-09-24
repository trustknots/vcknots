package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

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

	obs := newServerObservations(t, "token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		tokenRequests := obs.called("token")
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
	assert.Equal(t, 2, obs.callCount("token"))
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
		TokenEndpointAuthSigningAlgValuesSupported: &[]jose.SignatureAlgorithm{jose.ES256},
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
		PreAuthorizedGrantAnonymous:       mockserver.BoolPtr(false),
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

	// Fix the expected aud on the server side. Letting the mock derive it from
	// the incoming request would make the check tautological, since the wallet
	// resolves the same value from this server's metadata.
	issuerConfig.ClientAssertionAudience = issuer.URL()

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

func TestWallet_fetchCredentialMetadata_UsesCredentialIssuerAsAuthorizationServerWhenOmitted(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	key, _ := newClientAuthKeyEntry(t, "client-key-1")
	issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
		KeyPair:                           mockserver.MustGenerateKeyPair("issuer-key-id"),
		IssuerID:                          "test-issuer",
		PreAuthorizedGrantAnonymous:       mockserver.BoolPtr(false),
		OmitAuthorizationServers:          true,
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

func TestWallet_fetchCredentialMetadata_RejectsEmptyAuthorizationServers(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
		KeyPair:                     mockserver.MustGenerateKeyPair("issuer-key-id"),
		PreAuthorizedGrantAnonymous: mockserver.BoolPtr(true),
		EmptyAuthorizationServers:   true,
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
	dispatcher, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	require.NoError(t, err)
	w := &Wallet{receiver: dispatcher}

	_, _, err = w.fetchCredentialMetadata(ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{"test-config"},
			Grants:                     map[string]*CredentialOfferGrant{},
		},
		Type: receiverTypes.Oid4vci,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization_servers must not be an empty array")
}

func TestWallet_fetchCredentialMetadata_RejectsWhenNoUsableMethod(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
		KeyPair:                     mockserver.MustGenerateKeyPair("issuer-key-id"),
		IssuerID:                    "test-issuer",
		PreAuthorizedGrantAnonymous: mockserver.BoolPtr(false),
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

// TestWallet_fetchCredentialMetadata_PreAuthorizedGrantAnonymousAccess pins the three
// states of the OPTIONAL pre-authorized_grant_anonymous_access_supported metadata
// parameter. Omitting it means "unknown", not "unsupported" — issuers commonly leave it
// out, the OpenID conformance suite among them — so only an explicit false may stop the
// pre-authorized code flow.
func TestWallet_fetchCredentialMetadata_PreAuthorizedGrantAnonymousAccess(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	tests := []struct {
		name            string
		anonymousAccess *bool
		wantErr         bool
	}{
		{name: "omitted", anonymousAccess: nil, wantErr: false},
		{name: "explicit true", anonymousAccess: mockserver.BoolPtr(true), wantErr: false},
		{name: "explicit false", anonymousAccess: mockserver.BoolPtr(false), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
				KeyPair:                     mockserver.MustGenerateKeyPair("issuer-key-id"),
				IssuerID:                    "test-issuer",
				PreAuthorizedGrantAnonymous: tt.anonymousAccess,
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

			_, authMetadata, err := w.fetchCredentialMetadata(ReceiveCredentialRequest{
				CredentialOffer: &CredentialOffer{
					CredentialIssuer:           issuerURL,
					CredentialConfigurationIDs: []string{"test-config"},
					Grants:                     map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {}},
				},
				Type: receiverTypes.Oid4vci,
			})

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "no usable client authentication method")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, authMetadata)
		})
	}
}

// TestWallet_obtainAccessToken_OmittedAnonymousAccessSendsClientID checks that an issuer
// which never advertises pre-authorized_grant_anonymous_access_supported still receives a
// token request, and that the request names the configured client. The assertion is on
// what reached the server rather than on the returned token, because the failure this
// guards against stopped the wallet before any request went out.
func TestWallet_obtainAccessToken_OmittedAnonymousAccessSendsClientID(t *testing.T) {
	httpAllowed := env.IsHTTPAllowed()
	defer env.SetHTTPAllowed(httpAllowed)
	env.SetHTTPAllowed(true)

	issuer := mockserver.NewOID4VCIIssuerServer(&mockserver.OID4VCIIssuerConfig{
		KeyPair:                     mockserver.MustGenerateKeyPair("issuer-key-id"),
		IssuerID:                    "test-issuer",
		PreAuthorizedGrantAnonymous: nil,
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
			Method:   receiverTypes.None,
			ClientID: "wallet-id",
		},
	}

	authMetadata, err := d.FetchAuthorizationServerMetadata(common.URIField(*issuerURL), receiverTypes.Oid4vci)
	require.NoError(t, err)
	require.Nil(t, authMetadata.PreAuthorizedGrantAnonymousAccessSupported,
		"the mock must omit the parameter for this test to mean anything")

	token, err := w.obtainAccessToken(receiverTypes.Oid4vci, authMetadata, "pre-auth-code", "")
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "mock-access-token", token.Token)

	tokenRequests := issuer.TokenRequests()
	require.Len(t, tokenRequests, 1, "the wallet must reach the token endpoint")
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", tokenRequests[0].Get("grant_type"))
	assert.Equal(t, "wallet-id", tokenRequests[0].Get("client_id"))
	assert.Empty(t, tokenRequests[0].Get("client_assertion"), "no client authentication is configured")
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
