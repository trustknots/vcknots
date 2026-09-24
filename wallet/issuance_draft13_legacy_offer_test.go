package wallet

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/env"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

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
