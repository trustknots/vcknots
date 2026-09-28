package wallet

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestParseCredentialOfferURL(t *testing.T) {
	offer := map[string]any{
		"credential_issuer":            "https://issuer.example",
		"credential_configuration_ids": []string{"pid"},
		"grants": map[string]*CredentialOfferGrant{
			"authorization_code": {IssuerState: "issuer-state-1"},
		},
	}
	offerJSON, err := json.Marshal(offer)
	require.NoError(t, err)

	parsed, err := ParseCredentialOfferURL("openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)))
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example", parsed.CredentialIssuer.String())
	require.Equal(t, []string{"pid"}, parsed.CredentialConfigurationIDs)
	require.Equal(t, "issuer-state-1", parsed.Grants["authorization_code"].IssuerState)
}

func TestParseCredentialOfferURL_TransactionCodeRoundTrip(t *testing.T) {
	wantGrant := &CredentialOfferGrant{
		PreAuthorizedCode: "pre-authorized-code",
		TxCode: &TxCode{
			InputMode:   "numeric",
			Length:      6,
			Description: "Enter the code shown by the issuer",
		},
	}
	offerJSON, err := json.Marshal(map[string]any{
		"credential_issuer":            "https://issuer.example",
		"credential_configuration_ids": []string{"pid"},
		"grants": map[string]*CredentialOfferGrant{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": wantGrant,
		},
	})
	require.NoError(t, err)

	parsed, err := ParseCredentialOfferURL("openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)))
	require.NoError(t, err)
	parsedGrant := parsed.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	require.Equal(t, wantGrant, parsedGrant)

	roundTripJSON, err := json.Marshal(parsedGrant)
	require.NoError(t, err)
	var roundTripped CredentialOfferGrant
	require.NoError(t, json.Unmarshal(roundTripJSON, &roundTripped))
	require.Equal(t, *wantGrant, roundTripped)
}

// TestValidateOfferedConfigurations: every credential_configuration_id of an
// offer must be described by the issuer metadata (Draft 13 Section 4.1.1,
// 1.0 Section 4.1.1).
func TestValidateOfferedConfigurations(t *testing.T) {
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOfferedConfigurations(tt.offer, tt.issuerMetadata)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErrContains)
				return
			}

			require.NoError(t, err)
		})
	}
}
