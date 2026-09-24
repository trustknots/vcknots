package wallet

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
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
