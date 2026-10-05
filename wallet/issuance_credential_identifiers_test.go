package wallet

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// OpenID4VCI 1.0 Section 6.2: credential_identifiers is "A non-empty array of
// strings, each uniquely identifying a Credential Dataset", and its example
// lists two. Every identifier is kept, in the server's order.
func TestCredentialIdentifiersKeepsEveryDatasetOfTheEntry(t *testing.T) {
	token := &receiverTypes.CredentialIssuanceAccessToken{
		Token:                "access-1",
		AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{flowTestOpenIDCredentialDetail("pid", "CivilEngineeringDegree-2023", "ElectricalEngineeringDegree-2023")},
	}
	identifiers, err := credentialIdentifiersFor(token, "pid", authorizationDetailsRequired)
	require.NoError(t, err)
	require.Equal(t, []string{"CivilEngineeringDegree-2023", "ElectricalEngineeringDegree-2023"}, identifiers)
}

// Draft 13 Section 6.2 makes authorization_details REQUIRED in the Token
// Response of an authorization_details request but credential_identifiers
// OPTIONAL; an entry without them leaves the request to name the format.
func TestDraft13CredentialIdentifiersAreOptionalInTheRequiredEntry(t *testing.T) {
	token := &receiverTypes.CredentialIssuanceAccessToken{
		Token:                "access-1",
		AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{flowTestOpenIDCredentialDetail("degree")},
	}
	identifiers, err := credentialIdentifiersFor(token, "degree", authorizationDetailsEntryRequired)
	require.NoError(t, err)
	require.Empty(t, identifiers)

	_, err = credentialIdentifiersFor(&receiverTypes.CredentialIssuanceAccessToken{Token: "access-1"}, "degree", authorizationDetailsEntryRequired)
	require.ErrorIs(t, err, ErrAuthorizationDetailsMissing, "the entry itself stays REQUIRED")
}

// Section 6.2: "The Wallet MUST use these identifiers together with an Access
// Token in subsequent Credential Requests." Each dataset is requested with its
// own Credential Request (Section 8.2 credential_identifier); an identifier the
// token response did not name is refused before anything is sent.
func TestRequestCredentialSelectsOneOfSeveralCredentialIdentifiers(t *testing.T) {
	f := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitScope = true
		f.tokenResponse = map[string]any{
			"access_token": "access-1", "token_type": "DPoP", "expires_in": 3600,
			"authorization_details": []any{map[string]any{
				"type": "openid_credential", "credential_configuration_id": "pid",
				"credential_identifiers": []string{"dataset-1", "dataset-2"},
			}},
		}
	})
	ctx := context.Background()
	grant, err := f.authorize(f.issuanceRequest())
	require.NoError(t, err)
	require.Equal(t, []string{"dataset-1", "dataset-2"}, grant.CredentialIdentifiers)

	_, err = f.wallet.RequestCredential(ctx, grant, f.credentialRequest())
	require.NoError(t, err)
	require.Equal(t, "dataset-1", f.lastCredentialBody["credential_identifier"], "the first dataset by default")
	require.NotContains(t, f.lastCredentialBody, "credential_configuration_id")

	second := f.credentialRequest()
	second.CredentialIdentifier = "dataset-2"
	_, err = f.wallet.RequestCredential(ctx, grant, second)
	require.NoError(t, err)
	require.Equal(t, "dataset-2", f.lastCredentialBody["credential_identifier"])
	require.Equal(t, 2, f.credentialCalls)

	unknown := f.credentialRequest()
	unknown.CredentialIdentifier = "dataset-3"
	_, err = f.wallet.RequestCredential(ctx, grant, unknown)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.Equal(t, 2, f.credentialCalls, "nothing is sent for an identifier the token response did not name")
}

// Draft 13 Section 7.2: format is "REQUIRED when the credential_identifiers
// parameter was not returned from the Token Response", so an
// authorization_details Token Response without identifiers still issues.
func TestDraft13AuthorizationDetailsWithoutCredentialIdentifiersRequestsTheFormat(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	fixture.set(func(f *draft13Fixture) {
		f.tokenResponse = func(url.Values) (int, any) {
			return http.StatusOK, map[string]any{
				"access_token": "access-1", "token_type": "Bearer", "c_nonce": "nonce-1",
				"authorization_details": []any{map[string]any{"type": "openid_credential", "credential_configuration_id": "degree"}},
			}
		}
	})
	ctx := context.Background()
	authorization := fixture.beginAuthorization(t, fixture.wallet, IssuanceRequest{AuthorizationRequestType: AuthorizationRequestDetails})
	grant, err := fixture.wallet.Draft13().AuthorizeIssuance(ctx, authorization, draft13Redirect(authorization, ""))
	require.NoError(t, err)
	require.Empty(t, grant.CredentialIdentifiers)

	result, err := fixture.wallet.Draft13().RequestCredential(ctx, grant, fixture.holder())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	request := fixture.credentials()[0]
	require.Equal(t, "vc+sd-jwt", request["format"])
	require.NotContains(t, request, "credential_identifier")
}
