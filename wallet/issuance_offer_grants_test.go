package wallet

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// OpenID4VCI 1.0 Section 4.1.1: "If grants is not present or is empty, the
// Wallet MUST determine the Grant Types the Credential Issuer's Authorization
// Server supports using the respective metadata." An authorization server
// without grant_types_supported supports authorization_code (RFC 8414
// Section 2), so the flow starts, and completes, without an issuer_state.
func TestBeginIssuanceTakesTheGrantFromMetadataWhenTheOfferHasNone(t *testing.T) {
	for name, grants := range map[string]map[string]*CredentialOfferGrant{
		"absent": nil,
		"empty":  {},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFinalIssuanceFixture(t)
			offer := f.offer()
			offer.Grants = grants

			result, err := f.receive(IssuanceRequest{CredentialOffer: offer})
			require.NoError(t, err)
			require.Len(t, result.Credentials, 1)
			require.Equal(t, 1, f.parCalls)
			require.False(t, f.parForm.Has("issuer_state"), "an offer without grants carries no issuer_state")
		})
	}
}

// grant_types_supported that lists authorization_code admits the flow.
func TestBeginIssuanceWithoutGrantsAcceptsAnAdvertisedAuthorizationCodeGrant(t *testing.T) {
	f := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.grantTypesSupported = []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code", "authorization_code"}
	})
	offer := f.offer()
	offer.Grants = nil

	_, err := f.wallet.BeginIssuance(context.Background(), IssuanceRequest{CredentialOffer: offer})
	require.NoError(t, err)
}

// The metadata decides: an authorization server whose grant_types_supported
// lacks authorization_code cannot serve an offer without grants, and nothing
// is pushed.
func TestBeginIssuanceWithoutGrantsRefusesAServerWithoutTheAuthorizationCodeGrant(t *testing.T) {
	f := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.grantTypesSupported = []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}
	})
	offer := f.offer()
	offer.Grants = nil

	_, err := f.wallet.BeginIssuance(context.Background(), IssuanceRequest{CredentialOffer: offer})
	require.ErrorIs(t, err, ErrAuthorizationCodeGrantUnsupported)
	require.Zero(t, f.parCalls)
}

// An offer that names grants without authorization_code is the issuer's
// statement of the grants it prepared (Section 4.1.1), not an offer without
// grants.
func TestBeginIssuanceRefusesAnOfferWhoseGrantsLackAuthorizationCode(t *testing.T) {
	f := newFinalIssuanceFixture(t)
	offer := f.offer()
	offer.Grants = map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {PreAuthorizedCode: "code"}}

	_, err := f.wallet.BeginIssuance(context.Background(), IssuanceRequest{CredentialOffer: offer})
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.Zero(t, f.parCalls)
}

// A pre-authorized_code is a parameter of the offer, so an offer without
// grants never starts a Pre-Authorized Code Flow.
func TestPreAuthorizedIssuanceRequiresTheGrantInTheOffer(t *testing.T) {
	f := newFinalIssuanceFixture(t)
	offer := f.offer()
	offer.Grants = nil

	_, err := f.wallet.AuthorizePreAuthorizedIssuance(context.Background(), PreAuthorizedIssuanceRequest{CredentialOffer: offer})
	require.ErrorIs(t, err, ErrPreAuthorizedGrantMissing)
	require.Zero(t, f.tokenCalls)
}

// Draft 13 Section 4.1.1 states the same rule as 1.0.
func TestDraft13BeginIssuanceTakesTheGrantFromMetadataWhenTheOfferHasNone(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	ctx := context.Background()

	authorization := fixture.beginAuthorization(t, fixture.wallet, IssuanceRequest{CredentialOffer: fixture.offer(nil)})
	grant, err := fixture.wallet.Draft13().AuthorizeIssuance(ctx, authorization, draft13Redirect(authorization, ""))
	require.NoError(t, err)
	result, err := fixture.wallet.Draft13().RequestCredential(ctx, grant, fixture.holder())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
}

func TestDraft13BeginIssuanceWithoutGrantsRefusesAServerWithoutTheAuthorizationCodeGrant(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	fixture.set(func(f *draft13Fixture) {
		f.asMetadataExtra = map[string]any{"grant_types_supported": []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}}
	})

	_, err := fixture.wallet.Draft13().BeginIssuance(context.Background(), IssuanceRequest{CredentialOffer: fixture.offer(map[string]*CredentialOfferGrant{})})
	require.ErrorIs(t, err, ErrAuthorizationCodeGrantUnsupported)
}
