package wallet

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// RFC 9126 Section 2.2: a successful pushed authorization response carries
// request_uri ("REQUIRED") and expires_in ("REQUIRED ... a positive
// integer"). A response without them is refused, and the wallet never falls
// back to sending the parameters inline instead: HAIP Section 4 (FAPI 2.0
// Section 5.3.2.2) requires the pushed request, and a Final wallet that chose
// PAR must not silently leave it.
func TestBeginIssuanceRefusesAnIncompletePushedAuthorizationResponse(t *testing.T) {
	for name, response := range map[string]map[string]any{
		"empty":               {},
		"no request_uri":      {"expires_in": 60},
		"no expires_in":       {"request_uri": "urn:request:1"},
		"zero expires_in":     {"request_uri": "urn:request:1", "expires_in": 0},
		"negative expires_in": {"request_uri": "urn:request:1", "expires_in": -5},
		"blank request_uri":   {"request_uri": " ", "expires_in": 60},
	} {
		t.Run(name, func(t *testing.T) {
			for _, build := range map[string]func(*testing.T, ...func(*finalIssuanceFixture)) *finalIssuanceFixture{
				"final": newFinalIssuanceFixture,
				"haip":  newHAIPIssuanceFixture,
			} {
				f := build(t, func(f *finalIssuanceFixture) { f.parResponse = response })
				authorization, err := f.wallet.BeginIssuance(context.Background(), f.issuanceRequest())
				require.ErrorIs(t, err, receiverTypes.ErrPARResponseInvalid)
				require.Nil(t, authorization, "no inline authorization URL replaces the pushed request")
				require.Equal(t, 1, f.parCalls)
			}
		})
	}
}

// RFC 9126 Section 5: require_pushed_authorization_requests true means the
// server accepts authorization request data only through PAR, so an
// authorization server that also lacks a PAR endpoint cannot be used.
func TestBeginIssuanceHonoursAServerThatRequiresPushedAuthorizationRequests(t *testing.T) {
	f := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitPAREndpoint = true
		f.requirePAR = true
	})
	_, err := f.wallet.BeginIssuance(context.Background(), f.issuanceRequest())
	require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
	require.Zero(t, f.parCalls)

	withEndpoint := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) { f.requirePAR = true })
	authorization, err := withEndpoint.wallet.BeginIssuance(context.Background(), withEndpoint.issuanceRequest())
	require.NoError(t, err)
	require.Contains(t, authorization.AuthorizationURL, "request_uri=")
	require.False(t, authorization.RequestURIExpiresAt.IsZero())
}

// Draft 13 Section 5.1.3 uses RFC 9126 as is.
func TestDraft13BeginIssuanceHonoursAServerThatRequiresPushedAuthorizationRequests(t *testing.T) {
	fixture := newDraft13Fixture(t, draft13RegisteredClient)
	fixture.set(func(f *draft13Fixture) {
		f.asMetadataExtra = map[string]any{"require_pushed_authorization_requests": true}
	})
	_, err := fixture.wallet.Draft13().BeginIssuance(context.Background(), IssuanceRequest{CredentialOffer: fixture.authorizationCodeOffer()})
	require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
}
