package wallet

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
)

// requireJSONRoundTrip marshals value and unmarshals it into target, as a
// caller persisting a state between stages does.
func requireJSONRoundTrip(t *testing.T, value any, target any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, target))
}

// TestIssuanceWithKeysThatHoldNoPrivateJWK runs the whole OpenID4VCI 1.0
// authorization code issuance with a holder key and a DPoP key that expose no
// private JWK and sign with DER signatures, as a hardware module does.
func TestIssuanceWithKeysThatHoldNoPrivateJWK(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.hsmKeys = true
		f.includeNotification = true
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.NotNil(t, result.Notification)
	require.Nil(t, result.Deferred)
	require.Empty(t, fixture.notificationEvents, "the library never notifies on its own")

	holder := fixture.holderEntry.(*hsmKeyEntry)
	dpop := fixture.dpopEntry.(*hsmKeyEntry)
	require.Positive(t, holder.signed)
	require.Positive(t, dpop.signed)
	proofs := fixture.proofJWTs(t)
	require.Len(t, proofs, 1)
	require.Equal(t, "credential-nonce-1", finalProofClaims(t, proofs[0])["nonce"])
	require.NotEmpty(t, fixture.credentialHeaders.Get("DPoP"))

	require.NoError(t, fixture.wallet.NotifyIssuer(context.Background(), result.Notification, NotificationCredentialAccepted, ""))
	require.Equal(t, []string{"credential_accepted"}, fixture.notificationEvents)
}

// TestIssuanceStatesSurviveJSONInAnotherWallet resumes every stage from JSON in
// a wallet that shares only its Config with the one that started, so every
// stage re-discovers the metadata.
func TestIssuanceStatesSurviveJSONInAnotherWallet(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusAccepted, map[string]any{"transaction_id": "tx-1", "interval": 7})
		}
	})
	ctx := context.Background()
	authorization, err := fixture.wallet.BeginIssuance(ctx, fixture.issuanceRequest())
	require.NoError(t, err)
	var stored IssuanceAuthorization
	requireJSONRoundTrip(t, authorization, &stored)
	location, err := fixture.followAuthorization(&stored)
	require.NoError(t, err)

	calls := fixture.issuerMetadataCalls
	resumed := fixture.newWallet(t)
	grant, err := resumed.AuthorizeIssuance(ctx, &stored, location)
	require.NoError(t, err)
	require.Greater(t, fixture.issuerMetadataCalls, calls, "the resumed stage re-discovers the metadata")

	var storedGrant IssuanceGrant
	requireJSONRoundTrip(t, grant, &storedGrant)
	result, err := fixture.newWallet(t).RequestCredential(ctx, &storedGrant, fixture.credentialRequest())
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)
	require.Equal(t, "tx-1", result.Deferred.TransactionID)
	require.Equal(t, int64(7), int64(result.Deferred.Interval.Seconds()))

	var storedDeferred DeferredIssuance
	requireJSONRoundTrip(t, result.Deferred, &storedDeferred)
	issued, err := fixture.newWallet(t).RequestDeferredCredential(ctx, &storedDeferred)
	require.NoError(t, err)
	require.Len(t, issued.Credentials, 1)
	require.Equal(t, "tx-1", fixture.lastDeferredBody["transaction_id"])
}
