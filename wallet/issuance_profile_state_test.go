package wallet

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/profile"
)

// A flow authorized under HAIP must not be continued by a wallet built with a
// weaker profile - no DPoP, no iss check - at the token or credential stage.
// Binding the states to the protocol version alone would allow that, so each
// state records the flow's profile, which survives JSON, and a stage under
// another profile refuses it before sending
// anything.
func TestIssuanceStatesAreBoundToTheFlowProfile(t *testing.T) {
	ctx := context.Background()
	weaker := profile.HAIPOptions()
	weaker.RequireAuthorizationResponseIss = false
	weaker.RequireDPoP = false
	weakerProfile, err := profile.Final().With(weaker)
	require.NoError(t, err)

	t.Run("authorization state", func(t *testing.T) {
		fixture := newHAIPIssuanceFixture(t)
		authorization, err := fixture.wallet.BeginIssuance(ctx, fixture.issuanceRequest())
		require.NoError(t, err)
		require.Equal(t, profile.HAIP(), authorization.Profile)
		encoded, err := json.Marshal(authorization)
		require.NoError(t, err)
		require.Contains(t, string(encoded), `"profile":"haip"`)
		var stored IssuanceAuthorization
		require.NoError(t, json.Unmarshal(encoded, &stored))
		require.Equal(t, profile.HAIP(), stored.Profile)
		location, err := fixture.followAuthorization(authorization)
		require.NoError(t, err)

		useProfiles(t, fixture.wallet, weakerProfile)
		_, err = fixture.wallet.AuthorizeIssuance(ctx, &stored, location)
		requireCoded(t, err, ErrIssuanceProfileMismatch)
		require.Equal(t, 0, fixture.tokenCalls)

		useProfiles(t, fixture.wallet, profile.HAIP())
		grant, err := fixture.wallet.AuthorizeIssuance(ctx, &stored, location)
		require.NoError(t, err)
		require.Equal(t, profile.HAIP(), grant.Profile)
	})

	t.Run("grant", func(t *testing.T) {
		fixture := newHAIPIssuanceFixture(t)
		grant, err := fixture.authorize(fixture.issuanceRequest())
		require.NoError(t, err)
		encoded, err := json.Marshal(grant)
		require.NoError(t, err)
		var stored IssuanceGrant
		require.NoError(t, json.Unmarshal(encoded, &stored))
		require.Equal(t, profile.HAIP(), stored.Profile)

		useProfiles(t, fixture.wallet, weakerProfile)
		_, err = fixture.wallet.RequestCredential(ctx, &stored, fixture.credentialRequest())
		requireCoded(t, err, ErrIssuanceProfileMismatch)
		require.Equal(t, 0, fixture.credentialCalls)
	})

	t.Run("notification and deferred", func(t *testing.T) {
		fixture := newHAIPIssuanceFixture(t, notifyTestEndpoint)
		notification := fixture.notifyTestNotification()
		useProfiles(t, fixture.wallet, profile.Final())
		err := fixture.wallet.NotifyIssuer(ctx, notification, NotificationCredentialAccepted, "")
		requireCoded(t, err, ErrIssuanceProfileMismatch)
		require.Empty(t, fixture.notificationBodies)

		_, err = fixture.wallet.RequestDeferredCredential(ctx, &DeferredIssuance{
			Profile:                   profile.HAIP(),
			CredentialIssuer:          fixture.server.URL,
			CredentialConfigurationID: "pid",
			TransactionID:             "tx-1",
		})
		requireCoded(t, err, ErrIssuanceProfileMismatch)
		require.Equal(t, 0, fixture.deferredCalls)
	})
}
