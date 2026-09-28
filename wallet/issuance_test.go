package wallet

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
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

// A per-request acceptance policy does not survive serialization, and a
// deferred issuance read back without it must not be accepted under
// Config.CredentialAcceptance instead. The override is recorded, and its
// absence refuses the Deferred Credential Request before anything is sent.
func TestDeferredIssuanceKeepsTheFactOfAPerRequestPolicy(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusAccepted, map[string]any{"transaction_id": "tx-1"})
		}
	})
	ctx := context.Background()
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)
	perRequest := fixture.wallet.credentialAcceptance
	require.NotNil(t, perRequest)
	request := fixture.credentialRequest()
	request.Acceptance = perRequest
	result, err := fixture.wallet.RequestCredential(ctx, grant, request)
	require.NoError(t, err)
	require.True(t, result.Deferred.AcceptanceOverridden)

	var stored DeferredIssuance
	requireJSONRoundTrip(t, result.Deferred, &stored)
	require.True(t, stored.AcceptanceOverridden)
	require.Nil(t, stored.Acceptance)
	_, err = fixture.newWallet(t).RequestDeferredCredential(ctx, &stored)
	require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
	require.Nil(t, fixture.lastDeferredBody, "nothing is sent without the policy")

	stored.Acceptance = perRequest
	issued, err := fixture.newWallet(t).RequestDeferredCredential(ctx, &stored)
	require.NoError(t, err)
	require.Len(t, issued.Credentials, 1)

	// Without a per-request policy the wallet's own policy applies, as before.
	plain, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)
	result, err = fixture.wallet.RequestCredential(ctx, plain, fixture.credentialRequest())
	require.NoError(t, err)
	require.False(t, result.Deferred.AcceptanceOverridden)
}

// FetchCredentialIssuerMetadata reads the OpenID4VCI 1.0 Section 12.2.2
// location, where the well-known segment precedes the identifier's path; the
// Draft 13 Section 11.2.2 location a Draft 13 issuance reads appends it.
func TestFetchCredentialIssuerMetadataReadsThe10Location(t *testing.T) {
	server := mockserver.NewOID4VCIIssuerServer(nil)
	t.Cleanup(server.Close)
	issuer, err := url.Parse(server.URL())
	require.NoError(t, err)
	metadata, err := createTestControllerAllowingHTTP(t).FetchCredentialIssuerMetadata(t.Context(), issuer)
	require.NoError(t, err)
	require.Equal(t, server.URL(), metadata.CredentialIssuer)

	var paths []string
	var mu sync.Mutex
	pathServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		http.NotFound(w, r)
	}))
	t.Cleanup(pathServer.Close)
	tenant, err := url.Parse(pathServer.URL + "/tenant")
	require.NoError(t, err)
	_, err = createTestControllerAllowingHTTP(t).FetchCredentialIssuerMetadata(t.Context(), tenant)
	require.Error(t, err)
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"/.well-known/openid-credential-issuer/tenant"}, paths)
}
