package wallet

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/observetest"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// fixtureEndpointByPath is the role each path of the Final issuance fixture
// plays (issuance_fixture_test.go serveHTTP).
var fixtureEndpointByPath = map[string]observe.Endpoint{
	"/.well-known/openid-credential-issuer":   observe.EndpointIssuerMetadata,
	"/.well-known/oauth-authorization-server": observe.EndpointAuthorizationServerMetadata,
	"/par":          observe.EndpointPushedAuthorization,
	"/authorize":    observe.EndpointAuthorization,
	"/token":        observe.EndpointToken,
	"/nonce":        observe.EndpointNonce,
	"/credential":   observe.EndpointCredential,
	"/deferred":     observe.EndpointDeferredCredential,
	"/notification": observe.EndpointNotification,
}

// observedClient routes client through an observe.Transport, the way an
// integrator wires the client it injects into the library.
func observedClient(client *http.Client, recorder *observetest.Recorder) *http.Client {
	observed := *client
	observed.Transport = observe.Transport(client.Transport, recorder)
	return &observed
}

// observeFixtureTransport observes the fixture receiver's client.
func observeFixtureTransport(recorder *observetest.Recorder) func(*finalIssuanceFixture) {
	return func(f *finalIssuanceFixture) {
		f.wrapReceiverPlugin = func(plugin receiverTypes.Receiver) receiverTypes.Receiver {
			receiver := plugin.(*oid4vci.Oid4vciReceiver)
			receiver.HTTPClient = observedClient(receiver.HTTPClient, recorder)
			return receiver
		}
	}
}

func requireFixtureEndpointLabels(t *testing.T, exchanges []observe.Exchange) []observe.Endpoint {
	t.Helper()
	labels := make([]observe.Endpoint, 0, len(exchanges))
	for _, exchange := range exchanges {
		want, known := fixtureEndpointByPath[exchange.Request.URL.Path]
		require.True(t, known, "unexpected request to %s", exchange.Request.URL.Path)
		require.Equal(t, want, exchange.Endpoint, "role of %s %s", exchange.Request.Method, exchange.Request.URL.Path)
		require.NotNil(t, exchange.Response)
		labels = append(labels, exchange.Endpoint)
	}
	return labels
}

// TestObserveLabelsEveryFinalIssuanceRequest drives an authorization code
// issuance through an observed client: every request the library sends is
// labelled with the role it was sent for, so an integrator never classifies a
// URL itself.
func TestObserveLabelsEveryFinalIssuanceRequest(t *testing.T) {
	recorder := &observetest.Recorder{}
	fixture := newFinalIssuanceFixture(t, observeFixtureTransport(recorder), func(f *finalIssuanceFixture) {
		f.includeNotification = true
		f.responseEncryption = true
		f.requestEncryption = true
	})

	ctx := context.Background()
	authorization, err := fixture.wallet.BeginIssuance(ctx, fixture.issuanceRequest())
	require.NoError(t, err)
	// The authorization GET is the caller's, through its own client.
	location, err := followAuthorizationRedirect(ctx, observedClient(fixture.server.Client(), recorder), authorization.AuthorizationURL)
	require.NoError(t, err)
	grant, err := fixture.wallet.AuthorizeIssuance(ctx, authorization, location)
	require.NoError(t, err)
	result, err := fixture.wallet.RequestCredential(ctx, grant, fixture.credentialRequest())
	require.NoError(t, err)
	require.NoError(t, fixture.wallet.NotifyIssuer(ctx, result.Notification, NotificationCredentialAccepted, ""))

	exchanges := recorder.Exchanges()
	labels := requireFixtureEndpointLabels(t, exchanges)
	for _, want := range []observe.Endpoint{
		observe.EndpointIssuerMetadata,
		observe.EndpointAuthorizationServerMetadata,
		observe.EndpointPushedAuthorization,
		observe.EndpointAuthorization,
		observe.EndpointToken,
		observe.EndpointNonce,
		observe.EndpointCredential,
		observe.EndpointNotification,
	} {
		require.Contains(t, labels, want)
	}
	for _, exchange := range exchanges {
		switch exchange.Endpoint {
		case observe.EndpointToken, observe.EndpointCredential, observe.EndpointNotification:
			require.NotEmpty(t, exchange.Request.Header.Get("DPoP"), "%s carries a DPoP proof", exchange.Endpoint)
		case observe.EndpointIssuerMetadata:
			require.Empty(t, exchange.Request.Header.Get("DPoP"))
		}
		if exchange.Endpoint == observe.EndpointCredential {
			require.Equal(t, "application/jwt", exchange.Request.Header.Get("Content-Type"), "the encrypted Credential Request is application/jwt")
			require.Equal(t, "application/jwt", exchange.Response.Header.Get("Content-Type"), "the encrypted Credential Response is application/jwt")
		}
	}
}

// TestObserveLabelsDeferredCredentialPoll checks that the Deferred Credential
// Request is labelled by the endpoint it addresses.
func TestObserveLabelsDeferredCredentialPoll(t *testing.T) {
	recorder := &observetest.Recorder{}
	fixture := newFinalIssuanceFixture(t, observeFixtureTransport(recorder), func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"transaction_id": "tx-1"})
		}
		f.deferredHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credentials": []any{map[string]any{"credential": f.issuedCredential}}})
		}
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)
	_, err = fixture.wallet.RequestDeferredCredential(context.Background(), result.Deferred)
	require.NoError(t, err)

	labels := requireFixtureEndpointLabels(t, recorder.Exchanges())
	require.Contains(t, labels, observe.EndpointCredential)
	require.Contains(t, labels, observe.EndpointDeferredCredential)
}
