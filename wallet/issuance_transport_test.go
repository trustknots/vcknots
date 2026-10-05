package wallet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// FAPI 2.0 Section 5.2.1 (HAIP Section 4) and OpenID4VCI 1.0 Section 11
// require TLS on every endpoint. The wallet never fetches the authorization
// endpoint itself, so BeginIssuance checks the URL it hands to the holder's
// browser, and pushes nothing when it is plain http.
func TestBeginIssuanceRefusesAPlainHTTPAuthorizationEndpointUnderHAIP(t *testing.T) {
	f := newHAIPIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.authorizationEndpoint = "http://as.example/authorize"
	})
	authorization, err := f.wallet.BeginIssuance(context.Background(), f.issuanceRequest())
	require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
	require.ErrorContains(t, err, "does not use https")
	require.Nil(t, authorization)
	require.Zero(t, f.parCalls)
}

// Only a receiver that allows plain http (experimental, never under
// ForbidExperimental) lets an http authorization endpoint through; no other
// scheme is ever handed to the browser.
func TestRequireSecureAuthorizationEndpoint(t *testing.T) {
	endpoint := func(raw string) *common.URIField {
		parsed, err := common.ParseURIField(raw)
		require.NoError(t, err)
		return parsed
	}
	final := &oid4vci.Oid4vciReceiver{}
	allowHTTP := &oid4vci.Oid4vciReceiver{Experimental: experimental.Transport{AllowHTTP: true}}
	haipWithHTTP := &oid4vci.Oid4vciReceiver{Experimental: experimental.Transport{AllowHTTP: true}, Profile: profile.HAIP()}

	require.NoError(t, requireSecureAuthorizationEndpoint(final, endpoint("https://as.example/authorize")))
	require.ErrorIs(t, requireSecureAuthorizationEndpoint(final, endpoint("http://as.example/authorize")), receiverTypes.ErrInvalidMetadata)
	require.NoError(t, requireSecureAuthorizationEndpoint(allowHTTP, endpoint("http://127.0.0.1/authorize")))
	require.ErrorIs(t, requireSecureAuthorizationEndpoint(allowHTTP, endpoint("javascript:alert(1)")), receiverTypes.ErrInvalidMetadata)
	require.ErrorIs(t, requireSecureAuthorizationEndpoint(haipWithHTTP, endpoint("http://127.0.0.1/authorize")), receiverTypes.ErrInvalidMetadata)
	require.ErrorIs(t, requireSecureAuthorizationEndpoint(struct{}{}, endpoint("http://127.0.0.1/authorize")), receiverTypes.ErrInvalidMetadata,
		"a transport that reports no scheme policy gets https only")
}

// HAIP forbids experimental transport for a receiver plugin the caller
// injects as well as for one the wallet builds: the wallet refuses the plugin,
// and the plugin itself sends nothing on any exchange.
func TestHAIPRefusesAnInjectedReceiverWithAnExperimentalTransport(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	plugin := &oid4vci.Oid4vciReceiver{HTTPClient: server.Client(), Experimental: experimental.Transport{AllowHTTP: true}, Profile: profile.HAIP()}
	var refused *profile.OptionError
	require.ErrorAs(t, plugin.ValidateProfile(), &refused)
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)

	_, err = NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.HAIP()}, Receiver: receiving, CredStore: newProfileCredStore(t)})
	refused = nil
	require.ErrorAs(t, err, &refused)
	require.Equal(t, "ForbidExperimental", refused.Option)

	endpoint, err := common.ParseURIField(server.URL + "/token")
	require.NoError(t, err)
	_, err = plugin.RequestToken(context.Background(), *endpoint, receiverTypes.TokenRequest{GrantType: receiverTypes.PreAuthorizedCode, PreAuthorizedCode: "code"}, receiverTypes.ClientAuthentication{})
	require.ErrorAs(t, err, &refused)
	_, err = plugin.RequestNonce(context.Background(), *endpoint)
	require.ErrorAs(t, err, &refused)
	require.Zero(t, calls, "no exchange leaves a HAIP receiver over the experimental transport")

	final := &oid4vci.Oid4vciReceiver{Experimental: experimental.Transport{AllowHTTP: true}}
	require.NoError(t, final.ValidateProfile(), "Final permits the experimental transport")
}
