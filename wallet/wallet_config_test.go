package wallet

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/mock"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// plainPresenter is a presenter plugin that does not implement
// profile.Carrier.
type plainPresenter struct{}

func (plainPresenter) Present(presenterTypes.SupportedPresentationProtocol, url.URL, []byte, *presenterTypes.PresentationRequest) (string, error) {
	return "", nil
}

func receiverWith(t *testing.T, plugin receiverTypes.Receiver) *receiver.ReceivingDispatcher {
	t.Helper()
	d, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	return d
}

func presenterWith(t *testing.T, plugin presenterTypes.Presenter) *presenter.PresentationDispatcher {
	t.Helper()
	d, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenterTypes.Oid4vp, plugin))
	require.NoError(t, err)
	return d
}

func requireCoded(t *testing.T, err error, want error) {
	t.Helper()
	require.ErrorIs(t, err, want)
	code, ok := ErrorCode(err)
	require.True(t, ok)
	require.NotEqual(t, "unclassified", code)
}

func TestNewWalletWithConfigProfileChecks(t *testing.T) {
	for name, test := range map[string]struct {
		config Config
		want   error
	}{
		"HAIP refuses a receiver plugin that reports no profile": {
			config: Config{Profiles: []profile.Profile{profile.HAIP()}, Storeless: true, Receiver: receiverWith(t, mock.NewMockReceiver(t.TempDir()))},
			want:   ErrProfilePluginUnsupported,
		},
		"HAIP refuses a presenter plugin that reports no profile": {
			config: Config{Profiles: []profile.Profile{profile.HAIP()}, Storeless: true, Presenter: presenterWith(t, plainPresenter{})},
			want:   ErrProfilePluginUnsupported,
		},
		"HAIP refuses a plugin whose zero profile means Final": {
			config: Config{Profiles: []profile.Profile{profile.HAIP()}, Storeless: true, Receiver: receiverWith(t, &oid4vci.Oid4vciReceiver{})},
			want:   ErrProfileMismatch,
		},
		"Final refuses a HAIP plugin": {
			config: Config{Storeless: true, Presenter: presenterWith(t, &oid4vp.Oid4vpPresenter{Profile: profile.HAIP()})},
			want:   ErrProfileMismatch,
		},
		"HAIP refuses experimental hooks": {
			config: Config{Profiles: []profile.Profile{profile.HAIP()}, Storeless: true, Experimental: experimental.Options{Hooks: experimental.Hooks{KeyProof: experimental.ProofTransform{Serialized: identityProof}}}},
			want:   ErrInvalidArgument,
		},
		"transaction data types with an injected presenter": {
			config: Config{Storeless: true, Presenter: presenterWith(t, &oid4vp.Oid4vpPresenter{}), SupportedTransactionDataTypes: []string{"example"}},
			want:   ErrInvalidArgument,
		},
		"a presenter plugin other than the bundled OpenID4VP presenter": {
			config: Config{Storeless: true, Presenter: presenterWith(t, plainPresenter{})},
			want:   ErrInvalidArgument,
		},
		"HAIP refuses an experimental transport": {
			config: Config{Profiles: []profile.Profile{profile.HAIP()}, Storeless: true, Experimental: experimental.Options{Transport: experimental.Transport{AllowHTTP: true}}},
			want:   ErrInvalidArgument,
		},
		"an experimental transport with an injected receiver": {
			config: Config{Storeless: true, Receiver: receiverWith(t, &oid4vci.Oid4vciReceiver{}), Experimental: experimental.Options{Transport: experimental.Transport{AllowHTTP: true}}},
			want:   ErrInvalidArgument,
		},
		"an experimental transport with an injected presenter": {
			config: Config{Storeless: true, Presenter: presenterWith(t, &oid4vp.Oid4vpPresenter{}), Experimental: experimental.Options{Transport: experimental.Transport{AllowHTTP: true}}},
			want:   ErrInvalidArgument,
		},
		"ClientKeyFromDPoP without a DPoP key": {
			config: Config{Storeless: true, Attestation: AttestationConfig{ClientKeyFromDPoP: true}},
			want:   ErrInvalidArgument,
		},
		"ClientKeyFromDPoP with a ClientKey": {
			config: Config{Storeless: true, DPoP: DPoPConfig{Enabled: true}, Attestation: AttestationConfig{ClientKeyFromDPoP: true, ClientKey: newMockKeyEntry()}},
			want:   ErrInvalidArgument,
		},
		"a draft profile reported by a plugin": {
			config: Config{Storeless: true, Receiver: receiverWith(t, &oid4vci.Oid4vciReceiver{Profile: profile.Draft13()})},
			want:   profile.ErrDraftProfile,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewWalletWithConfig(test.config)
			requireCoded(t, err, test.want)
		})
	}

	t.Run("Final accepts plugins that report no profile", func(t *testing.T) {
		_, err := NewWalletWithConfig(Config{
			Storeless: true,
			Receiver:  receiverWith(t, mock.NewMockReceiver(t.TempDir())),
		})
		require.NoError(t, err)
	})

	t.Run("a refused plugin is left as it was given", func(t *testing.T) {
		plugin := &oid4vci.Oid4vciReceiver{Profile: profile.Final()}
		_, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.HAIP()}, Storeless: true, Receiver: receiverWith(t, plugin)})
		require.ErrorIs(t, err, ErrProfileMismatch)
		require.Equal(t, profile.Final(), plugin.Profile)
	})

	t.Run("the experimental transport reaches the plugins the wallet builds", func(t *testing.T) {
		w, err := NewWalletWithConfig(Config{Storeless: true, Experimental: experimental.Options{Transport: experimental.Transport{AllowHTTP: true}}})
		require.NoError(t, err)
		require.True(t, receiverAllowsHTTP(t, w))
		for _, plugin := range w.presenter.Plugins() {
			require.True(t, plugin.(*oid4vp.Oid4vpPresenter).Experimental.Transport.AllowHTTP)
		}
	})

	t.Run("the removed VCKNOTS_WALLET_HTTP_ALLOWED variable relaxes nothing", func(t *testing.T) {
		t.Setenv("VCKNOTS_WALLET_HTTP_ALLOWED", "true")
		w, err := NewWalletWithConfig(Config{Storeless: true})
		require.NoError(t, err)
		require.False(t, receiverAllowsHTTP(t, w))
		for _, plugin := range w.presenter.Plugins() {
			require.False(t, plugin.(*oid4vp.Oid4vpPresenter).Experimental.Transport.AllowHTTP)
		}
	})

	t.Run("the default HAIP receiver holds only HAIP plugins", func(t *testing.T) {
		w, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.HAIP()}, Storeless: true})
		require.NoError(t, err)
		plugins := w.receiver.Plugins()
		require.Len(t, plugins, 1)
		require.Equal(t, profile.HAIP(), plugins[0].(profile.Carrier).ProtocolProfile())
	})
}

// TestDraft13NeedsADraft13Transport: an injected receiver whose OpenID4VCI
// plugin has no Draft 13 transport is reported by the Draft 13 stages, which
// send nothing.
func TestDraft13NeedsADraft13Transport(t *testing.T) {
	w, err := NewWalletWithConfig(Config{Storeless: true, Receiver: receiverWith(t, mock.NewMockReceiver(t.TempDir())), CredentialAcceptance: mockIssuerAcceptance()})
	require.NoError(t, err)

	issuer, err := url.Parse("https://issuer.example")
	require.NoError(t, err)
	_, err = w.Draft13().AuthorizePreAuthorizedIssuance(t.Context(), PreAuthorizedIssuanceRequest{CredentialOffer: preAuthorizedCodeOffer(issuer, "pid", "code")})
	requireCoded(t, err, receiverTypes.ErrUnsupportedProtocol)
}

func TestGenerateDIDRejectsATypeIDThatIsNotADID(t *testing.T) {
	w, err := NewWalletWithConfig(Config{Storeless: true})
	require.NoError(t, err)
	_, err = w.GenerateDID(DIDCreateOptions{TypeID: "key"})
	requireCoded(t, err, ErrInvalidArgument)
}

// receiverAllowsHTTP reports whether w's OpenID4VCI receiver accepts plain
// http endpoints.
func receiverAllowsHTTP(t *testing.T, w *Wallet) bool {
	t.Helper()
	transport, err := w.receiver.Draft13Transport(receiverTypes.Oid4vci)
	require.NoError(t, err)
	policy, ok := transport.(receiverTypes.HTTPSchemePolicy)
	return ok && policy.HTTPAllowed()
}
