package wallet

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
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
			config: Config{Profile: profile.HAIP, Storeless: true, Receiver: receiverWith(t, mock.NewMockReceiver(t.TempDir()))},
			want:   ErrProfilePluginUnsupported,
		},
		"HAIP refuses a presenter plugin that reports no profile": {
			config: Config{Profile: profile.HAIP, Storeless: true, Presenter: presenterWith(t, plainPresenter{})},
			want:   ErrProfilePluginUnsupported,
		},
		"HAIP refuses a plugin whose zero profile means Final": {
			config: Config{Profile: profile.HAIP, Storeless: true, Receiver: receiverWith(t, &oid4vci.Oid4vciReceiver{})},
			want:   ErrProfileMismatch,
		},
		"Final refuses a HAIP plugin": {
			config: Config{Storeless: true, Presenter: presenterWith(t, &oid4vp.Oid4vpPresenter{Profile: profile.HAIP})},
			want:   ErrProfileMismatch,
		},
		"HAIP refuses test hooks": {
			config: Config{Profile: profile.HAIP, Storeless: true, TestHooks: &TestHooks{}},
			want:   ErrProfileForbidsDraft,
		},
		"transaction data types with an injected presenter": {
			config: Config{Storeless: true, Presenter: presenterWith(t, &oid4vp.Oid4vpPresenter{}), SupportedTransactionDataTypes: []string{"example"}},
			want:   ErrInvalidArgument,
		},
		"a presenter plugin other than the bundled OpenID4VP presenter": {
			config: Config{Storeless: true, Presenter: presenterWith(t, plainPresenter{})},
			want:   ErrInvalidArgument,
		},
		"unknown profile": {
			config: Config{Profile: "haip-draft", Storeless: true},
			want:   profile.ErrUnknownProfile,
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
		plugin := &oid4vci.Oid4vciReceiver{Profile: profile.Final}
		_, err := NewWalletWithConfig(Config{Profile: profile.HAIP, Storeless: true, Receiver: receiverWith(t, plugin)})
		require.ErrorIs(t, err, ErrProfileMismatch)
		require.Equal(t, profile.Final, plugin.Profile)
	})

	t.Run("the default HAIP receiver holds only HAIP plugins", func(t *testing.T) {
		w, err := NewWalletWithConfig(Config{Profile: profile.HAIP, Storeless: true})
		require.NoError(t, err)
		plugins := w.receiver.Plugins()
		require.Len(t, plugins, 1)
		require.Equal(t, profile.HAIP, plugins[0].(profile.Carrier).ProtocolProfile())
	})
}

// TestSetReceiverChecksProfile: a Final-profile receiver set on a HAIP wallet
// is not installed, and the receiver-using methods report the refusal instead
// of running without the HAIP checks.
func TestSetReceiverChecksProfile(t *testing.T) {
	finalPlugin := &oid4vci.Oid4vciReceiver{Profile: profile.Final}
	w, err := NewWalletWithConfig(Config{Profile: profile.HAIP, Storeless: true})
	require.NoError(t, err)

	w.SetReceiver(receiverWith(t, finalPlugin))

	issuer, err := url.Parse("https://issuer.example")
	require.NoError(t, err)
	_, err = w.FetchCredentialIssuerMetadata(issuer, receiverTypes.Oid4vci)
	requireCoded(t, err, ErrProfileMismatch)
	_, err = w.receiver.OID4VCITransport(receiverTypes.Oid4vci)
	require.ErrorIs(t, err, ErrProfileMismatch)
	_, err = w.receiver.Draft13Transport(receiverTypes.Oid4vci)
	require.ErrorIs(t, err, ErrProfileMismatch)
	require.Equal(t, profile.Final, finalPlugin.Profile, "the wallet must not change a plugin it was given")

	w.SetReceiver(nil)
	_, err = w.receiver.OID4VCITransport(receiverTypes.Oid4vci)
	requireCoded(t, err, ErrInvalidArgument)

	haipReceiver := receiverWith(t, &oid4vci.Oid4vciReceiver{Profile: profile.HAIP})
	w.SetReceiver(haipReceiver)
	require.Same(t, haipReceiver, w.receiver)
}

func TestSetReceiverRefusalReachesReceiveCredential(t *testing.T) {
	w, err := NewWalletWithConfig(Config{Storeless: true})
	require.NoError(t, err)
	w.SetReceiver(receiverWith(t, &oid4vci.Oid4vciReceiver{Profile: profile.HAIP}))

	issuer, err := url.Parse("https://issuer.example")
	require.NoError(t, err)
	_, err = w.ReceiveCredential(ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuer,
			CredentialConfigurationIDs: []string{"pid"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {PreAuthorizedCode: "code"},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  newMockKeyEntry(),
	})
	require.ErrorIs(t, err, ErrProfileMismatch)
}

func TestGenerateDIDRejectsATypeIDThatIsNotADID(t *testing.T) {
	w, err := NewWalletWithConfig(Config{Storeless: true})
	require.NoError(t, err)
	_, err = w.GenerateDID(DIDCreateOptions{TypeID: "key"})
	requireCoded(t, err, ErrInvalidArgument)
}
