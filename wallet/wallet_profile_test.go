package wallet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// profilesFor is Config.Profiles for a wallet built around the 1.0 profile
// p: alone when it forbids draft profiles (HAIP), and otherwise with both
// draft profiles, as DefaultProfiles runs Final.
func profilesFor(p profile.Profile) []profile.Profile {
	if p.Options().ForbidDraftProfiles {
		return []profile.Profile{p}
	}
	return []profile.Profile{p, profile.Draft13(), profile.Draft24()}
}

// useProfiles re-points a built wallet at profiles, as NewWalletWithConfig
// would have set them.
func useProfiles(t *testing.T, w *Wallet, profiles ...profile.Profile) {
	t.Helper()
	resolved, err := resolveProfiles(profiles)
	require.NoError(t, err)
	w.profile, w.draft13, w.draft24 = resolved.final, resolved.draft13, resolved.draft24
}

func newProfileCredStore(t *testing.T) *credstore.CredStoreDispatcher {
	t.Helper()
	storage, err := local.NewLocalCredentialStorage(filepath.Join(t.TempDir(), "credentials.db"))
	require.NoError(t, err)
	store, err := credstore.NewCredStoreDispatcher(credstore.WithPlugin(local.Local, storage))
	require.NoError(t, err)
	return store
}

// newProfileWallet builds a root wallet with an explicit profile. A non-nil
// receiver/presenter plugin is registered as a caller-injected dispatcher;
// otherwise the root constructs the default dispatcher for that component.
func newProfileWallet(t *testing.T, p profile.Profile, receiverPlugin receiverTypes.Receiver, presenterPlugin presenterTypes.Presenter, acceptance *acceptance.Policy) *Wallet {
	t.Helper()
	config := Config{Profiles: profilesFor(p), CredStore: newProfileCredStore(t), CredentialAcceptance: acceptance}
	if receiverPlugin != nil {
		receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, receiverPlugin))
		require.NoError(t, err)
		config.Receiver = receiving
	}
	if presenterPlugin != nil {
		presenting, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenterTypes.Oid4vp, presenterPlugin))
		require.NoError(t, err)
		config.Presenter = presenting
	}
	w, err := NewWalletWithConfig(config)
	require.NoError(t, err)
	return w
}

func assertCarrierProfile[T any](t *testing.T, plugins []T, want profile.Profile) {
	t.Helper()
	found := false
	for _, plugin := range plugins {
		carrier, ok := any(plugin).(profile.Carrier)
		if !ok {
			continue
		}
		found = true
		require.Equal(t, want, carrier.ProtocolProfile())
	}
	require.True(t, found, "expected at least one profile carrier plugin")
}

func TestNewWalletWithConfig_ProfilePropagation(t *testing.T) {
	t.Run("rejects a mismatched injected presenter plugin", func(t *testing.T) {
		presenting, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenterTypes.Oid4vp, &oid4vp.Oid4vpPresenter{Profile: profile.Final()}))
		require.NoError(t, err)
		_, err = NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.HAIP()}, CredStore: newProfileCredStore(t), Presenter: presenting})
		require.ErrorIs(t, err, ErrProfileMismatch)
	})

	t.Run("rejects a mismatched injected receiver plugin", func(t *testing.T) {
		finalPlugin := &oid4vci.Oid4vciReceiver{Profile: profile.Final()}
		receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, finalPlugin))
		require.NoError(t, err)
		_, err = NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.HAIP()}, CredStore: newProfileCredStore(t), Receiver: receiving})
		require.ErrorIs(t, err, ErrProfileMismatch)
		require.Equal(t, profile.Final(), finalPlugin.Profile, "the wallet must not change a plugin it was given")
	})

	t.Run("accepts matching injected plugins", func(t *testing.T) {
		receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{Profile: profile.HAIP()}))
		require.NoError(t, err)
		presenting, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenterTypes.Oid4vp, &oid4vp.Oid4vpPresenter{Profile: profile.HAIP()}))
		require.NoError(t, err)
		w, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.HAIP()}, CredStore: newProfileCredStore(t), Receiver: receiving, Presenter: presenting})
		require.NoError(t, err)
		require.Equal(t, profile.HAIP(), w.profile)
	})

	t.Run("default construction propagates the profile to both plugins", func(t *testing.T) {
		w := newProfileWallet(t, profile.HAIP(), nil, nil, nil)
		assertCarrierProfile(t, w.receiver.Plugins(), profile.HAIP())
		assertCarrierProfile(t, w.presenter.Plugins(), profile.HAIP())
	})

	t.Run("a plugin reporting a draft profile is rejected", func(t *testing.T) {
		receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{Profile: profile.Draft24()}))
		require.NoError(t, err)
		_, err = NewWalletWithConfig(Config{CredStore: newProfileCredStore(t), Receiver: receiving})
		require.ErrorIs(t, err, profile.ErrDraftProfile)
	})
}

func TestBeginIssuance_HAIPClientAuthentication(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()
	issuerURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	request := IssuanceRequest{CredentialOffer: &CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{"pid"},
		Grants:                     map[string]*CredentialOfferGrant{"authorization_code": {IssuerState: "issuer-state-1"}},
	}}
	dpopKey, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	newWallet := func(p profile.Profile, plugin *oid4vci.Oid4vciReceiver) *Wallet {
		receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
		require.NoError(t, err)
		w, err := NewWalletWithConfig(Config{
			Profiles:             profilesFor(p),
			CredStore:            newProfileCredStore(t),
			Receiver:             receiving,
			CredentialAcceptance: acceptIssuerKeyPolicy(testutil.NewP256Key(t)),
			ClientAuth:           ClientAuthConfig{ClientID: "client-1"},
			DPoP:                 DPoPConfig{Key: dpopKey},
			Issuance:             IssuanceConfig{RedirectURI: "openid-credential-offer://callback"},
		})
		require.NoError(t, err)
		return w
	}

	t.Run("HAIP with no client authentication rejects before any network request", func(t *testing.T) {
		w := newWallet(profile.HAIP(), &oid4vci.Oid4vciReceiver{HTTPClient: server.Client(), Profile: profile.HAIP()})
		_, err := w.BeginIssuance(t.Context(), request)
		require.ErrorContains(t, err, "client authentication")
		require.ErrorIs(t, err, ErrInvalidArgument)
		require.Equal(t, int32(0), requests.Load())
	})

	t.Run("Final proceeds to metadata discovery", func(t *testing.T) {
		w := newWallet(profile.Final(), &oid4vci.Oid4vciReceiver{HTTPClient: server.Client(), Experimental: experimental.Transport{AllowHTTP: true}, Profile: profile.Final()})
		_, err := w.BeginIssuance(t.Context(), request)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "client authentication")
		require.Greater(t, requests.Load(), int32(0))
	})
}

func TestWallet_HAIPCredentialAcceptance(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	issuerKey := testutil.NewP256Key(t)

	resolvePolicy := func() *acceptance.Policy {
		return acceptIssuerKeyPolicy(issuerKey)
	}
	accept := func(w *Wallet, wire string) error {
		_, _, err := w.VerifyCredentialForAcceptance(t.Context(), CredentialAcceptanceRequest{Raw: []byte(wire), Flavor: credential.SDJwtVC, HolderKey: &holder, CredentialIssuer: testIssuerIdentifier})
		return err
	}
	anchorPolicy := func() *acceptance.Policy {
		return &acceptance.Policy{IssuerX509: &acceptance.IssuerX509TrustOptions{
			TrustAnchors:                chain.anchors(),
			AllowUnadvertisedRevocation: true,
		}}
	}

	t.Run("SD-JWT VC without x5c", func(t *testing.T) {
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder})

		finalWallet := newProfileWallet(t, profile.Final(), nil, nil, resolvePolicy())
		require.NoError(t, accept(finalWallet, wire))

		haipWallet := newProfileWallet(t, profile.HAIP(), nil, nil, resolvePolicy())
		require.ErrorContains(t, accept(haipWallet, wire), "x5c")
	})

	t.Run("trust anchor included in x5c", func(t *testing.T) {
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder})

		finalWallet := newProfileWallet(t, profile.Final(), nil, nil, anchorPolicy())
		require.NoError(t, accept(finalWallet, wire))

		haipWallet := newProfileWallet(t, profile.HAIP(), nil, nil, anchorPolicy())
		require.ErrorContains(t, accept(haipWallet, wire), "trust anchor")
	})
}

func finalPresentationURI(baseURL, responseMode, query string) string {
	return "openid4vp://present?" + url.Values{
		"client_id":     {"redirect_uri:" + baseURL + "/response"},
		"response_uri":  {baseURL + "/response"},
		"response_type": {"vp_token"},
		"response_mode": {responseMode},
		"nonce":         {"presentation-nonce"},
		"state":         {"state-to-preserve"},
		"dcql_query":    {query},
	}.Encode()
}

func presentedCredential(t *testing.T, form url.Values) string {
	t.Helper()
	var tokens map[string][]string
	require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
	require.Len(t, tokens["pid"], 1)
	return tokens["pid"][0]
}

// keyBindingSegment returns the trailing KB-JWT segment of an SD-JWT VC
// presentation, or "" when no KB-JWT was appended.
func keyBindingSegment(wire string) string {
	separator := strings.LastIndex(wire, "~")
	if separator < 0 {
		return ""
	}
	return wire[separator+1:]
}

func TestWallet_FinalAuthorizationResponseMode(t *testing.T) {
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`

	t.Run("direct_post.jwt without encryption metadata fails before any POST", func(t *testing.T) {
		fixture := newSDJWTPresentationFixture(t)
		holder := fixture.key.PublicKey()
		fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})

		_, err := presentWithWalletChoice(t, fixture.wallet, finalPresentationURI(fixture.baseURL, "direct_post.jwt", query), fixture.key, nil)
		require.Error(t, err)
		select {
		case <-fixture.posted:
			t.Fatal("direct_post.jwt without encryption metadata must not fall back to plaintext")
		default:
		}
	})

	t.Run("direct_post posts plaintext", func(t *testing.T) {
		fixture := newSDJWTPresentationFixture(t)
		holder := fixture.key.PublicKey()
		fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})

		_, err := presentWithWalletChoice(t, fixture.wallet, finalPresentationURI(fixture.baseURL, "direct_post", query), fixture.key, nil)
		require.NoError(t, err)
		require.NotEmpty(t, presentedCredential(t, <-fixture.posted))
	})
}

func TestWallet_HAIPForcesKeyBindingForConfirmationCredentials(t *testing.T) {
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"require_cryptographic_holder_binding":false,"claims":[{"path":["given_name"]}]}]}`

	newFixture := func(t *testing.T) (sdjwtPresentationFixture, string) {
		t.Helper()
		fixture := newSDJWTPresentationFixture(t)
		holder := fixture.key.PublicKey()
		fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
		return fixture, finalPresentationURI(fixture.baseURL, "direct_post", query)
	}

	t.Run("Final honors the verifier holder-binding waiver", func(t *testing.T) {
		fixture, uri := newFixture(t)
		_, err := presentWithWalletChoice(t, fixture.wallet, uri, fixture.key, nil)
		require.NoError(t, err)
		require.Empty(t, keyBindingSegment(presentedCredential(t, <-fixture.posted)))
	})

	t.Run("HAIP forces a KB-JWT", func(t *testing.T) {
		fixture, uri := newFixture(t)
		useProfiles(t, fixture.wallet, profile.HAIP())

		_, err := presentWithWalletChoice(t, fixture.wallet, uri, fixture.key, nil)
		require.NoError(t, err)

		kb := keyBindingSegment(presentedCredential(t, <-fixture.posted))
		require.NotEmpty(t, kb)
		signed, err := jwt.ParseSigned(kb, []jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)
		require.Equal(t, "kb+jwt", signed.Headers[0].ExtraHeaders[jose.HeaderType])
	})
}
