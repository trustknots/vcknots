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
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

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
	config := Config{Profile: p, CredStore: newProfileCredStore(t), CredentialAcceptance: acceptance}
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
		presenting, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenterTypes.Oid4vp, &oid4vp.Oid4vpPresenter{Profile: profile.Final}))
		require.NoError(t, err)
		_, err = NewWalletWithConfig(Config{Profile: profile.HAIP, CredStore: newProfileCredStore(t), Presenter: presenting})
		require.ErrorIs(t, err, ErrProfileMismatch)
	})

	t.Run("rejects a mismatched injected receiver plugin", func(t *testing.T) {
		receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{Profile: profile.Final}))
		require.NoError(t, err)
		_, err = NewWalletWithConfig(Config{Profile: profile.HAIP, CredStore: newProfileCredStore(t), Receiver: receiving})
		require.ErrorIs(t, err, ErrProfileMismatch)
	})

	t.Run("accepts matching injected plugins", func(t *testing.T) {
		receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{Profile: profile.HAIP}))
		require.NoError(t, err)
		presenting, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenterTypes.Oid4vp, &oid4vp.Oid4vpPresenter{Profile: profile.HAIP}))
		require.NoError(t, err)
		w, err := NewWalletWithConfig(Config{Profile: profile.HAIP, CredStore: newProfileCredStore(t), Receiver: receiving, Presenter: presenting})
		require.NoError(t, err)
		require.Equal(t, profile.HAIP, w.profile)
	})

	t.Run("default construction propagates the profile to both plugins", func(t *testing.T) {
		w := newProfileWallet(t, profile.HAIP, nil, nil, nil)
		assertCarrierProfile(t, w.receiver.Plugins(), profile.HAIP)
		assertCarrierProfile(t, w.presenter.Plugins(), profile.HAIP)
	})

	t.Run("unknown profile is rejected", func(t *testing.T) {
		_, err := NewWalletWithConfig(Config{Profile: profile.Profile("bogus"), CredStore: newProfileCredStore(t)})
		require.ErrorIs(t, err, profile.ErrUnknownProfile)
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
			Profile:              p,
			CredStore:            newProfileCredStore(t),
			Receiver:             receiving,
			CredentialAcceptance: &acceptance.Policy{UnverifiedIssuer: true},
			ClientAuth:           ClientAuthConfig{ClientID: "client-1"},
			DPoP:                 DPoPConfig{Key: dpopKey},
			Issuance:             IssuanceConfig{RedirectURI: "openid-credential-offer://callback"},
		})
		require.NoError(t, err)
		return w
	}

	t.Run("HAIP with no client authentication rejects before any network request", func(t *testing.T) {
		w := newWallet(profile.HAIP, &oid4vci.Oid4vciReceiver{HTTPClient: server.Client(), Profile: profile.HAIP})
		_, err := w.BeginIssuance(t.Context(), request)
		require.ErrorContains(t, err, "client authentication")
		require.ErrorIs(t, err, ErrInvalidArgument)
		require.Equal(t, int32(0), requests.Load())
	})

	t.Run("Final proceeds to metadata discovery", func(t *testing.T) {
		w := newWallet(profile.Final, &oid4vci.Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true, Profile: profile.Final})
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
	issuerJWK := jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}

	resolvePolicy := func() *acceptance.Policy {
		return &acceptance.Policy{ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{issuerJWK}, nil
		}}
	}
	anchorPolicy := func() *acceptance.Policy {
		return &acceptance.Policy{IssuerX509: &acceptance.IssuerX509TrustOptions{
			TrustAnchors:                chain.anchors(),
			AllowUnadvertisedRevocation: true,
		}}
	}

	t.Run("SD-JWT VC without x5c", func(t *testing.T) {
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder})

		finalWallet := newProfileWallet(t, profile.Final, nil, nil, resolvePolicy())
		_, err := finalWallet.storeAndParseCredential(t.Context(), &wire, credential.SDJwtVC, &holder, false)
		require.NoError(t, err)

		haipWallet := newProfileWallet(t, profile.HAIP, nil, nil, resolvePolicy())
		_, err = haipWallet.storeAndParseCredential(t.Context(), &wire, credential.SDJwtVC, &holder, false)
		require.ErrorContains(t, err, "x5c")
	})

	t.Run("trust anchor included in x5c", func(t *testing.T) {
		wire := buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder})

		finalWallet := newProfileWallet(t, profile.Final, nil, nil, anchorPolicy())
		_, err := finalWallet.storeAndParseCredential(t.Context(), &wire, credential.SDJwtVC, &holder, false)
		require.NoError(t, err)

		haipWallet := newProfileWallet(t, profile.HAIP, nil, nil, anchorPolicy())
		_, err = haipWallet.storeAndParseCredential(t.Context(), &wire, credential.SDJwtVC, &holder, false)
		require.ErrorContains(t, err, "trust anchor")
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

		_, err := fixture.wallet.PresentCredential(finalPresentationURI(fixture.baseURL, "direct_post.jwt", query), fixture.key, nil)
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

		_, err := fixture.wallet.PresentCredential(finalPresentationURI(fixture.baseURL, "direct_post", query), fixture.key, nil)
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
		_, err := fixture.wallet.PresentCredential(uri, fixture.key, nil)
		require.NoError(t, err)
		require.Empty(t, keyBindingSegment(presentedCredential(t, <-fixture.posted)))
	})

	t.Run("HAIP forces a KB-JWT", func(t *testing.T) {
		fixture, uri := newFixture(t)
		fixture.wallet.profile = profile.HAIP

		_, err := fixture.wallet.PresentCredential(uri, fixture.key, nil)
		require.NoError(t, err)

		kb := keyBindingSegment(presentedCredential(t, <-fixture.posted))
		require.NotEmpty(t, kb)
		signed, err := jwt.ParseSigned(kb, []jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)
		require.Equal(t, "kb+jwt", signed.Headers[0].ExtraHeaders[jose.HeaderType])
	})
}

// newDraftIssuanceServer serves the OpenID4VCI Draft 13 pre-authorized code
// flow and hands wire to the wallet as the issued credential.
func newDraftIssuanceServer(t *testing.T, wire string, tokenType string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	writeJSON := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(value))
	}
	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"credential_issuer":     server.URL,
			"credential_endpoint":   server.URL + "/credential",
			"nonce_endpoint":        server.URL + "/nonce",
			"authorization_servers": []string{server.URL},
			"credential_configurations_supported": map[string]any{
				"draft-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:acceptance"},
			},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":         server.URL,
			"token_endpoint": server.URL + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"access_token": "draft-token", "token_type": tokenType, "c_nonce": "draft-nonce"})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"c_nonce": "draft-nonce"})
	})
	mux.HandleFunc("/credential", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"credential": wire})
	})
	return server
}

func draftReceiveRequest(t *testing.T, server *httptest.Server, holder IKeyEntry) ReceiveCredentialRequest {
	t.Helper()
	issuer, err := url.Parse(server.URL)
	require.NoError(t, err)
	return ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{
			CredentialIssuer:           issuer,
			CredentialConfigurationIDs: []string{"draft-config"},
			Grants: map[string]*CredentialOfferGrant{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": {PreAuthorizedCode: "code"},
			},
		},
		Type: receiverTypes.Oid4vci,
		Key:  holder,
	}
}

// ReceiveCredential is upstream's Draft 13 entry point and
// Config.CredentialAcceptance is optional there by design, so a nil policy
// keeps storing credentials. SD-JWT VC §3.5 leaves issuer key resolution to
// ecosystem policy, so the library does not turn its absence into an error.
func TestReceiveCredentialDraftKeepsPermissiveDefault(t *testing.T) {
	holder := newMockKeyEntry()
	holderKey := holder.PublicKey()
	wire := buildAcceptanceWire(t, acceptanceWire{signingKey: testutil.NewP256Key(t), cnf: &holderKey})
	server := newDraftIssuanceServer(t, wire, "Bearer")

	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{HTTPClient: server.Client()}))
	require.NoError(t, err)
	store := newProfileCredStore(t)
	w, err := NewWalletWithConfig(Config{Profile: profile.Final, CredStore: store, Receiver: receiving})
	require.NoError(t, err)

	saved, err := w.ReceiveCredential(draftReceiveRequest(t, server, holder))
	require.NoError(t, err)
	require.NotNil(t, saved)
	require.Equal(t, 1, acceptanceEntryCount(t, store))
}

// ReceiveCredential is a draft entry point, so a HAIP wallet refuses it
// before anything is sent.
func TestReceiveCredentialIsRefusedUnderHAIP(t *testing.T) {
	holder := newMockKeyEntry()
	holderKey := holder.PublicKey()
	wire := buildAcceptanceWire(t, acceptanceWire{signingKey: testutil.NewP256Key(t), cnf: &holderKey})
	// HAIP §4.3 requires a DPoP-bound access token, which the receiver
	// plugin checks before the credential request.
	server := newDraftIssuanceServer(t, wire, "DPoP")

	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{HTTPClient: server.Client(), Profile: profile.HAIP}))
	require.NoError(t, err)
	store := newProfileCredStore(t)
	w, err := NewWalletWithConfig(Config{
		Profile:   profile.HAIP,
		CredStore: store,
		Receiver:  receiving,
		DPoP:      DPoPConfig{Enabled: true, Key: newMockKeyEntry()},
	})
	require.NoError(t, err)

	_, err = w.ReceiveCredential(draftReceiveRequest(t, server, holder))
	require.ErrorIs(t, err, ErrProfileForbidsDraft)
	require.Equal(t, 0, acceptanceEntryCount(t, store))
}
