package wallet

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func sameKeyThumbprint(t *testing.T, a, b jose.JSONWebKey) bool {
	t.Helper()
	aThumbprint, err := a.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	bThumbprint, err := b.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	return bytes.Equal(aThumbprint, bThumbprint)
}

type sdjwtPresentationFixture struct {
	wallet  *Wallet
	key     IKeyEntry
	baseURL string
	posted  <-chan url.Values
	// mux serves baseURL; a test adds its own handlers to it.
	mux           *http.ServeMux
	receive       func(vct string, holder *jose.JSONWebKey, mandatory map[string]any, selective map[string]string)
	receiveValues func(vct string, holder *jose.JSONWebKey, mandatory, selective map[string]any)
}

// Credentials enter through the real public receive API and TLS issuer. The
// fixture signs issuer JWTs and commits disclosures with independent SHA-256.
func newSDJWTPresentationFixture(t *testing.T) sdjwtPresentationFixture {
	t.Helper()
	holder := newMockKeyEntry()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	writeJSON := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Error(err)
		}
	}
	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"credential_issuer": server.URL, "credential_endpoint": server.URL + "/credential", "authorization_servers": []string{server.URL},
			"credential_configurations_supported": map[string]any{
				"urn:test:identity": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:identity"},
				"urn:test:address":  map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:address"},
			},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"issuer": server.URL, "token_endpoint": server.URL + "/token", "pre-authorized_grant_anonymous_access_supported": true})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"access_token": "access-token", "token_type": "Bearer", "c_nonce": "issuance-nonce"})
	})
	wires := make(chan string, 1)
	mux.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
		select {
		case wire := <-wires:
			writeJSON(w, map[string]any{"credentials": []map[string]string{{"credential": wire}}})
		case <-r.Context().Done():
		}
	})
	posted := make(chan url.Values, 4)
	mux.HandleFunc("/response", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			http.Error(w, "bad form", 400)
			return
		}
		posted <- r.PostForm
		writeJSON(w, map[string]any{"redirect_uri": server.URL + "/done"})
	})
	storage, err := local.NewLocalCredentialStorage(filepath.Join(t.TempDir(), "credentials.db"))
	require.NoError(t, err)
	store, err := credstore.NewCredStoreDispatcher(credstore.WithPlugin(local.Local, storage))
	require.NoError(t, err)
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{HTTPClient: server.Client()}))
	require.NoError(t, err)
	presenting, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, &oid4vp.Oid4vpPresenter{HTTPClient: server.Client()}))
	require.NoError(t, err)
	controller, err := NewWalletWithConfig(Config{CredStore: store, Receiver: receiving, Presenter: presenting})
	require.NoError(t, err)
	issue := func(vct string, boundKey *jose.JSONWebKey, mandatory, selective map[string]any) {
		t.Helper()
		claims := map[string]any{"iss": server.URL, "vct": vct, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
		if boundKey != nil {
			claims["cnf"] = map[string]any{"jwk": boundKey}
		}
		for k, v := range mandatory {
			claims[k] = v
		}
		var disclosures, hashes, names []string
		for name := range selective {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			raw, err := json.Marshal([]any{"test-salt-for-" + name, name, selective[name]})
			require.NoError(t, err)
			encoded := base64.RawURLEncoding.EncodeToString(raw)
			disclosures = append(disclosures, encoded)
			digest := sha256.Sum256([]byte(encoded))
			hashes = append(hashes, base64.RawURLEncoding.EncodeToString(digest[:]))
		}
		if len(hashes) > 0 {
			claims["_sd"] = hashes
			claims["_sd_alg"] = "sha-256"
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: issuerKey}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
		require.NoError(t, err)
		signed, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)
		wire := strings.Join(append([]string{signed}, disclosures...), "~") + "~"
		if boundKey != nil && !sameKeyThumbprint(t, *boundKey, holder.PublicKey()) {
			// Deliberately persist a credential bound to a different holder key
			// so presentation tests can exercise holder-binding enforcement,
			// which reception now rejects through the public API.
			entry := credstoreTypes.CredentialEntry{
				Id:         uuid.NewString(),
				ReceivedAt: time.Now(),
				Raw:        []byte(wire),
				MimeType:   string(credential.SDJwtVC),
			}
			require.NoError(t, controller.credStore.SaveCredentialEntry(entry, credstoreTypes.SupportedCredStoreTypes(0)))
			return
		}
		wires <- wire
		issuer, err := url.Parse(server.URL)
		require.NoError(t, err)
		saved, err := controller.ReceiveCredential(ReceiveCredentialRequest{CredentialOffer: &CredentialOffer{CredentialIssuer: issuer, CredentialConfigurationIDs: []string{vct}, Grants: map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {PreAuthorizedCode: "code"}}}, Type: receiverTypes.Oid4vci, Key: holder})
		require.NoError(t, err)
		require.Equal(t, wire, string(saved.Entry.Raw))
	}
	return sdjwtPresentationFixture{wallet: controller, key: holder, baseURL: server.URL, posted: posted, mux: mux, receiveValues: issue,
		receive: func(vct string, boundKey *jose.JSONWebKey, mandatory map[string]any, selective map[string]string) {
			values := map[string]any{}
			for name, value := range selective {
				values[name] = value
			}
			issue(vct, boundKey, mandatory, values)
		},
	}
}
