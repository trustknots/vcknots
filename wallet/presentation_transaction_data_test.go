package wallet

import (
	"context"
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
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

// Issue a signed credential through ReceiveCredential and a real TLS server.
// Presentation tests do not insert credentials through private storage.
func receiveSDJWTForHolderBinding(t *testing.T, bound bool) (*Wallet, IKeyEntry, string, <-chan string) {
	t.Helper()
	holder := newMockKeyEntry()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	claims := map[string]any{"iss": server.URL, "vct": "urn:test:identity", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	if bound {
		claims["cnf"] = map[string]any{"jwk": holder.PublicKey()}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: issuerKey}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	require.NoError(t, err)
	credentialJWT, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	wire := credentialJWT + "~"
	writeJSON := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Error(err)
		}
	}
	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"credential_issuer": server.URL, "credential_endpoint": server.URL + "/credential", "authorization_servers": []string{server.URL},
			"credential_configurations_supported": map[string]any{"identity": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:identity"}},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"issuer": server.URL, "token_endpoint": server.URL + "/token", "pre-authorized_grant_anonymous_access_supported": true})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"access_token": "access-token", "token_type": "Bearer", "c_nonce": "issuance-nonce"})
	})
	mux.HandleFunc("/credential", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"credentials": []map[string]string{{"credential": wire}}})
	})
	posted := make(chan string, 1)
	mux.HandleFunc("/response", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			http.Error(w, "bad form", 400)
			return
		}
		posted <- r.PostForm.Get("vp_token")
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
	issuer, err := url.Parse(server.URL)
	require.NoError(t, err)
	saved, err := controller.ReceiveCredential(ReceiveCredentialRequest{
		CredentialOffer: &CredentialOffer{CredentialIssuer: issuer, CredentialConfigurationIDs: []string{"identity"},
			Grants: map[string]*CredentialOfferGrant{"urn:ietf:params:oauth:grant-type:pre-authorized_code": {PreAuthorizedCode: "code"}}},
		Type: receiverTypes.Oid4vci, Key: holder,
	})
	require.NoError(t, err)
	require.Equal(t, wire, string(saved.Entry.Raw))
	return controller, holder, server.URL, posted
}

func TestWallet_SDHolderBindingFromDCQL(t *testing.T) {
	for _, api := range []string{"present", "submit"} {
		for _, tc := range []struct {
			name                                                                             string
			requestValue                                                                     any
			bound, wrongKey, explicitOptions, typedNil, forceBinding, wantBinding, wantError bool
		}{
			{name: "default requires binding", bound: true, wantBinding: true},
			{name: "explicit true", requestValue: true, bound: true, wantBinding: true},
			{name: "caller cannot disable requested binding", bound: true, explicitOptions: true, wantBinding: true},
			{name: "typed nil still requires binding", bound: true, typedNil: true, wantBinding: true},
			{name: "default rejects unbound credential", wantError: true},
			{name: "wrong signing key", bound: true, wrongKey: true, wantError: true},
			{name: "false permits unbound credential", requestValue: false},
			{name: "caller can request optional binding", requestValue: false, bound: true, forceBinding: true, wantBinding: true},
		} {
			if api == "submit" && (tc.forceBinding || tc.explicitOptions || tc.typedNil) {
				continue // The submit case passes no serialization options.
			}
			t.Run(api+"/"+tc.name, func(t *testing.T) {
				controller, key, baseURL, posted := receiveSDJWTForHolderBinding(t, tc.bound)
				if tc.wrongKey {
					key = newMockKeyEntry()
				}
				query := map[string]any{"id": "identity", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:test:identity"}}}
				if tc.requestValue != nil {
					query["require_cryptographic_holder_binding"] = tc.requestValue
				}
				queryJSON, err := json.Marshal(map[string]any{"credentials": []any{query}})
				require.NoError(t, err)
				clientID := "redirect_uri:" + baseURL + "/response"
				uri := "openid4vp://present?" + url.Values{
					"client_id": {clientID}, "response_uri": {baseURL + "/response"}, "response_type": {"vp_token"},
					"response_mode": {"direct_post"}, "nonce": {"presentation-nonce"}, "dcql_query": {string(queryJSON)},
				}.Encode()
				var tokens map[string][]string
				if api == "present" {
					var options serializerTypes.SerializePresentationOptions
					if tc.explicitOptions {
						options = &sdjwtvc.SdJwtVcPresentationOptions{RequireKeyBinding: false}
					}
					if tc.typedNil {
						options = (*sdjwtvc.SdJwtVcPresentationOptions)(nil)
					}
					if tc.forceBinding {
						options = &sdjwtvc.SdJwtVcPresentationOptions{RequireKeyBinding: true}
					}
					_, err = controller.PresentCredential(uri, key, options)
					if tc.explicitOptions {
						require.False(t, options.(*sdjwtvc.SdJwtVcPresentationOptions).RequireKeyBinding, "request must not mutate caller options")
					}
					if err == nil {
						select {
						case body := <-posted:
							require.NoError(t, json.Unmarshal([]byte(body), &tokens))
						default:
							t.Fatal("verifier received no response")
						}
					}
				} else {
					err = submitSelectedForTest(t, controller, uri, key)
					if err == nil {
						require.NoError(t, json.Unmarshal([]byte(<-posted), &tokens))
					}
				}
				if tc.wantError {
					require.Error(t, err)
					select {
					case <-posted:
						t.Fatal("rejected presentation reached the verifier")
					default:
					}
					return
				}
				require.NoError(t, err)
				require.Len(t, tokens["identity"], 1)
				wire := tokens["identity"][0]
				lastSeparator := strings.LastIndex(wire, "~")
				require.GreaterOrEqual(t, lastSeparator, 0)
				if !tc.wantBinding {
					require.True(t, strings.HasSuffix(wire, "~"))
					return
				}
				signed, err := jwt.ParseSigned(wire[lastSeparator+1:], []jose.SignatureAlgorithm{jose.ES256})
				require.NoError(t, err)
				var claims map[string]any
				require.NoError(t, signed.Claims(key.PublicKey().Key, &claims))
				require.Equal(t, "kb+jwt", signed.Headers[0].ExtraHeaders[jose.HeaderType])
				require.Equal(t, clientID, claims["aud"])
				require.Equal(t, "presentation-nonce", claims["nonce"])
				hash := sha256.Sum256([]byte(wire[:lastSeparator+1]))
				require.Equal(t, base64.RawURLEncoding.EncodeToString(hash[:]), claims["sd_hash"])
			})
		}
	}
}

func TestWallet_FinalBindingRequirementsArePerQuery(t *testing.T) {
	controller, key, baseURL, posted := receiveSDJWTForHolderBinding(t, true)
	query := `{"credentials":[{"id":"unbound","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"require_cryptographic_holder_binding":false},{"id":"bound","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]}}]}`
	uri := "openid4vp://present?" + url.Values{
		"client_id": {"redirect_uri:" + baseURL + "/response"}, "response_uri": {baseURL + "/response"}, "response_type": {"vp_token"},
		"response_mode": {"direct_post"}, "nonce": {"presentation-nonce"}, "dcql_query": {query},
	}.Encode()
	require.NoError(t, submitSelectedForTest(t, controller, uri, key))
	var tokens map[string][]string
	require.NoError(t, json.Unmarshal([]byte(<-posted), &tokens))
	require.Len(t, tokens["unbound"], 1)
	require.Len(t, tokens["bound"], 1)
	require.True(t, strings.HasSuffix(tokens["unbound"][0], "~"))
	require.False(t, strings.HasSuffix(tokens["bound"][0], "~"))
}

func TestWallet_TransactionDataBindingChecksReferencedQueries(t *testing.T) {
	optional := false
	for _, tc := range []struct {
		name, data string
		wantError  bool
	}{
		{name: "bound query", data: `{"type":"example","credential_ids":["bound"]}`},
		{name: "unbound query", data: `{"type":"example","credential_ids":["unbound"]}`, wantError: true},
		{name: "mixed queries", data: `{"type":"example","credential_ids":["bound","unbound"]}`, wantError: true},
		{name: "unknown query", data: `{"type":"example","credential_ids":["unknown"]}`, wantError: true},
		{name: "missing ids", data: `{"type":"example"}`, wantError: true},
		{name: "wrong ids type", data: `{"credential_ids":"bound"}`, wantError: true},
		{name: "malformed JSON", data: `{`, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &oid4vp.CredentialPresentationRequest{
				DcqlQuery: &oid4vp.DcqlQuery{Credentials: []oid4vp.CredentialQuery{
					{ID: "unbound", Format: "dc+sd-jwt", RequireCryptographicHolderBinding: &optional}, {ID: "bound", Format: "dc+sd-jwt"},
				}},
				TransactionData: []string{base64.RawURLEncoding.EncodeToString([]byte(tc.data))},
			}
			err := validateTransactionDataHolderBinding(req)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
	req := &oid4vp.CredentialPresentationRequest{
		DcqlQuery: &oid4vp.DcqlQuery{Credentials: []oid4vp.CredentialQuery{{ID: "unbound", Format: "dc+sd-jwt", RequireCryptographicHolderBinding: &optional}}},
	}
	req.TransactionData = []string{"not-valid-base64!"}
	require.ErrorContains(t, validateTransactionDataHolderBinding(req), "encoding")
	req.TransactionData = nil
	require.NoError(t, validateTransactionDataHolderBinding(req))
}

// transactionDataForQuery applies the OID4VP 1.0 Final Section 5.1 credential_ids
// filter and assignTransactionDataOwners the "MUST use only one of the
// referenced Credentials" rule. Both are exercised here on inputs the public
// request parser rejects before buildDCQLVPToken can see them.
func TestTransactionDataQueryFilterAndOwnership(t *testing.T) {
	first := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"example","credential_ids":["pid"]}`))
	both := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"example","credential_ids":["addr","pid"]}`))
	entries := []string{first, both}

	matched, err := transactionDataForQuery(entries, "pid")
	require.NoError(t, err)
	require.Equal(t, entries, matched)
	matched, err = transactionDataForQuery(entries, "addr")
	require.NoError(t, err)
	require.Equal(t, []string{both}, matched)
	matched, err = transactionDataForQuery(entries, "other")
	require.NoError(t, err)
	require.Empty(t, matched)
	_, err = transactionDataForQuery([]string{"not-base64!"}, "pid")
	require.ErrorContains(t, err, "transaction_data entry 0")

	selections := []string{"pid", "addr"}
	owners, err := assignTransactionDataOwners(entries, selections)
	require.NoError(t, err)
	require.Equal(t, map[string]string{first: "pid", both: "addr"}, owners)

	// With only "pid" presented, the entry listing both is authorized by it.
	owners, err = assignTransactionDataOwners(entries, selections[:1])
	require.NoError(t, err)
	require.Equal(t, map[string]string{first: "pid", both: "pid"}, owners)

	owners, err = assignTransactionDataOwners([]string{both, both}, selections)
	require.NoError(t, err)
	require.Equal(t, map[string]string{both: "addr"}, owners)

	owners, err = assignTransactionDataOwners(nil, selections)
	require.NoError(t, err)
	require.Nil(t, owners)

	_, err = assignTransactionDataOwners([]string{both}, []string{"other"})
	require.ErrorContains(t, err, "references no selected credential (invalid_transaction_data)")
	_, err = assignTransactionDataOwners([]string{"not-base64!"}, selections)
	require.ErrorContains(t, err, "transaction_data entry 0")
}

// OID4VP 1.0 Section 8.4: the presentation that authorizes a transaction_data
// entry must carry it. Only an SD-JWT VC Key Binding JWT can here, so an entry
// owned by any other credential fails the presentation instead of being
// dropped. The request is built directly because the parser refuses it.
func TestWallet_TransactionDataOwnedByANonSDJWTCredentialFails(t *testing.T) {
	controller, key := receiveCredentialForPresentationTest(t)
	req := &oid4vp.CredentialPresentationRequest{
		OAuthAuthzRequest: &oid4vp.OAuthAuthzRequest{ResponseType: "vp_token", ClientID: "redirect_uri:https://verifier.example/response", Nonce: "n"},
		DcqlQuery: &oid4vp.DcqlQuery{Credentials: []oid4vp.CredentialQuery{{
			ID: "vc", Format: "jwt_vc_json", Meta: map[string]any{"type_values": [][]string{{"VerifiableCredential"}}},
		}}},
		TransactionData: []string{base64.RawURLEncoding.EncodeToString([]byte(`{"type":"example","credential_ids":["vc"]}`))},
	}

	entries, _, err := controller.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	_, err = controller.buildDCQLVPToken(context.Background(), nil, req, Presentation{Key: key, Credentials: []CredentialSelection{
		{CredentialID: entries[0].Entry.Id, QueryIDs: []string{"vc"}},
	}})
	require.ErrorContains(t, err, "invalid_transaction_data")
}

// submitSelectedForTest presents the library's own choice for uri through
// ParsePresentationRequest, SelectCredentials and SubmitPresentation.
func submitSelectedForTest(t *testing.T, w *Wallet, uri string, key IKeyEntry) error {
	t.Helper()
	request, err := w.ParsePresentationRequest(t.Context(), uri)
	if err != nil {
		return err
	}
	selections, err := w.SelectCredentials(t.Context(), request)
	if err != nil {
		return err
	}
	_, err = w.SubmitPresentation(t.Context(), request, Presentation{Key: key, Credentials: selections})
	return err
}
