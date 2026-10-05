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

// Issue a signed credential through the staged Draft 13 issuance methods and a
// real TLS server.
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
			"credential_configurations_supported": map[string]any{"identity": map[string]any{"format": "vc+sd-jwt", "vct": "urn:test:identity"}},
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
	controller, err := NewWalletWithConfig(Config{CredStore: store, Receiver: receiving, Presenter: presenting, CredentialAcceptance: acceptIssuerPolicyFor(server.URL, issuerKey)})
	require.NoError(t, err)
	issuer, err := url.Parse(server.URL)
	require.NoError(t, err)
	saved, err := receiveDraft13(t.Context(), controller,
		PreAuthorizedIssuanceRequest{CredentialOffer: preAuthorizedCodeOffer(issuer, "identity", "code")},
		CredentialRequest{HolderKeys: []IKeyEntry{holder}})
	require.NoError(t, err)
	require.Equal(t, wire, string(saved.Entry.Raw))
	return controller, holder, server.URL, posted
}

func TestWallet_SDHolderBindingFromDCQL(t *testing.T) {
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
		t.Run(tc.name, func(t *testing.T) {
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
			_, err = presentWithWalletChoice(t, controller, uri, key, options)
			if tc.explicitOptions {
				require.False(t, options.(*sdjwtvc.SdJwtVcPresentationOptions).RequireKeyBinding, "request must not mutate caller options")
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
			var tokens map[string][]string
			select {
			case body := <-posted:
				require.NoError(t, json.Unmarshal([]byte(body), &tokens))
			default:
				t.Fatal("verifier received no response")
			}
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

func TestWallet_FinalBindingRequirementsArePerQuery(t *testing.T) {
	controller, key, baseURL, posted := receiveSDJWTForHolderBinding(t, true)
	query := `{"credentials":[{"id":"unbound","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"require_cryptographic_holder_binding":false},{"id":"bound","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]}}]}`
	uri := "openid4vp://present?" + url.Values{
		"client_id": {"redirect_uri:" + baseURL + "/response"}, "response_uri": {baseURL + "/response"}, "response_type": {"vp_token"},
		"response_mode": {"direct_post"}, "nonce": {"presentation-nonce"}, "dcql_query": {query},
	}.Encode()
	_, err := presentWithWalletChoice(t, controller, uri, key, nil)
	require.NoError(t, err)
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

// assignTransactionData applies OID4VP 1.0 Section 5.1 ("If there is more
// than one element in the array, the Wallet MUST use only one of the
// referenced Credentials") and Section 8.4 (the respective presentation MUST
// carry it) to the Holder's selections. The inputs here are ones the public
// request parser refuses or that need no credential store.
func TestAssignTransactionData(t *testing.T) {
	pidOnly := encodedTransactionData(`{"type":"example","credential_ids":["pid"]}`)
	either := encodedTransactionData(`{"type":"example","credential_ids":["addr","pid"]}`)
	entries := []string{pidOnly, either}
	pid := CredentialSelection{CredentialID: "a", QueryIDs: []string{"pid"}}
	addr := CredentialSelection{CredentialID: "b", QueryIDs: []string{"addr"}}
	secondPID := CredentialSelection{CredentialID: "c", QueryIDs: []string{"pid"}}
	with := func(selection CredentialSelection, indexes ...int) CredentialSelection {
		selection.TransactionData = indexes
		return selection
	}

	t.Run("default: first presented referenced query", func(t *testing.T) {
		assignment, err := assignTransactionData(entries, []CredentialSelection{pid, addr})
		require.NoError(t, err)
		require.Equal(t, []string{pidOnly}, assignment.carried(0, "pid", entries))
		require.Equal(t, []string{either}, assignment.carried(1, "addr", entries))
		// With only pid presented, pid authorizes the entry naming both.
		assignment, err = assignTransactionData(entries, []CredentialSelection{pid})
		require.NoError(t, err)
		require.Equal(t, entries, assignment.carried(0, "pid", entries))
	})
	t.Run("default: several credentials of one query need the Holder's choice", func(t *testing.T) {
		_, err := assignTransactionData([]string{pidOnly}, []CredentialSelection{pid, secondPID})
		require.ErrorIs(t, err, ErrTransactionDataAssignmentRequired)
	})
	t.Run("default: an entry referencing nothing presented", func(t *testing.T) {
		_, err := assignTransactionData([]string{either}, []CredentialSelection{{CredentialID: "x", QueryIDs: []string{"other"}}})
		require.ErrorContains(t, err, "references no selected credential (invalid_transaction_data)")
	})
	t.Run("explicit: the Holder's credential carries it", func(t *testing.T) {
		assignment, err := assignTransactionData([]string{pidOnly}, []CredentialSelection{with(pid), with(secondPID, 0)})
		require.NoError(t, err)
		require.Empty(t, assignment.carried(0, "pid", entries))
		require.Equal(t, []string{pidOnly}, assignment.carried(1, "pid", []string{pidOnly}))
		// "either" assigned to addr goes to the addr presentation.
		assignment, err = assignTransactionData(entries, []CredentialSelection{with(pid, 0), with(addr, 1)})
		require.NoError(t, err)
		require.Equal(t, []string{either}, assignment.carried(1, "addr", entries))
	})
	t.Run("explicit: the query every assigned credential answers", func(t *testing.T) {
		// credential_ids [addr, pid]: selection 0 answers pid only, selection
		// 2 answers both, so pid carries it in both presentations.
		both := CredentialSelection{CredentialID: "d", QueryIDs: []string{"pid", "addr"}}
		assignment, err := assignTransactionData([]string{either}, []CredentialSelection{with(pid, 0), addr, with(both, 0)})
		require.NoError(t, err)
		require.Equal(t, []string{either}, assignment.carried(0, "pid", []string{either}))
		require.Equal(t, []string{either}, assignment.carried(2, "pid", []string{either}))
		require.Empty(t, assignment.carried(2, "addr", []string{either}))
	})
	t.Run("explicit: several credentials of one query when the Holder says so", func(t *testing.T) {
		assignment, err := assignTransactionData([]string{pidOnly}, []CredentialSelection{with(pid, 0), with(secondPID, 0)})
		require.NoError(t, err)
		require.Equal(t, []string{pidOnly}, assignment.carried(0, "pid", []string{pidOnly}))
		require.Equal(t, []string{pidOnly}, assignment.carried(1, "pid", []string{pidOnly}))
	})
	for name, selections := range map[string][]CredentialSelection{
		"two referenced queries":           {with(pid, 1), with(addr, 1), with(secondPID, 0)},
		"a credential the entry names not": {with(addr, 0), with(pid, 1)},
		"an entry assigned to nobody":      {with(pid, 0), addr},
		"an index out of range":            {with(pid, 0, 1, 2)},
		"an index twice":                   {with(pid, 0, 0, 1)},
		"a negative index":                 {with(pid, -1)},
	} {
		t.Run("explicit refused: "+name, func(t *testing.T) {
			_, err := assignTransactionData(entries, selections)
			require.ErrorIs(t, err, ErrTransactionDataAssignmentInvalid)
		})
	}
	t.Run("explicit refused: the request carries none", func(t *testing.T) {
		_, err := assignTransactionData(nil, []CredentialSelection{with(pid, 0)})
		require.ErrorIs(t, err, ErrTransactionDataAssignmentInvalid)
	})
	_, err := assignTransactionData([]string{"not-base64!"}, []CredentialSelection{pid})
	require.ErrorContains(t, err, "transaction_data entry 0")
}

// With credential_ids ["pid"] and pid answered by two credentials (multiple:
// true), the same transaction must not be bound into both Key Binding JWTs by
// default. OpenID4VP 1.0 Section 5.1 lets one referenced Credential authorize
// it, so the library asks the Holder which
// (ErrTransactionDataAssignmentRequired) and then binds it into that
// credential's presentation alone - or into several, only when the Holder's
// assignment names each.
func TestWallet_TransactionDataFollowsTheHoldersAssignment(t *testing.T) {
	fixture := transactionDataFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Hanako"})
	entries, _, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	var identities []string
	for _, entry := range entries {
		if entry.Credential.Types[0] == "urn:test:identity" {
			identities = append(identities, entry.Entry.Id)
		}
	}
	require.Len(t, identities, 2)
	const query = `{"credentials":[{"id":"pid","format":"dc+sd-jwt","multiple":true,"meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`
	entry := encodedTransactionData(`{"type":"example","credential_ids":["pid"]}`)
	digest := sha256.Sum256([]byte(entry))
	hash := base64.RawURLEncoding.EncodeToString(digest[:])
	submit := func(first, second []int) (map[string][]string, error) {
		request := parsedPresentationRequest(t, fixture, presentationURIWithTransactionData(t, fixture.baseURL, query, []string{entry}))
		_, err := presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
			{CredentialID: identities[0], QueryIDs: []string{"pid"}, TransactionData: first},
			{CredentialID: identities[1], QueryIDs: []string{"pid"}, TransactionData: second},
		})
		if err != nil {
			select {
			case <-fixture.posted:
				t.Fatal("a refused assignment still sent a presentation")
			default:
			}
			return nil, err
		}
		return postedVPToken(t, fixture), nil
	}

	_, err = submit(nil, nil)
	require.ErrorIs(t, err, ErrTransactionDataAssignmentRequired)

	tokens, err := submit(nil, []int{0})
	require.NoError(t, err)
	require.Len(t, tokens["pid"], 2)
	require.Empty(t, transactionDataHashesOf(t, tokens["pid"][0]))
	require.Equal(t, []string{hash}, transactionDataHashesOf(t, tokens["pid"][1]))

	tokens, err = submit([]int{0}, []int{0})
	require.NoError(t, err)
	require.Equal(t, []string{hash}, transactionDataHashesOf(t, tokens["pid"][0]))
	require.Equal(t, []string{hash}, transactionDataHashesOf(t, tokens["pid"][1]))
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
