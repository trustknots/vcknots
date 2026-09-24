package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

func presentationURI(baseURL, query string) string {
	return "openid4vp://present?" + url.Values{
		"client_id": {"redirect_uri:" + baseURL + "/response"}, "response_uri": {baseURL + "/response"}, "response_type": {"vp_token"},
		"response_mode": {"direct_post"}, "nonce": {"presentation-nonce"}, "state": {"state-to-preserve"}, "dcql_query": {query},
	}.Encode()
}

func disclosedNames(t *testing.T, wire string) []string {
	t.Helper()
	names := []string{}
	parts := strings.Split(wire, "~")
	for _, encoded := range parts[1 : len(parts)-1] {
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		require.NoError(t, err)
		var disclosure []any
		require.NoError(t, json.Unmarshal(raw, &disclosure))
		require.Len(t, disclosure, 3)
		names = append(names, disclosure[1].(string))
	}
	return names
}

func TestWallet_PublicDCQLPresentation(t *testing.T) {
	{
		for _, tc := range []struct {
			name, query string
			want        map[string][]string
			wantError   bool
		}{
			{name: "no claims discloses none", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]}}]}`, want: map[string][]string{"pid": {}}},
			{name: "only requested claim", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "mandatory claim needs no disclosure", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["nationality"]},{"path":["given_name"]}]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "all credential queries answered", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},{"id":"address","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:address"]},"claims":[{"path":["street_address"]}]}]}`, want: map[string][]string{"pid": {"given_name"}, "address": {"street_address"}}},
			{name: "required missing credential sends nothing", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]}},{"id":"missing","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:missing"]}}]}`, wantError: true},
			{name: "required missing claim sends nothing", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]},{"path":["unavailable"]}]}]}`, wantError: true},
			{name: "optional missing query omitted", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]}},{"id":"missing","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:missing"]}}],"credential_sets":[{"options":[["pid"]]},{"options":[["missing"]],"required":false}]}`, want: map[string][]string{"pid": {}}},
			{name: "claim sets disclose only first matching choice", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"id":"given","path":["given_name"]},{"id":"family","path":["family_name"]}],"claim_sets":[["given"],["family"]]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "claim sets use available alternative", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"id":"missing","path":["not_available"]},{"id":"given","path":["given_name"]}],"claim_sets":[["missing"],["given"]]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "credential sets select fallback", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},{"id":"missing","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:missing"]}}],"credential_sets":[{"options":[["pid","missing"],["pid"]]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "same credential has different disclosure per query", query: `{"credentials":[{"id":"given","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},{"id":"family","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["family_name"]}]}]}`, want: map[string][]string{"given": {"given_name"}, "family": {"family_name"}}},
			{name: "claim value matches", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"],"values":["Taro"]}]}]}`, want: map[string][]string{"pid": {"given_name"}}},
			{name: "claim value mismatch sends nothing", query: `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"],"values":["Hanako"]}]}]}`, wantError: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				fixture := newSDJWTPresentationFixture(t)
				holder := fixture.key.PublicKey()
				fixture.receive("urn:test:identity", &holder, map[string]any{"nationality": "JP"}, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
				// A newer, different credential must not replace the matching identity.
				fixture.receive("urn:test:address", &holder, nil, map[string]string{"street_address": "1 Example St", "postal_code": "100-0000"})
				uri := presentationURI(fixture.baseURL, tc.query)
				var tokens map[string][]string
				redirect, err := fixture.wallet.PresentCredential(uri, fixture.key, nil)
				if err == nil {
					require.Equal(t, fixture.baseURL+"/done", redirect)
					select {
					case form := <-fixture.posted:
						require.Equal(t, "state-to-preserve", form.Get("state"))
						require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
					default:
						t.Fatal("no response received")
					}
				}
				if tc.wantError {
					require.Error(t, err)
					select {
					case <-fixture.posted:
						t.Fatal("unsatisfied request disclosed credentials")
					default:
					}
					return
				}
				require.NoError(t, err)
				require.Len(t, tokens, len(tc.want))
				for id, names := range tc.want {
					require.Len(t, tokens[id], 1)
					require.ElementsMatch(t, names, disclosedNames(t, tokens[id][0]))
					wire := tokens[id][0]
					separator := strings.LastIndex(wire, "~")
					signed, err := jwt.ParseSigned(wire[separator+1:], []jose.SignatureAlgorithm{jose.ES256})
					require.NoError(t, err)
					var claims map[string]any
					require.NoError(t, signed.Claims(holder.Key, &claims))
					require.Equal(t, "kb+jwt", signed.Headers[0].ExtraHeaders[jose.HeaderType])
					require.Equal(t, "redirect_uri:"+fixture.baseURL+"/response", claims["aud"])
					require.Equal(t, "presentation-nonce", claims["nonce"])
					digest := sha256.Sum256([]byte(wire[:separator+1]))
					require.Equal(t, base64.RawURLEncoding.EncodeToString(digest[:]), claims["sd_hash"])
				}
			})
		}
	}
}

func TestWallet_DCQLRespectsCallerDisclosureChoice(t *testing.T) {
	for _, tc := range []struct {
		name      string
		options   *sdjwtvc.SdJwtVcPresentationOptions
		wantError bool
	}{
		{name: "caller cannot add unrequested claims", options: &sdjwtvc.SdJwtVcPresentationOptions{SelectedClaims: []string{"given_name", "family_name"}}},
		{name: "caller cannot be forced to disclose denied claim", options: &sdjwtvc.SdJwtVcPresentationOptions{SelectedClaims: []string{"family_name"}}, wantError: true},
		{name: "explicit empty selection denies all", options: &sdjwtvc.SdJwtVcPresentationOptions{LimitDisclosureToSelectedClaims: true}, wantError: true},
		{name: "typed nil defaults safely"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSDJWTPresentationFixture(t)
			holder := fixture.key.PublicKey()
			fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
			uri := presentationURI(fixture.baseURL, `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`)
			var options serializerTypes.SerializePresentationOptions = tc.options
			var before sdjwtvc.SdJwtVcPresentationOptions
			if tc.options != nil {
				before = *tc.options
			}
			_, err := fixture.wallet.PresentCredential(uri, fixture.key, options)
			if tc.options != nil {
				require.Equal(t, before, *tc.options)
			}
			if tc.wantError {
				require.Error(t, err)
				select {
				case <-fixture.posted:
					t.Fatal("caller denial was ignored")
				default:
				}
				return
			}
			require.NoError(t, err)
			var tokens map[string][]string
			require.NoError(t, json.Unmarshal([]byte((<-fixture.posted).Get("vp_token")), &tokens))
			require.Equal(t, []string{"given_name"}, disclosedNames(t, tokens["pid"][0]))
		})
	}
}

func TestWallet_DCQLDoesNotSubmitWhenLaterCredentialCannotBind(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	otherHolder := newMockKeyEntry().PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	fixture.receive("urn:test:address", &otherHolder, nil, map[string]string{"street_address": "1 Example St"})
	uri := presentationURI(fixture.baseURL, `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},{"id":"address","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:address"]},"claims":[{"path":["street_address"]}]}]}`)
	_, err := fixture.wallet.PresentCredential(uri, fixture.key, nil)
	require.ErrorContains(t, err, "signing key does not match")
	select {
	case <-fixture.posted:
		t.Fatal("partially serialized response was submitted")
	default:
	}
}

func TestWallet_DCQLIntegerValuesSurviveReceiveAndPresentation(t *testing.T) {
	for _, selective := range []bool{false, true} {
		for _, requested := range []string{"9007199254740993", "9007199254740992"} {
			t.Run(fmt.Sprintf("selective=%t/request=%s", selective, requested), func(t *testing.T) {
				fixture := newSDJWTPresentationFixture(t)
				holder := fixture.key.PublicKey()
				claims := map[string]any{"account_number": int64(9007199254740993)}
				if selective {
					fixture.receiveValues("urn:test:identity", &holder, nil, claims)
				} else {
					fixture.receiveValues("urn:test:identity", &holder, claims, nil)
				}
				query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["account_number"],"values":[` + requested + `]}]}]}`
				_, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
				if requested != "9007199254740993" {
					require.Error(t, err)
					select {
					case <-fixture.posted:
						t.Fatal("different integer value was submitted")
					default:
					}
					return
				}
				require.NoError(t, err)
				select {
				case <-fixture.posted:
				default:
					t.Fatal("exact integer value was not submitted")
				}
			})
		}
	}
}

func TestWallet_DCQLUnboundCredentialIsSkipped(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", nil, nil, map[string]string{"given_name": "Unbound"})

	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`
	_, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
	var authzErr *oid4vp.AuthorizationRequestError
	require.ErrorAs(t, err, &authzErr)
	require.Equal(t, oid4vp.AccessDeniedError, authzErr.Code)

	// A bound credential for the same query must be selected instead.
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Bound"})
	redirect, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)
	select {
	case form := <-fixture.posted:
		var tokens map[string][]string
		require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
		require.Len(t, tokens["pid"], 1)
	default:
		t.Fatal("no presentation submitted")
	}
}

func TestWallet_DCQLMultiplePresentsEveryMatch(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Hanako"})

	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"multiple":true}]}`
	redirect, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)
	select {
	case form := <-fixture.posted:
		var tokens map[string][]string
		require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
		require.Len(t, tokens["pid"], 2)
	default:
		t.Fatal("no presentation submitted")
	}
}

func TestWallet_DCQLNestedClaimDisclosureMinimality(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encodeDisclosure := func(name, value string) (string, string) {
		raw, err := json.Marshal([]any{"salt-" + name, name, value})
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		digest := sha256.Sum256([]byte(encoded))
		return encoded, base64.RawURLEncoding.EncodeToString(digest[:])
	}
	postal, postalHash := encodeDisclosure("postal_code", "12345")
	city, cityHash := encodeDisclosure("city", "Milliways")

	payload := map[string]any{
		"iss": "https://issuer.example", "vct": "urn:test:identity",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		"cnf":     map[string]any{"jwk": holder},
		"address": map[string]any{"_sd": []any{postalHash, cityHash}},
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: issuerKey}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(payload).Serialize()
	require.NoError(t, err)
	wire := signed + "~" + postal + "~" + city + "~"
	require.NoError(t, fixture.wallet.credStore.SaveCredentialEntry(credstoreTypes.CredentialEntry{
		Id: uuid.NewString(), ReceivedAt: time.Now(), Raw: []byte(wire), MimeType: string(credential.SDJwtVC),
	}, credstoreTypes.SupportedCredStoreTypes(0)))

	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["address","postal_code"]}]}]}`
	redirect, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)
	select {
	case form := <-fixture.posted:
		var tokens map[string][]string
		require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
		require.Len(t, tokens["pid"], 1)
		require.Equal(t, []string{"postal_code"}, disclosedNames(t, tokens["pid"][0]))
	default:
		t.Fatal("no presentation submitted")
	}
}

func TestWallet_DCQLUnsatisfiableIsAccessDenied(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:missing"]}}]}`
	_, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
	var authzErr *oid4vp.AuthorizationRequestError
	require.ErrorAs(t, err, &authzErr)
	require.Equal(t, oid4vp.AccessDeniedError, authzErr.Code)
}

// OID4VP 1.0 Appendix B.1.1: a jwt_vc_json credential is presented only when
// its types cover one type_values alternative.
func TestWallet_DCQLMatchesJWTVCTypeValues(t *testing.T) {
	for _, tc := range []struct {
		name, typeValues string
		wantPresented    bool
	}{
		{name: "expanded base type", typeValues: `[["https://www.w3.org/2018/credentials#VerifiableCredential"]]`, wantPresented: true},
		{name: "type the credential lacks", typeValues: `[["VerifiableCredential","IDCredential"]]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, key := receiveCredentialForPresentationTest(t)
			posted := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ParseForm() == nil && r.PostForm.Get("vp_token") != "" {
					posted = true
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(server.Close)
			query := `{"credentials":[{"id":"vc","format":"jwt_vc_json","meta":{"type_values":` + tc.typeValues + `}}]}`
			uri := "openid4vp://present?" + url.Values{
				"client_id": {"redirect_uri:" + server.URL}, "response_uri": {server.URL}, "response_type": {"vp_token"},
				"response_mode": {"direct_post"}, "nonce": {"presentation-nonce"}, "dcql_query": {query},
			}.Encode()

			_, err := controller.PresentCredential(uri, key, nil)
			if tc.wantPresented {
				require.NoError(t, err)
				require.True(t, posted)
				return
			}
			var authzErr *oid4vp.AuthorizationRequestError
			require.ErrorAs(t, err, &authzErr)
			require.Equal(t, oid4vp.AccessDeniedError, authzErr.Code)
			require.False(t, posted)
		})
	}
}

func TestWallet_ConfigPropagatesTransactionDataTypes(t *testing.T) {
	controller, err := NewWalletWithConfig(Config{SupportedTransactionDataTypes: []string{"example"}})
	require.NoError(t, err)
	var finalPresenter *oid4vp.Oid4vpPresenter
	for _, plugin := range controller.presenter.Plugins() {
		if candidate, ok := plugin.(*oid4vp.Oid4vpPresenter); ok {
			finalPresenter = candidate
		}
	}
	require.NotNil(t, finalPresenter)
	require.Equal(t, []string{"example"}, finalPresenter.SupportedTransactionDataTypes)
}

func TestWallet_SubmitHandlesTransactionData(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	fixturePresenter(t, fixture.wallet).SupportedTransactionDataTypes = []string{"example"}

	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	metadata, err := json.Marshal(map[string]any{
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &recipient.PublicKey, KeyID: "enc", Use: "enc", Algorithm: string(jose.ECDH_ES),
		}}},
		"encrypted_response_enc_values_supported": []string{"A256GCM"},
	})
	require.NoError(t, err)
	transactionData := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"example","credential_ids":["pid"],"transaction_data_hashes_alg":["sha-384"]}`))
	entries, err := json.Marshal([]string{transactionData})
	require.NoError(t, err)
	uri := "openid4vp://present?" + url.Values{
		"client_id": {"redirect_uri:" + fixture.baseURL + "/response"}, "response_uri": {fixture.baseURL + "/response"},
		"response_type": {"vp_token"}, "response_mode": {"direct_post.jwt"}, "nonce": {"n"}, "state": {"s"},
		"dcql_query":       {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`},
		"client_metadata":  {string(metadata)},
		"transaction_data": {string(entries)},
	}.Encode()
	request := parsedPresentationRequest(t, fixture, uri)
	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	result, err := fixture.wallet.SubmitPresentation(t.Context(), request, Presentation{Key: fixture.key, Credentials: selections})
	require.NoError(t, err)
	require.True(t, result.Encrypted)

	select {
	case form := <-fixture.posted:
		jwe, err := jose.ParseEncrypted(form.Get("response"), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
		require.NoError(t, err)
		plaintext, err := jwe.Decrypt(recipient)
		require.NoError(t, err)
		var payload struct {
			VPToken map[string][]string `json:"vp_token"`
		}
		require.NoError(t, json.Unmarshal(plaintext, &payload))
		wire := payload.VPToken["pid"][0]
		kbJWT := wire[strings.LastIndex(wire, "~")+1:]
		parts := strings.Split(kbJWT, ".")
		require.Len(t, parts, 3)
		claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		var claims map[string]any
		require.NoError(t, json.Unmarshal(claimsBytes, &claims))
		require.Equal(t, "sha-384", claims["transaction_data_hashes_alg"])
		hashes, ok := claims["transaction_data_hashes"].([]any)
		require.True(t, ok)
		require.Len(t, hashes, 1)
		expected := sha512.Sum384([]byte(transactionData))
		require.Equal(t, base64.RawURLEncoding.EncodeToString(expected[:]), hashes[0])
	default:
		t.Fatal("no encrypted response submitted")
	}
}

// presentationURIWithTransactionData builds the same Authorization Request as
// presentationURI plus the transaction_data parameter, which the Final profile
// carries as a JSON-serialized array of base64url strings.
func presentationURIWithTransactionData(t *testing.T, baseURL, query string, entries []string) string {
	t.Helper()
	raw, err := json.Marshal(entries)
	require.NoError(t, err)
	return "openid4vp://present?" + url.Values{
		"client_id": {"redirect_uri:" + baseURL + "/response"}, "response_uri": {baseURL + "/response"}, "response_type": {"vp_token"},
		"response_mode": {"direct_post"}, "nonce": {"presentation-nonce"}, "state": {"state-to-preserve"}, "dcql_query": {query},
		"transaction_data": {string(raw)},
	}.Encode()
}

// encodedTransactionData base64url-encodes one transaction_data object.
func encodedTransactionData(object string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(object))
}

// transactionDataHashesOf reads the transaction_data_hashes claim of a
// presentation's Key Binding JWT, returning nil when the claim is absent.
func transactionDataHashesOf(t *testing.T, wire string) []string {
	t.Helper()
	separator := strings.LastIndex(wire, "~")
	require.Greater(t, separator, -1)
	parts := strings.Split(wire[separator+1:], ".")
	require.Len(t, parts, 3, "presentation has no Key Binding JWT")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	raw, present := claims["transaction_data_hashes"]
	if !present {
		require.NotContains(t, claims, "transaction_data_hashes_alg")
		return nil
	}
	values, ok := raw.([]any)
	require.True(t, ok)
	require.Equal(t, "sha-256", claims["transaction_data_hashes_alg"])
	hashes := make([]string, 0, len(values))
	for _, value := range values {
		hash, ok := value.(string)
		require.True(t, ok)
		hashes = append(hashes, hash)
	}
	return hashes
}

// transactionDataFixture stores a holder-bound identity and address credential
// and accepts the "example" transaction data type.
func transactionDataFixture(t *testing.T) sdjwtPresentationFixture {
	t.Helper()
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	fixture.receive("urn:test:address", &holder, nil, map[string]string{"street_address": "1 Example St"})
	fixturePresenter(t, fixture.wallet).SupportedTransactionDataTypes = []string{"example"}
	return fixture
}

// presentWithTransactionData runs the public presentation flow and returns the
// vp_token the verifier received.
func presentWithTransactionData(t *testing.T, fixture sdjwtPresentationFixture, query string, entries []string) (map[string][]string, error) {
	t.Helper()
	uri := presentationURIWithTransactionData(t, fixture.baseURL, query, entries)
	redirect, err := fixture.wallet.PresentCredential(uri, fixture.key, nil)
	if err != nil {
		select {
		case <-fixture.posted:
			t.Fatal("rejected transaction_data still disclosed credentials")
		default:
		}
		return nil, err
	}
	require.Equal(t, fixture.baseURL+"/done", redirect)
	var tokens map[string][]string
	select {
	case form := <-fixture.posted:
		require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
	default:
		t.Fatal("no response received")
	}
	return tokens, nil
}

const twoCredentialDCQLQuery = `{"credentials":[` +
	`{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},` +
	`{"id":"addr","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:address"]},"claims":[{"path":["street_address"]}]}]}`

// OID4VP 1.0 Final Section 5.1 binds each transaction_data entry to the
// credential queries named in its credential_ids, and Section 8.4 requires the
// hash in "the respective Credential presentation" only. A presentation for a
// query the entry does not name must stay free of the hash.
func TestDCQLTransactionDataAttachedOnlyToNamedCredential(t *testing.T) {
	fixture := transactionDataFixture(t)
	entry := encodedTransactionData(`{"type":"example","credential_ids":["pid"]}`)
	tokens, err := presentWithTransactionData(t, fixture, twoCredentialDCQLQuery, []string{entry})
	require.NoError(t, err)
	require.Len(t, tokens, 2)
	digest := sha256.Sum256([]byte(entry))
	require.Equal(t, []string{base64.RawURLEncoding.EncodeToString(digest[:])}, transactionDataHashesOf(t, tokens["pid"][0]))
	require.Empty(t, transactionDataHashesOf(t, tokens["addr"][0]))
}

// OID4VP 1.0 Final Section 5.1: "If there is more than one element in the
// array, the Wallet MUST use only one of the referenced Credentials for
// transaction authorization." The wallet authorizes with the first referenced
// query it is actually presenting, here "addr", and hashes the entry once.
func TestDCQLTransactionDataAttachedOnceWhenSeveralCredentialIDsMatch(t *testing.T) {
	fixture := transactionDataFixture(t)
	entry := encodedTransactionData(`{"type":"example","credential_ids":["addr","pid"]}`)
	tokens, err := presentWithTransactionData(t, fixture, twoCredentialDCQLQuery, []string{entry})
	require.NoError(t, err)
	require.Len(t, tokens, 2)
	digest := sha256.Sum256([]byte(entry))
	hash := base64.RawURLEncoding.EncodeToString(digest[:])
	carriers := []string{}
	for queryID, presentations := range tokens {
		require.Len(t, presentations, 1)
		if len(transactionDataHashesOf(t, presentations[0])) > 0 {
			carriers = append(carriers, queryID)
		}
	}
	require.Equal(t, []string{"addr"}, carriers)
	require.Equal(t, []string{hash}, transactionDataHashesOf(t, tokens["addr"][0]))
}

// OID4VP 1.0 Final lists "the credential_ids does not match, or the referenced
// Credential(s) are not available in the Wallet" as invalid_transaction_data.
// The optional "missing" query is part of the request but is not presented, so
// an entry that only references it must fail before anything is disclosed.
func TestDCQLTransactionDataRejectsUnmatchedEntry(t *testing.T) {
	fixture := transactionDataFixture(t)
	query := `{"credentials":[` +
		`{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},` +
		`{"id":"missing","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:missing"]}}],` +
		`"credential_sets":[{"options":[["pid"]]},{"options":[["missing"]],"required":false}]}`
	entry := encodedTransactionData(`{"type":"example","credential_ids":["missing"]}`)
	_, err := presentWithTransactionData(t, fixture, query, []string{entry})
	require.ErrorContains(t, err, "transaction_data entry 0 references no selected credential (invalid_transaction_data)")
}

// parsedPresentationRequest admits an Authorization Request the way an
// application does before it renders a consent screen and hands the Holder's
// decision back to the wallet.
func parsedPresentationRequest(t *testing.T, fixture sdjwtPresentationFixture, uri string) *oid4vp.AdmittedRequest {
	t.Helper()
	request, err := fixture.wallet.ParsePresentationRequest(t.Context(), uri)
	require.NoError(t, err)
	return request
}

// fixturePresenter returns the OpenID4VP plugin registered with w.
func fixturePresenter(t *testing.T, w *Wallet) *oid4vp.Oid4vpPresenter {
	t.Helper()
	for _, plugin := range w.presenter.Plugins() {
		if presenting, ok := plugin.(*oid4vp.Oid4vpPresenter); ok {
			return presenting
		}
	}
	t.Fatal("no OpenID4VP presenter registered")
	return nil
}

// storedCredentialID returns the wallet credential id a consent screen shows
// for a vct, which is the CandidateID of a DCQL selection.
func storedCredentialID(t *testing.T, controller *Wallet, vct string) string {
	t.Helper()
	entries, _, err := controller.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	for _, entry := range entries {
		if len(entry.Credential.Types) > 0 && entry.Credential.Types[0] == vct {
			return entry.Entry.Id
		}
	}
	t.Fatalf("no stored credential with vct %q", vct)
	return ""
}

// claimSetsDCQLQuery offers the same credential under two alternative claim
// sets, so the disclosure depends entirely on which one is chosen.
const claimSetsDCQLQuery = `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},` +
	`"claims":[{"id":"given","path":["given_name"]},{"id":"family","path":["family_name"]}],"claim_sets":[["given"],["family"]]}]}`

// OID4VP 1.0 Section 6.3: "the Wallet MUST return one of the sets that it can
// satisfy". The library's own selection always takes the first satisfiable set
// (TestWallet_PublicDCQLPresentation), so a Holder who chose the second one
// must reach the Verifier with that choice intact.
func TestWallet_SubmitPresentationDisclosesTheChosenClaimSet(t *testing.T) {
	for _, claims := range [][]string{{"given_name"}, {"family_name"}} {
		t.Run(claims[0], func(t *testing.T) {
			fixture := newSDJWTPresentationFixture(t)
			holder := fixture.key.PublicKey()
			fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
			request := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, claimSetsDCQLQuery))

			redirect, err := presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{{
				CredentialID:    storedCredentialID(t, fixture.wallet, "urn:test:identity"),
				QueryIDs:        []string{"pid"},
				DisclosedClaims: claims,
			}})
			require.NoError(t, err)
			require.Equal(t, fixture.baseURL+"/done", redirect)

			select {
			case form := <-fixture.posted:
				require.Equal(t, "state-to-preserve", form.Get("state"))
				var tokens map[string][]string
				require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
				require.Len(t, tokens["pid"], 1)
				require.Equal(t, claims, disclosedNames(t, tokens["pid"][0]))
			default:
				t.Fatal("no presentation submitted")
			}
		})
	}
}

// A consent decision the request cannot accept must fail before anything is
// serialized, and must be distinguishable from a transport failure.
func TestWallet_SubmitPresentationRejectsUnsatisfyingSelection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		query      string
		selections func(identity, address string) []CredentialSelection
	}{
		{
			name:  "claims outside every claim set",
			query: claimSetsDCQLQuery,
			selections: func(identity, _ string) []CredentialSelection {
				return []CredentialSelection{{CredentialID: identity, QueryIDs: []string{"pid"}, DisclosedClaims: []string{"birthdate"}}}
			},
		},
		{
			name:  "credential the credential query does not accept",
			query: claimSetsDCQLQuery,
			selections: func(_, address string) []CredentialSelection {
				return []CredentialSelection{{CredentialID: address, QueryIDs: []string{"pid"}}}
			},
		},
		{
			name:  "credential query the request does not contain",
			query: claimSetsDCQLQuery,
			selections: func(identity, _ string) []CredentialSelection {
				return []CredentialSelection{{CredentialID: identity, QueryIDs: []string{"passport"}}}
			},
		},
		{
			name:  "required credential query left unanswered",
			query: twoCredentialDCQLQuery,
			selections: func(identity, _ string) []CredentialSelection {
				return []CredentialSelection{{CredentialID: identity, QueryIDs: []string{"pid"}}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSDJWTPresentationFixture(t)
			holder := fixture.key.PublicKey()
			fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
			fixture.receive("urn:test:address", &holder, nil, map[string]string{"street_address": "1 Example St"})
			request := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, tc.query))

			_, err := presentSelections(t, fixture.wallet, request, fixture.key, tc.selections(
				storedCredentialID(t, fixture.wallet, "urn:test:identity"),
				storedCredentialID(t, fixture.wallet, "urn:test:address"),
			))
			require.ErrorIs(t, err, oid4vp.ErrDCQLSelectionUnsatisfied)
			select {
			case <-fixture.posted:
				t.Fatal("rejected selection still disclosed credentials")
			default:
			}
		})
	}
}

// OID4VP 1.0 Section 6.4.2 lets the Holder decline an optional credential_set,
// and Section 8.1 defines the vp_token as an object, so the answer to declining
// everything is the empty object rather than an error or an absent parameter.
func TestWallet_SubmitPresentationSendsEmptyVPTokenWhenNothingIsSelected(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}],` +
		`"credential_sets":[{"options":[["pid"]],"required":false}]}`
	request := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query))

	redirect, err := presentSelections(t, fixture.wallet, request, fixture.key, nil)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)

	select {
	case form := <-fixture.posted:
		require.Equal(t, "{}", form.Get("vp_token"))
		require.Equal(t, "state-to-preserve", form.Get("state"))
	default:
		t.Fatal("no presentation submitted")
	}
}

// The caller-chosen path must assign transaction_data exactly as the
// library-chosen path does: OID4VP 1.0 Final Section 5.1 allows only one of the
// referenced Credentials to authorize the transaction, and Section 8.4 puts the
// hash in that Credential's presentation alone.
func TestWallet_SubmitPresentationKeepsTransactionDataAssignment(t *testing.T) {
	fixture := transactionDataFixture(t)
	entry := encodedTransactionData(`{"type":"example","credential_ids":["addr","pid"]}`)
	request := parsedPresentationRequest(t, fixture,
		presentationURIWithTransactionData(t, fixture.baseURL, twoCredentialDCQLQuery, []string{entry}))

	redirect, err := presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: storedCredentialID(t, fixture.wallet, "urn:test:identity"), QueryIDs: []string{"pid"}},
		{CredentialID: storedCredentialID(t, fixture.wallet, "urn:test:address"), QueryIDs: []string{"addr"}},
	})
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)

	select {
	case form := <-fixture.posted:
		var tokens map[string][]string
		require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
		digest := sha256.Sum256([]byte(entry))
		require.Equal(t, []string{base64.RawURLEncoding.EncodeToString(digest[:])}, transactionDataHashesOf(t, tokens["addr"][0]))
		require.Empty(t, transactionDataHashesOf(t, tokens["pid"][0]))
	default:
		t.Fatal("no presentation submitted")
	}
}

// storeSDJWT signs payload as an SD-JWT VC bound to the fixture key and stores
// it with the given disclosures.
func storeSDJWT(t *testing.T, fixture sdjwtPresentationFixture, payload map[string]any, disclosures ...string) {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	payload["iss"] = "https://issuer.example"
	payload["vct"] = "urn:test:identity"
	payload["iat"] = time.Now().Unix()
	payload["exp"] = time.Now().Add(time.Hour).Unix()
	payload["cnf"] = map[string]any{"jwk": fixture.key.PublicKey()}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: issuerKey}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(payload).Serialize()
	require.NoError(t, err)
	wire := signed + "~" + strings.Join(disclosures, "~") + "~"
	require.NoError(t, fixture.wallet.credStore.SaveCredentialEntry(credstoreTypes.CredentialEntry{
		Id: uuid.NewString(), ReceivedAt: time.Now(), Raw: []byte(wire), MimeType: string(credential.SDJwtVC),
	}, credstoreTypes.SupportedCredStoreTypes(0)))
}

// sdDisclosure encodes one disclosure (a [salt, name, value] object property or
// a [salt, value] array element) and returns it with its sha-256 digest.
func sdDisclosure(t *testing.T, parts ...any) (string, string) {
	t.Helper()
	raw, err := json.Marshal(parts)
	require.NoError(t, err)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(encoded))
	return encoded, base64.RawURLEncoding.EncodeToString(digest[:])
}

// disclosedParts returns the disclosures of a presented SD-JWT, each as the
// name of an object property or the value of an array element.
func disclosedParts(t *testing.T, wire string) []any {
	t.Helper()
	parts := strings.Split(wire, "~")
	disclosed := []any{}
	for _, encoded := range parts[1 : len(parts)-1] {
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		require.NoError(t, err)
		var disclosure []any
		require.NoError(t, json.Unmarshal(raw, &disclosure))
		require.True(t, len(disclosure) == 2 || len(disclosure) == 3)
		disclosed = append(disclosed, disclosure[1])
	}
	return disclosed
}

// OID4VP 1.0 Section 6.4.1 and Section 7: a claims query selects the claims its
// path points to, values treats a non-matching element as absent, and a
// selected object is disclosed with its selectively disclosable members.
func TestWallet_DCQLDisclosesExactlyTheSelectedClaims(t *testing.T) {
	for _, tc := range []struct {
		name, claims string
		want         []any
	}{
		{name: "values narrow a wildcard to the matching element", claims: `[{"path":["nationalities",null],"values":["DE"]}]`, want: []any{"DE"}},
		{name: "wildcard without values selects every element", claims: `[{"path":["nationalities",null]}]`, want: []any{"JP", "DE", "FR"}},
		{name: "a selected object carries its members", claims: `[{"path":["address"]}]`, want: []any{"address", "postal_code", "city"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSDJWTPresentationFixture(t)
			jp, jpHash := sdDisclosure(t, "salt-jp", "JP")
			de, deHash := sdDisclosure(t, "salt-de", "DE")
			fr, frHash := sdDisclosure(t, "salt-fr", "FR")
			postal, postalHash := sdDisclosure(t, "salt-postal", "postal_code", "12345")
			city, cityHash := sdDisclosure(t, "salt-city", "city", "Milliways")
			address, addressHash := sdDisclosure(t, "salt-address", "address", map[string]any{"_sd": []any{postalHash, cityHash}})
			storeSDJWT(t, fixture, map[string]any{
				"_sd":           []any{addressHash},
				"nationalities": []any{map[string]any{"...": jpHash}, map[string]any{"...": deHash}, map[string]any{"...": frHash}},
			}, jp, de, fr, address, postal, city)

			query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":` + tc.claims + `}]}`
			_, err := fixture.wallet.PresentCredential(presentationURI(fixture.baseURL, query), fixture.key, nil)
			require.NoError(t, err)
			select {
			case form := <-fixture.posted:
				var tokens map[string][]string
				require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
				require.Len(t, tokens["pid"], 1)
				require.ElementsMatch(t, tc.want, disclosedParts(t, tokens["pid"][0]))
			default:
				t.Fatal("no presentation submitted")
			}
		})
	}
}
