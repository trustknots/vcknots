package wallet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

// Draft 24 transaction_data follows the 1.0 rules: each entry is carried only
// by the presentation of the one input descriptor that owns it (Draft 24
// Section 5.1), in its Key Binding JWT.
func TestWallet_Draft24TransactionDataAttachedOnlyToItsOwner(t *testing.T) {
	fixture := transactionDataFixture(t)
	ids := draft24SelectionCredentialIDs(t, fixture)
	entry := encodedTransactionData(`{"type":"example","credential_ids":["identity"]}`)
	raw, err := json.Marshal([]string{entry})
	require.NoError(t, err)
	uri := "openid4vp://present?" + url.Values{
		"client_id":               {"redirect_uri:" + fixture.baseURL + "/response"},
		"response_uri":            {fixture.baseURL + "/response"},
		"response_type":           {"vp_token"},
		"response_mode":           {"direct_post"},
		"nonce":                   {"presentation-nonce"},
		"presentation_definition": {`{"id":"definition-1","input_descriptors":[{"id":"identity","format":{"vc+sd-jwt":{}}},{"id":"address","format":{"vc+sd-jwt":{}}}]}`},
		"transaction_data":        {string(raw)},
	}.Encode()
	request := parseDraft24(t, fixture.wallet, uri)

	_, err = presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
		{CredentialID: ids["urn:test:identity"], QueryIDs: []string{"identity"}, DisclosedClaims: []string{"given_name"}},
		{CredentialID: ids["urn:test:address"], QueryIDs: []string{"address"}, DisclosedClaims: []string{"street_address"}},
	})
	require.NoError(t, err)
	form := <-fixture.posted
	var tokens []string
	require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &tokens))
	require.Len(t, tokens, 2)
	digest := sha256.Sum256([]byte(entry))
	require.Equal(t, []string{base64.RawURLEncoding.EncodeToString(digest[:])}, transactionDataHashesOf(t, tokens[0]))
	require.Empty(t, transactionDataHashesOf(t, tokens[1]))
}

// A presentation that cannot carry transaction data fails with
// invalid_transaction_data instead of dropping it. The request is built
// directly, as for a definition passed by reference whose descriptors name no
// format.
func TestWallet_Draft24TransactionDataOwnedByANonSDJWTCredentialFails(t *testing.T) {
	controller, key := receiveCredentialForPresentationTest(t)
	entries, _, err := controller.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	flavor, err := entries[0].Entry.SerializationFlavor()
	require.NoError(t, err)
	req := &oid4vp.CredentialPresentationRequest{
		OAuthAuthzRequest: &oid4vp.OAuthAuthzRequest{ResponseType: "vp_token", ClientID: "redirect_uri:https://verifier.example/response", Nonce: "n"},
		TransactionData:   []string{encodedTransactionData(`{"type":"example","credential_ids":["d1"]}`)},
	}
	selections := []CredentialSelection{{CredentialID: entries[0].Entry.Id, QueryIDs: []string{"d1"}}}
	credentials, err := controller.resolveSelections(selections, key)
	require.NoError(t, err)
	_, err = controller.serializeDraft24Presentation(req, Presentation{Key: key, Credentials: selections}, credentials, flavor)
	require.ErrorContains(t, err, "invalid_transaction_data")
}
