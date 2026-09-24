package oid4vp

import (
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// Draft 24 transaction_data follows the rules of the 1.0 path (Draft 24
// Sections 5.1 and 6.4): a supported type, credential_ids naming requested
// credentials, and a referenced credential that can carry the hashes, which
// only an SD-JWT VC Key Binding JWT does (Appendix A.4.5).
func TestDraft24TransactionDataValidation(t *testing.T) {
	encode := func(raw string) string { return base64.RawURLEncoding.EncodeToString([]byte(raw)) }
	const sdJWTDefinition = `{"id":"pd","input_descriptors":[{"id":"pid","format":{"vc+sd-jwt":{}}}]}`
	parse := func(t *testing.T, query map[string]string, entry string, supported []string) (*CredentialPresentationRequest, error) {
		t.Helper()
		params := url.Values{
			"client_id":        {"redirect_uri:https://verifier.example/response"},
			"response_type":    {"vp_token"},
			"response_mode":    {"fragment"},
			"nonce":            {"nonce"},
			"transaction_data": {`["` + entry + `"]`},
		}
		for name, value := range query {
			params.Set(name, value)
		}
		return parseDraft24ForTest(&Oid4vpPresenter{SupportedTransactionDataTypes: supported}, "openid4vp://present?"+params.Encode())
	}
	pe := map[string]string{"presentation_definition": sdJWTDefinition}

	req, err := parse(t, pe, encode(`{"type":"example","credential_ids":["pid"],"transaction_data_hashes_alg":["sha-384"]}`), []string{"example"})
	require.NoError(t, err)
	require.Len(t, req.TransactionData, 1)
	require.Equal(t, "sha-384", req.TransactionDataHashesAlg)

	req, err = parse(t, map[string]string{"dcql_query": `{"credentials":[{"id":"pid","format":"vc+sd-jwt"}]}`}, encode(`{"type":"example","credential_ids":["pid"]}`), []string{"example"})
	require.NoError(t, err)
	require.Equal(t, "sha-256", req.TransactionDataHashesAlg)

	// A definition passed by reference is resolved after admission, so its
	// descriptors are checked when the presentation is built.
	_, err = parse(t, map[string]string{"presentation_definition_uri": "https://verifier.example/pd"}, encode(`{"type":"example","credential_ids":["pid"]}`), []string{"example"})
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		query     map[string]string
		entry     string
		supported []string
	}{
		{"no supported type", pe, encode(`{"type":"example","credential_ids":["pid"]}`), nil},
		{"unknown type", pe, encode(`{"type":"example","credential_ids":["pid"]}`), []string{"other"}},
		{"unknown input descriptor", pe, encode(`{"type":"example","credential_ids":["nope"]}`), []string{"example"}},
		{"empty credential_ids", pe, encode(`{"type":"example","credential_ids":[]}`), []string{"example"}},
		{"malformed base64", pe, "not base64!!", []string{"example"}},
		{"no supported hashes alg", pe, encode(`{"type":"example","credential_ids":["pid"],"transaction_data_hashes_alg":["md5"]}`), []string{"example"}},
		{"jwt_vc_json input descriptor", map[string]string{"presentation_definition": `{"id":"pd","input_descriptors":[{"id":"pid","format":{"jwt_vc_json":{}}}]}`}, encode(`{"type":"example","credential_ids":["pid"]}`), []string{"example"}},
		{"jwt_vc_json definition", map[string]string{"presentation_definition": `{"id":"pd","format":{"jwt_vc_json":{}},"input_descriptors":[{"id":"pid"}]}`}, encode(`{"type":"example","credential_ids":["pid"]}`), []string{"example"}},
		{"jwt_vc_json credential query", map[string]string{"dcql_query": `{"credentials":[{"id":"pid","format":"jwt_vc_json"}]}`}, encode(`{"type":"example","credential_ids":["pid"]}`), []string{"example"}},
		{"unknown credential query", map[string]string{"dcql_query": `{"credentials":[{"id":"pid","format":"vc+sd-jwt"}]}`}, encode(`{"type":"example","credential_ids":["other"]}`), []string{"example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, tc.query, tc.entry, tc.supported)
			assertAuthzErrorCode(t, err, InvalidTransactionDataError)
		})
	}
}
