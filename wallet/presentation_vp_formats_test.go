package wallet

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

// The Verifier's vp_formats_supported limits the algorithms of the
// SD-JWT VC it accepts (OpenID4VP 1.0 Appendix B.3.4); the fixture issuer
// signs with ES256, so a Verifier listing only ES384 gets nothing rather than
// a presentation it said it cannot verify.
func TestWallet_PresentationHonoursTheVerifiersAlgorithms(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	uri := func(algorithms string) string {
		return "openid4vp://present?" + url.Values{
			"client_id": {"redirect_uri:" + fixture.baseURL + "/response"}, "response_uri": {fixture.baseURL + "/response"},
			"response_type": {"vp_token"}, "response_mode": {"direct_post"}, "nonce": {"n"},
			"dcql_query":      {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`},
			"client_metadata": {`{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":` + algorithms + `}}}`},
		}.Encode()
	}

	_, err := presentWithWalletChoice(t, fixture.wallet, uri(`["ES384"]`), fixture.key, nil)
	require.ErrorIs(t, err, oid4vp.ErrVPFormatAlgUnsupported)
	select {
	case <-fixture.posted:
		t.Fatal("a presentation the Verifier cannot verify was sent")
	default:
	}

	_, err = presentWithWalletChoice(t, fixture.wallet, uri(`["ES256","ES384"]`), fixture.key, nil)
	require.NoError(t, err)
	<-fixture.posted
}

// Draft 24 §5.4: the format member of an input descriptor restricts the
// SD-JWT VC algorithms like vp_formats does, unless vp_formats omits that
// format, in which case the Wallet ignores it.
func TestWallet_Draft24DescriptorFormatAlgorithms(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	id := draft24SelectionCredentialIDs(t, fixture)["urn:test:identity"]
	uri := func(descriptorFormat, clientMetadata string) string {
		values := url.Values{
			"client_id": {"redirect_uri:" + fixture.baseURL + "/response"}, "response_uri": {fixture.baseURL + "/response"},
			"response_type": {"vp_token"}, "response_mode": {"direct_post"}, "nonce": {"n"},
			"presentation_definition": {`{"id":"pd","input_descriptors":[{"id":"identity","format":` + descriptorFormat + `}]}`},
		}
		if clientMetadata != "" {
			values.Set("client_metadata", clientMetadata)
		}
		return "openid4vp://present?" + values.Encode()
	}
	present := func(uri string) error {
		request := parseDraft24(t, fixture.wallet, uri)
		_, err := presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{
			{CredentialID: id, QueryIDs: []string{"identity"}, DisclosedClaims: []string{"given_name"}},
		})
		return err
	}

	require.ErrorIs(t, present(uri(`{"vc+sd-jwt":{"sd-jwt_alg_values":["ES384"]}}`, "")), oid4vp.ErrVPFormatAlgUnsupported)
	require.NoError(t, present(uri(`{"vc+sd-jwt":{"sd-jwt_alg_values":["ES256"]}}`, "")))
	<-fixture.posted
	// vp_formats names only jwt_vc_json, so the descriptor's vc+sd-jwt entry
	// is ignored.
	require.NoError(t, present(uri(`{"vc+sd-jwt":{"sd-jwt_alg_values":["ES384"]}}`, `{"vp_formats":{"jwt_vc_json":{"alg":["ES256"]}}}`)))
	<-fixture.posted
}
