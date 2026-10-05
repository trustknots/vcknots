package oid4vp

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// OpenID4VP 1.0 §5.1: "Other metadata parameters MUST be ignored". A member
// the Wallet does not act on cannot refuse the request by its type; a member
// it acts on still must be well formed.
func TestFinalClientMetadataIgnoresUnusedMembersOfAnyType(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	metadata := claims["client_metadata"].(map[string]any)
	metadata["client_name"] = map[string]any{"en": "Verifier"}
	metadata["logo_uri"] = 42
	metadata["tos_uri"] = "https://verifier.example/tos"
	request, err := f.parse(t, claims)
	require.NoError(t, err)
	require.Empty(t, request.ClientMetadata.ClientName, "a member of the wrong type is dropped")
	require.Equal(t, "https://verifier.example/tos", request.ClientMetadata.ToSURI, "a well-typed member is kept")
	require.NotEmpty(t, request.ClientMetadata.Jwks.Keys)

	claims = f.claims()
	claims["client_metadata"].(map[string]any)["jwks"] = map[string]any{"keys": "ignored"}
	_, err = f.parse(t, claims)
	require.Error(t, err, "jwks is acted on and must be a JWK Set")
}

// §5.9.3: with openid_federation "The client_metadata parameter, if present
// in the Authorization Request, MUST be ignored", including its type.
func TestFederationIgnoresTheRequestClientMetadata(t *testing.T) {
	f := newFederationRequestFixture(t)
	claims := f.claims()
	claims["client_metadata"] = map[string]any{"jwks": map[string]any{"keys": "ignored"}, "client_name": 7}
	request, err := f.parse(t, f.requestObject(t, claims, f.requestKey, federationRequestKid, nil), f.options(), f.server.Client())
	require.NoError(t, err)
	require.Equal(t, "Federated verifier", request.ClientMetadata.ClientName)
}

// A 1.0 request is judged by vp_formats_supported; the Draft 24
// vp_formats member is never read there, and the other way round.
func TestEachVersionReadsItsOwnFormatsMember(t *testing.T) {
	raw := []byte(`{"vp_formats":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"]}},"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES384"]}}}`)
	final, err := decodeVerifierMetadata(raw, finalMetadata)
	require.NoError(t, err)
	require.Nil(t, final.VPFormats)
	require.JSONEq(t, `{"sd-jwt_alg_values":["ES384"]}`, string(final.VPFormatsSupported["dc+sd-jwt"]))
	draft, err := decodeVerifierMetadata(raw, draft24Metadata)
	require.NoError(t, err)
	require.Nil(t, draft.VPFormatsSupported)
	require.JSONEq(t, `{"sd-jwt_alg_values":["ES256"]}`, string(draft.VPFormats["dc+sd-jwt"]))

	_, err = decodeVerifierMetadata([]byte(`{"vp_formats_supported":"dc+sd-jwt"}`), finalMetadata)
	require.Error(t, err, "vp_formats_supported is acted on")
	_, err = decodeVerifierMetadata([]byte(`{"vp_formats_supported":"dc+sd-jwt"}`), draft24Metadata)
	require.NoError(t, err, "a Draft 24 request never reads vp_formats_supported")
}

// OpenID4VP 1.0 Appendix B.3.4 and Draft 24 Appendix B.4.2: the alg of the
// Issuer-signed JWT and of the KB-JWT must be one the Verifier lists. Absent
// lists accept every algorithm.
func TestCheckSDJWTPresentationAlgorithms(t *testing.T) {
	jws := func(alg string) string {
		header, _ := json.Marshal(map[string]string{"alg": alg})
		return base64.RawURLEncoding.EncodeToString(header) + ".e30.sig"
	}
	presentation := jws("ES384") + "~disclosure~" + jws("ES256")
	metadata := func(formats string) *VerifierMetadata {
		decoded, err := decodeVerifierMetadata([]byte(`{"vp_formats_supported":`+formats+`}`), finalMetadata)
		require.NoError(t, err)
		return decoded
	}
	require.NoError(t, (*VerifierMetadata)(nil).CheckSDJWTPresentationAlgorithms(presentation))
	require.NoError(t, metadata(`{"dc+sd-jwt":{}}`).CheckSDJWTPresentationAlgorithms(presentation))
	require.NoError(t, metadata(`{"jwt_vc_json":{"alg_values":["ES256"]}}`).CheckSDJWTPresentationAlgorithms(presentation))
	require.NoError(t, metadata(`{"dc+sd-jwt":{"sd-jwt_alg_values":["ES384"],"kb-jwt_alg_values":["ES256"]}}`).CheckSDJWTPresentationAlgorithms(presentation))
	require.ErrorIs(t, metadata(`{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"]}}`).CheckSDJWTPresentationAlgorithms(presentation), ErrVPFormatAlgUnsupported)
	require.ErrorIs(t, metadata(`{"dc+sd-jwt":{"kb-jwt_alg_values":["EdDSA"]}}`).CheckSDJWTPresentationAlgorithms(presentation), ErrVPFormatAlgUnsupported)
	// Without a KB-JWT only the issuer signature is judged.
	require.NoError(t, metadata(`{"dc+sd-jwt":{"kb-jwt_alg_values":["EdDSA"]}}`).CheckSDJWTPresentationAlgorithms(jws("ES384")+"~disclosure~"))
}
