package wallet

import (
	"crypto/ecdsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

func dcapiWalletRequestData(t *testing.T, responseMode string, recipient *ecdsa.PrivateKey, encValues []string) json.RawMessage {
	t.Helper()
	metadata := map[string]any{}
	if recipient != nil {
		metadata["jwks"] = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &recipient.PublicKey, KeyID: "enc-key", Use: "enc", Algorithm: "ECDH-ES",
		}}}
		metadata["encrypted_response_enc_values_supported"] = encValues
	}
	raw, err := json.Marshal(map[string]any{
		"response_type": "vp_token", "response_mode": responseMode, "nonce": "dcapi-nonce",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt",
			"meta":    map[string]any{"vct_values": []string{"urn:test:identity"}},
			"claims":  []any{map[string]any{"path": []any{"given_name"}}},
			"purpose": "identity",
		}}},
		"client_metadata": metadata,
	})
	require.NoError(t, err)
	return raw
}

func invokeDCAPI(t *testing.T, fixture sdjwtPresentationFixture, responseMode string, recipient *ecdsa.PrivateKey, encValues []string) *presenterTypes.DCAPIResponse {
	t.Helper()
	invocation := presenterTypes.DCAPIInvocation{
		Request: presenterTypes.DCAPIRequest{
			Protocol: oid4vp.DCAPIProtocolUnsigned,
			Data:     dcapiWalletRequestData(t, responseMode, recipient, encValues),
		},
		Origin: "https://verifier.example",
	}
	request, err := fixture.wallet.ParseDCAPIRequest(t.Context(), invocation)
	require.NoError(t, err)
	require.Nil(t, request.ResponseEndpoint())
	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	result, err := fixture.wallet.SubmitPresentation(t.Context(), request, Presentation{Key: fixture.key, Credentials: selections})
	require.NoError(t, err)
	require.Empty(t, result.RedirectURI)
	require.NotNil(t, result.DCAPIResponse)
	return result.DCAPIResponse
}

func kbJWTAudience(t *testing.T, wire string, holder *jose.JSONWebKey) (string, string) {
	t.Helper()
	separator := strings.LastIndex(wire, "~")
	require.GreaterOrEqual(t, separator, 0)
	signed, err := jwt.ParseSigned(wire[separator+1:], []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, signed.Claims(holder.Key, &claims))
	audience, _ := claims["aud"].(string)
	nonce, _ := claims["nonce"].(string)
	return audience, nonce
}

func TestWalletSubmitPresentationToDCAPIPlaintext(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, map[string]any{"nationality": "JP"}, map[string]string{"given_name": "Taro"})

	response := invokeDCAPI(t, fixture, "dc_api", nil, nil)
	require.Equal(t, oid4vp.DCAPIProtocolUnsigned, response.Protocol)
	vpToken, ok := response.Data["vp_token"].(map[string][]string)
	require.True(t, ok)
	require.Len(t, vpToken["pid"], 1)
	audience, nonce := kbJWTAudience(t, vpToken["pid"][0], &holder)
	// Appendix A.4: the Key Binding JWT audience is origin:<origin>.
	require.Equal(t, "origin:https://verifier.example", audience)
	require.Equal(t, "dcapi-nonce", nonce)
}

func TestWalletSubmitPresentationToDCAPIEncrypted(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, map[string]any{"nationality": "JP"}, map[string]string{"given_name": "Taro"})
	recipient := testutil.NewP256Key(t)

	response := invokeDCAPI(t, fixture, "dc_api.jwt", recipient, []string{"A128GCM"})
	require.Equal(t, oid4vp.DCAPIProtocolUnsigned, response.Protocol)
	token, ok := response.Data["response"].(string)
	require.True(t, ok)
	jwe, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM})
	require.NoError(t, err)
	plaintext, err := jwe.Decrypt(recipient)
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(plaintext, &payload))
	vpToken, ok := payload["vp_token"].(map[string]any)
	require.True(t, ok)
	tokens, ok := vpToken["pid"].([]any)
	require.True(t, ok)
	require.Len(t, tokens, 1)
	wire, ok := tokens[0].(string)
	require.True(t, ok)
	audience, nonce := kbJWTAudience(t, wire, &holder)
	require.Equal(t, "origin:https://verifier.example", audience)
	require.Equal(t, "dcapi-nonce", nonce)
}
