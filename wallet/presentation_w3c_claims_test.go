package wallet

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

// OID4VP 1.0 Appendix B.1: for W3C Verifiable Credentials a claims path
// pointer starts at the root of the Verifiable Credential, so a jwt_vc_json
// subject claim is addressed as ["credentialSubject", name].
func TestWallet_DCQLJWTVCClaimsPathsStartAtTheCredential(t *testing.T) {
	for _, tc := range []struct {
		name, claims  string
		wantPresented bool
	}{
		{name: "subject claim under credentialSubject", claims: `[{"path":["credentialSubject","name"]}]`, wantPresented: true},
		{name: "subject claim value", claims: `[{"path":["credentialSubject","name"],"values":["John Doe"]}]`, wantPresented: true},
		{name: "credential member", claims: `[{"path":["issuer"]}]`, wantPresented: true},
		{name: "subject claim value mismatch", claims: `[{"path":["credentialSubject","name"],"values":["Jane Doe"]}]`},
		{name: "subject claim without its parent", claims: `[{"path":["name"]}]`},
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
			query := `{"credentials":[{"id":"vc","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]},"claims":` + tc.claims + `}]}`
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
