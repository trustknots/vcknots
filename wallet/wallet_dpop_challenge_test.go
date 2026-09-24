package wallet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// RFC9449 section 9: an RS challenge supplies its nonce in that response.
// A VCI c_nonce endpoint need not provide a DPoP nonce or even exist.
func TestCredentialDPoPChallengeUsesResourceResponse(t *testing.T) {
	for _, scenario := range []struct {
		name          string
		header        string
		repeat        bool
		wantRequests  int
		wantError     bool
		nonceEndpoint bool
	}{
		{name: "response nonce and injected TLS client", header: "resource-nonce", wantRequests: 2},
		{name: "missing header has no fallback", nonceEndpoint: true, wantRequests: 1, wantError: true},
		{name: "second challenge is bounded", header: "resource-nonce", repeat: true, wantRequests: 2, wantError: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			key, err := newInMemoryECKeyEntry()
			require.NoError(t, err)
			requests := 0
			firstJTI := ""
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/credential", r.URL.Path)
				require.Equal(t, "DPoP access-token", r.Header.Get("Authorization"))
				requests++
				proof, err := jwt.ParseSigned(r.Header.Get("DPoP"), []jose.SignatureAlgorithm{jose.ES256})
				require.NoError(t, err)
				var claims map[string]any
				require.NoError(t, proof.Claims(key.PublicKey().Key, &claims))
				require.Equal(t, "POST", claims["htm"])
				require.Equal(t, "https://"+r.Host+"/credential", claims["htu"])
				digest := sha256.Sum256([]byte("access-token"))
				require.Equal(t, base64.RawURLEncoding.EncodeToString(digest[:]), claims["ath"])
				if requests == 1 {
					require.NotContains(t, claims, "nonce")
					firstJTI, _ = claims["jti"].(string)
					require.NotEmpty(t, firstJTI)
				} else {
					require.Equal(t, scenario.header, claims["nonce"])
					require.NotEqual(t, firstJTI, claims["jti"])
				}
				if requests == 1 || scenario.repeat {
					if scenario.header != "" {
						w.Header().Set("DPoP-Nonce", scenario.header)
					}
					w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"credentials": []map[string]string{{"credential": "opaque-for-request-test"}}}))
			}))
			defer server.Close()
			dispatcher, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{HTTPClient: server.Client()}))
			require.NoError(t, err)
			w := &Wallet{receiver: dispatcher, dpop: DPoPConfig{Enabled: true, Key: key}}
			endpoint, err := common.ParseURIField(server.URL + "/credential")
			require.NoError(t, err)
			metadata := &receiverTypes.CredentialIssuerMetadata{CredentialIssuer: server.URL, CredentialEndpoint: *endpoint}
			if scenario.nonceEndpoint {
				metadata.NonceEndpoint, err = common.ParseURIField(server.URL + "/nonce-must-not-be-called")
				require.NoError(t, err)
			}
			value, err := w.requestCredential(ReceiveCredentialRequest{Type: receiverTypes.Oid4vci, RequestedFormat: credential.SDJwtVC}, metadata, &receiverTypes.CredentialIssuanceAccessToken{Token: "access-token", TokenType: "dpop"}, "pid", nil)
			if scenario.wantError {
				require.ErrorIs(t, err, receiverTypes.ErrUseDPoPNonce)
				require.Nil(t, value)
			} else {
				require.NoError(t, err)
				require.Equal(t, "opaque-for-request-test", *value)
			}
			require.Equal(t, scenario.wantRequests, requests)
		})
	}
}
