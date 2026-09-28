package oid4vp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustknots/vcknots/wallet/experimental"
)

// OpenID4VP 1.0 §8.2 and Draft 24 §8.2: "If the redirect_uri Authorization
// Request parameter is present when the Response Mode is direct_post, the
// Wallet MUST return an invalid_request Authorization Response error." The
// redirect_uri Client Identifier Prefix lets the request omit response_uri
// (§5.9.3), so a request carrying only redirect_uri must still be refused.
// §8.3.1 applies the rule to direct_post.jwt.
func TestDirectPostWithRedirectURIIsInvalidRequest(t *testing.T) {
	posted := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		posted <- r.PostForm
	}))
	defer server.Close()
	endpoint := server.URL + "/response"

	for _, mode := range []string{"direct_post", "direct_post.jwt"} {
		for _, draft24 := range []bool{false, true} {
			// The rule holds whatever the redirect_uri value, also one other
			// than the Client Identifier's.
			for _, redirect := range []string{endpoint, "https://elsewhere.example/cb"} {
				name := mode + "/final/" + redirect
				if draft24 {
					name = mode + "/draft24/" + redirect
				}
				t.Run(name, func(t *testing.T) {
					params := url.Values{
						"client_id":     {"redirect_uri:" + endpoint},
						"redirect_uri":  {redirect},
						"response_type": {"vp_token"},
						"response_mode": {mode},
						"nonce":         {"n"},
						"state":         {"s"},
					}
					if draft24 {
						params.Set("presentation_definition", `{"id":"pd","input_descriptors":[{"id":"pid"}]}`)
					} else {
						params.Set("dcql_query", `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]}}]}`)
					}
					p := withExperimental(&Oid4vpPresenter{SendParseErrorResponses: true}, experimental.Presenter{Transport: experimental.Transport{AllowHTTP: true}})
					uri := "openid4vp://present?" + params.Encode()
					var err error
					if draft24 {
						_, err = p.ParseDraft24Request(context.Background(), uri)
					} else {
						_, err = p.ParseRequest(context.Background(), uri)
					}
					require.ErrorIs(t, err, ErrRedirectURIWithDirectPost)
					assertAuthzErrorCode(t, err, InvalidRequestError)
					// The error goes to the Response URI the Client Identifier
					// binds, never to a URI the request chose; with no Verifier key
					// to encrypt to, a direct_post.jwt error goes in the clear
					// (§8.3.1).
					form := <-posted
					require.Equal(t, "invalid_request", form.Get("error"))
					require.Equal(t, "s", form.Get("state"))
				})
			}
		}
	}
}
