package oid4vp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/observetest"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
)

func observePresenterClient(p *Oid4vpPresenter, recorder *observetest.Recorder) {
	client := *p.HTTPClient
	client.Transport = observe.Transport(client.Transport, recorder)
	p.HTTPClient = &client
}

func requireSingleExchange(t *testing.T, recorder *observetest.Recorder) observe.Exchange {
	t.Helper()
	exchanges := recorder.Exchanges()
	require.Len(t, exchanges, 1)
	return exchanges[0]
}

// TestObserveLabelsRequestObjectFetch: the request_uri fetch is labelled even
// though its URL appears nowhere but inside the Authorization Request.
func TestObserveLabelsRequestObjectFetch(t *testing.T) {
	f := newRequestObjectFixture(t)
	recorder := &observetest.Recorder{}
	f.mu.Lock()
	f.requestObject = []byte(f.signWithRoot(t, f.claims(), false))
	f.mu.Unlock()
	p := f.presenterWith(requestFixtureOptions{})
	observePresenterClient(p, recorder)

	uri := "openid4vp://authorize?" + url.Values{
		"client_id":   {f.clientID()},
		"request_uri": {f.server.URL + "/request-object"},
	}.Encode()
	_, err := p.ParsePresentationRequest(uri)
	require.NoError(t, err)

	exchanges := recorder.Exchanges()
	require.NotEmpty(t, exchanges)
	exchange := exchanges[0]
	require.Equal(t, observe.EndpointRequestObject, exchange.Endpoint)
	require.Equal(t, http.MethodGet, exchange.Request.Method)
	require.Equal(t, "/request-object", exchange.Request.URL.Path)
	require.Equal(t, http.StatusOK, exchange.Response.StatusCode)
	// The X.509 chain walk that authenticates the Request Object downloads its
	// CRL through the same client; a CRL has no protocol role of its own.
	for _, later := range exchanges[1:] {
		require.Equal(t, observe.EndpointOther, later.Endpoint, later.Request.URL.Path)
	}
}

// TestObserveLabelsAuthorizationResponse: the Response Endpoint POST is
// labelled, and whether it carried a JWE, which its wire shape cannot show, is
// reported on the SubmitResult.
func TestObserveLabelsAuthorizationResponse(t *testing.T) {
	recipient := testutil.NewP256Key(t)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	metadata, err := json.Marshal(map[string]any{
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &recipient.PublicKey, KeyID: "enc", Use: "enc", Algorithm: "ECDH-ES"}}},
		"encrypted_response_enc_values_supported": []string{"A128GCM"},
	})
	require.NoError(t, err)

	for name, testCase := range map[string]struct {
		responseMode string
		want         bool
	}{
		"plaintext direct_post": {responseMode: "direct_post", want: false},
		"direct_post.jwt":       {responseMode: "direct_post.jwt", want: true},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := &observetest.Recorder{}
			p := &Oid4vpPresenter{AllowHTTP: true, HTTPClient: server.Client()}
			observePresenterClient(p, recorder)
			request, err := p.ParseRequest(context.Background(), "openid4vp://authorize?"+url.Values{
				"client_id":       {"redirect_uri:" + server.URL + "/response"},
				"response_type":   {"vp_token"},
				"response_mode":   {testCase.responseMode},
				"nonce":           {"n"},
				"state":           {"state-1"},
				"client_metadata": {string(metadata)},
				"dcql_query":      {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}`},
			}.Encode())
			require.NoError(t, err)

			result, err := p.SubmitDCQLResponse(context.Background(), request, map[string][]string{"pid": {"presentation"}})
			require.NoError(t, err)
			require.Equal(t, testCase.want, result.Encrypted)

			exchange := requireSingleExchange(t, recorder)
			require.Equal(t, observe.EndpointResponse, exchange.Endpoint)
			require.Equal(t, http.MethodPost, exchange.Request.Method)
		})
	}

	t.Run("error response", func(t *testing.T) {
		recorder := &observetest.Recorder{}
		p, endpoint, _, _ := dcqlTransportEndpoint(t)
		observePresenterClient(p, recorder)

		request := admitDirectPost(t, p, endpoint.String(), "state-1")
		result, err := p.SubmitErrorResponse(context.Background(), request, "access_denied", "")
		require.NoError(t, err)
		require.False(t, result.Encrypted)
		require.Equal(t, observe.EndpointResponse, requireSingleExchange(t, recorder).Endpoint)
	})
}
