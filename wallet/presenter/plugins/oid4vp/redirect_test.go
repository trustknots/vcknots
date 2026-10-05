package oid4vp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// newPlainHTTPSink is a plain-http server that counts every request it gets.
func newPlainHTTPSink(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server, calls
}

// newRedirectingTLSServer answers every request with a 307 to target.
func newRedirectingTLSServer(t *testing.T, target string) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(server.Close)
	return server
}

// The https requirement on the Response Endpoint cannot be bypassed by a
// redirect: the VP Token must not reach a plain-http endpoint.
func TestPresentDCQLDoesNotFollowRedirects(t *testing.T) {
	sink, calls := newPlainHTTPSink(t)
	origin := newRedirectingTLSServer(t, sink.URL+"/steal")
	endpoint, err := url.Parse(origin.URL + "/response")
	if err != nil {
		t.Fatal(err)
	}
	p := &Oid4vpPresenter{HTTPClient: origin.Client()}
	_, err = sendDCQLForTest(p, *endpoint, map[string][]string{"pid": {"SECRET-VP"}},
		&types.PresentationRequest{State: "s", ResponseMode: string(OAuthAuthzReqResponseModeDirectPost)})
	var verifierErr *VerifierResponseError
	if !errors.As(err, &verifierErr) || verifierErr.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("want the 307 reported as a VerifierResponseError, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("the redirect target received the presentation")
	}
}

// A request_uri fetch does not follow a redirect either, so the https check
// on request_uri covers the whole fetch.
func TestRequestURIFetchDoesNotFollowRedirects(t *testing.T) {
	sink, calls := newPlainHTTPSink(t)
	origin := newRedirectingTLSServer(t, sink.URL+"/request-object")
	f := newRequestObjectFixture(t)
	p := f.presenter()
	p.HTTPClient = origin.Client()
	for _, method := range []string{"get", "post"} {
		uri := "openid4vp://authorize?" + url.Values{
			"client_id":          {f.clientID()},
			"request_uri":        {origin.URL + "/request-object"},
			"request_uri_method": {method},
		}.Encode()
		if _, err := p.ParsePresentationRequest(uri); err == nil {
			t.Fatalf("%s: a redirected request_uri fetch must fail", method)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("the redirect target was fetched")
	}
}
