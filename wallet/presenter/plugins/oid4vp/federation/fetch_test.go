package federation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEntityConfigurationURL(t *testing.T) {
	for entityID, want := range map[string]string{
		"https://entity.example.test":         "https://entity.example.test/.well-known/openid-federation",
		"https://entity.example.test/":        "https://entity.example.test/.well-known/openid-federation",
		"https://entity.example.test/tenant/": "https://entity.example.test/tenant/.well-known/openid-federation",
		"https://entity.example.test:8443/t":  "https://entity.example.test:8443/t/.well-known/openid-federation",
	} {
		got, err := EntityConfigurationURL(entityID)
		if err != nil || got != want {
			t.Errorf("EntityConfigurationURL(%q) = %q, %v; want %q", entityID, got, err, want)
		}
	}
	for entityID, fragment := range map[string]string{
		"http://entity.example.test":        "entity identifier must use HTTPS",
		"https://entity.example.test?x=1":   "entity identifier must not contain query or fragment",
		"https://entity.example.test#frag":  "must not contain a fragment",
		"https://user@entity.example.test":  "must not contain userinfo",
		"not a url":                         "entity identifier is not a URL",
		"https:///no-host/.well-known/path": "entity identifier is not a URL",
	} {
		_, err := EntityConfigurationURL(entityID)
		requireCode(t, err, ErrStatementFetchFailed, fragment)
	}
}

func TestSubordinateStatementURL(t *testing.T) {
	got, err := SubordinateStatementURL("https://superior.example.test/fetch?existing=1", "https://wallet.example.test/verifier")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://superior.example.test/fetch?existing=1&sub=https%3A%2F%2Fwallet.example.test%2Fverifier"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// An origin-only subject is sent exactly as written, without the
	// trailing slash URL normalization would add.
	got, err = SubordinateStatementURL("https://superior.example.test/fetch", "https://verifier.example.test")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(got)
	if parsed.Query().Get("sub") != "https://verifier.example.test" || got != "https://superior.example.test/fetch?sub=https%3A%2F%2Fverifier.example.test" {
		t.Fatalf("subject was normalized: %q", got)
	}

	_, err = SubordinateStatementURL("http://superior.example.test/fetch", "https://wallet.example.test/verifier")
	requireCode(t, err, ErrStatementFetchFailed, "fetch endpoint must use HTTPS")
	_, err = SubordinateStatementURL("https://superior.example.test/fetch", "http://wallet.example.test/verifier")
	requireCode(t, err, ErrStatementFetchFailed, "subordinate entity identifier must use HTTPS")
	_, err = SubordinateStatementURL("https://superior.example.test/fetch", "https://wallet.example.test/verifier?tenant=1")
	requireCode(t, err, ErrStatementFetchFailed, "subordinate entity identifier must not contain query or fragment")
}

// statementServer answers every request with handler and counts requests.
func statementServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var count atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server, &count
}

func serveBody(contentType, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write([]byte(body))
	}
}

func TestFetchEntityStatement(t *testing.T) {
	oversized := strings.Repeat("x", int(DefaultMaxStatementBytes)+1)
	cases := []struct {
		name     string
		handler  http.HandlerFunc
		want     string
		fragment string
	}{
		{name: "entity statement", handler: serveBody(entityStatementMediaType, " header.payload.signature\n"), want: "header.payload.signature"},
		{name: "media type with parameters", handler: serveBody("Application/Entity-Statement+JWT; charset=utf-8", "a.b.c"), want: "a.b.c"},
		{
			name: "redirect is not followed",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://other.example.test/entity.jwt", http.StatusFound)
			},
			fragment: "redirects are not allowed",
		},
		{
			name: "error status",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", entityStatementMediaType)
				w.WriteHeader(http.StatusNotFound)
			},
			fragment: "returned HTTP 404",
		},
		{name: "JSON response", handler: serveBody("application/json", `{"jwt":"a.b.c"}`), fragment: "response must use application/entity-statement+jwt"},
		{name: "media type as a substring", handler: serveBody("application/entity-statement+jwt-bad", "a.b.c"), fragment: "response must use application/entity-statement+jwt"},
		{name: "empty body", handler: serveBody(entityStatementMediaType, ""), fragment: "response is empty"},
		{name: "whitespace body", handler: serveBody(entityStatementMediaType, "  \n"), fragment: "response is empty"},
		{name: "oversized body", handler: serveBody(entityStatementMediaType, oversized), fragment: "response is too large"},
		{
			name: "oversized declared length",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", entityStatementMediaType)
				w.Header().Set("Content-Length", strconv.FormatInt(DefaultMaxStatementBytes+1, 10))
				w.WriteHeader(http.StatusOK)
			},
			fragment: "response is too large",
		},
		{
			name: "oversized streamed body without declared length",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", entityStatementMediaType)
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				_, _ = w.Write([]byte(oversized))
			},
			fragment: "response is too large",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := statementServer(t, tc.handler)
			resolver := &Resolver{HTTPClient: server.Client()}
			got, err := resolver.fetchEntityStatement(context.Background(), server.URL+"/.well-known/openid-federation")
			if tc.fragment != "" {
				requireCode(t, err, ErrStatementFetchFailed, tc.fragment)
				if strings.Contains(err.Error(), "xxxx") || strings.Contains(err.Error(), "a.b.c") {
					t.Fatalf("error leaks the response body: %v", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestFetchEntityStatementSendsTheMediaTypeAndDoesNotMutateTheClient(t *testing.T) {
	var accept string
	server, _ := statementServer(t, func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		serveBody(entityStatementMediaType, "a.b.c")(w, r)
	})
	client := server.Client()
	resolver := &Resolver{HTTPClient: client}
	if _, err := resolver.fetchEntityStatement(context.Background(), server.URL+"/x"); err != nil {
		t.Fatal(err)
	}
	if accept != entityStatementMediaType {
		t.Fatalf("Accept = %q", accept)
	}
	if client.CheckRedirect != nil {
		t.Fatal("the caller's client must not be mutated")
	}
}

func TestFetchEntityStatementRefusesNonHTTPSBeforeFetching(t *testing.T) {
	resolver := &Resolver{HTTPClient: &http.Client{Transport: failingTransport{t}}}
	_, err := resolver.fetchEntityStatement(context.Background(), "http://entity.example.test/.well-known/openid-federation")
	requireCode(t, err, ErrStatementFetchFailed, "entity statement URL must use HTTPS")
}

func TestFetchEntityStatementAppliesThePublicNetworkPolicy(t *testing.T) {
	server, count := statementServer(t, serveBody(entityStatementMediaType, "a.b.c"))

	refuseAll := &Resolver{HTTPClient: server.Client(), RequirePublicNetworkHost: true}
	_, err := refuseAll.fetchEntityStatement(context.Background(), server.URL+"/x")
	requireCode(t, err, ErrStatementFetchFailed, "must use a public network host")

	var asked []string
	private := &Resolver{HTTPClient: server.Client(), RequirePublicNetworkHost: true, IsPublicNetworkHost: func(host string) bool {
		asked = append(asked, host)
		return false
	}}
	_, err = private.fetchEntityStatement(context.Background(), server.URL+"/x")
	requireCode(t, err, ErrStatementFetchFailed, "must use a public network host")
	if count.Load() != 0 {
		t.Fatalf("a refused host was fetched %d times", count.Load())
	}
	if len(asked) != 1 || asked[0] != "127.0.0.1" {
		t.Fatalf("the policy was asked about %v, want the bare host", asked)
	}

	public := &Resolver{HTTPClient: server.Client(), RequirePublicNetworkHost: true, IsPublicNetworkHost: func(string) bool { return true }}
	if got, err := public.fetchEntityStatement(context.Background(), server.URL+"/x"); err != nil || got != "a.b.c" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// failingTransport fails the test when any request is sent.
type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Fatal("no request may be sent")
	return nil, nil
}
