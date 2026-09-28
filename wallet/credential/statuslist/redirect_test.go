package statuslist

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// redirectingHarness serves a Status List Token at /token and answers the
// status path with the redirects route gives it.
func redirectingHarness(t *testing.T, claims func(h *harness) map[string]any, route func(h *harness, w http.ResponseWriter, r *http.Request) bool) (*harness, *atomic.Int32) {
	t.Helper()
	h := newHarness(t)
	var tokenHits atomic.Int32
	h.respond = func(w http.ResponseWriter, r *http.Request) {
		if route(h, w, r) {
			return
		}
		if r.URL.Path == "/token" {
			tokenHits.Add(1)
			w.Header().Set("Content-Type", statusListTokenMediaType)
			_, _ = w.Write([]byte(signES256(t, h.key, defaultHeader(), claims(h))))
			return
		}
		http.NotFound(w, r)
	}
	return h, &tokenHits
}

func claimsForURI(h *harness) map[string]any { return defaultClaims(h.uri) }

// TestCheckReferenceFollowsRedirects covers draft-ietf-oauth-status-list
// Section 8.2: "A response MAY also choose to redirect the client to another
// URI using an HTTP status code in the 3xx range, which clients SHOULD
// follow." The token served at the end is still bound to the `uri` the
// credential named, through its `sub`.
func TestCheckReferenceFollowsRedirects(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			h, tokenHits := redirectingHarness(t, claimsForURI, func(_ *harness, w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != statusPath {
					return false
				}
				if r.Header.Get("Accept") != statusListTokenMediaType {
					t.Errorf("Accept = %q", r.Header.Get("Accept"))
				}
				w.Header().Set("Location", "/token#ignored")
				w.WriteHeader(code)
				return true
			})
			status, err := h.checker().CheckReference(context.Background(), testIssuer, h.reference(1))
			if err != nil {
				t.Fatal(err)
			}
			if status.URI != h.uri || status.TokenSubject != h.uri || tokenHits.Load() != 1 {
				t.Fatalf("status = %+v, token requested %d times", status, tokenHits.Load())
			}
			if last := h.lastReq.Load().(*http.Request); last.Header.Get("Accept") != statusListTokenMediaType {
				t.Fatalf("redirected request Accept = %q", last.Header.Get("Accept"))
			}
		})
	}
}

// TestCheckReferenceBoundsRedirects covers Section 11.4, which asks a client
// that follows redirects to guard against loops (RFC 9110 Section 15.4).
func TestCheckReferenceBoundsRedirects(t *testing.T) {
	chain := func(hops int) func(*harness, http.ResponseWriter, *http.Request) bool {
		return func(_ *harness, w http.ResponseWriter, r *http.Request) bool {
			var hop int
			switch {
			case r.URL.Path == statusPath:
				hop = 0
			case strings.HasPrefix(r.URL.Path, "/hop/"):
				_, _ = fmt.Sscanf(r.URL.Path, "/hop/%d", &hop)
			default:
				return false
			}
			next := "/token"
			if hop+1 < hops {
				next = fmt.Sprintf("/hop/%d", hop+1)
			}
			http.Redirect(w, r, next, http.StatusFound)
			return true
		}
	}
	t.Run("five redirects are followed", func(t *testing.T) {
		h, _ := redirectingHarness(t, claimsForURI, chain(maxStatusListRedirects))
		if _, err := h.checker().CheckReference(context.Background(), testIssuer, h.reference(0)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a sixth redirect is refused", func(t *testing.T) {
		h, tokenHits := redirectingHarness(t, claimsForURI, chain(maxStatusListRedirects+1))
		_, err := h.checker().CheckReference(context.Background(), testIssuer, h.reference(0))
		assertSentinel(t, err, ErrStatusListFetchFailed)
		if !strings.Contains(err.Error(), "redirected more than 5 times") || tokenHits.Load() != 0 {
			t.Fatalf("err = %v, token requested %d times", err, tokenHits.Load())
		}
	})
	t.Run("a redirect loop is refused", func(t *testing.T) {
		h, _ := redirectingHarness(t, claimsForURI, func(_ *harness, w http.ResponseWriter, r *http.Request) bool {
			http.Redirect(w, r, statusPath, http.StatusFound)
			return true
		})
		_, err := h.checker().CheckReference(context.Background(), testIssuer, h.reference(0))
		assertSentinel(t, err, ErrStatusListFetchFailed)
		if got := h.requests.Load(); got != maxStatusListRedirects+1 {
			t.Fatalf("endpoint requested %d times, want %d", got, maxStatusListRedirects+1)
		}
	})
}

func TestCheckReferenceRefusesUnfollowableRedirects(t *testing.T) {
	for _, test := range []struct {
		name     string
		code     int
		location func(h *harness) string
		message  string
	}{
		{name: "to http", code: http.StatusFound, location: func(h *harness) string {
			return strings.Replace(h.server.URL, "https://", "http://", 1) + "/token"
		}, message: "must use the https scheme"},
		{name: "to another scheme", code: http.StatusFound, location: func(*harness) string { return "ftp://issuer.example.test/token" }, message: "must use the https scheme"},
		{name: "with user information", code: http.StatusFound, location: func(h *harness) string {
			return strings.Replace(h.server.URL, "https://", "https://user:pass@", 1) + "/token"
		}, message: "user information"},
		{name: "without a location", code: http.StatusFound, location: func(*harness) string { return "" }, message: "without a Location"},
		{name: "multiple choices", code: http.StatusMultipleChoices, location: func(*harness) string { return "/token" }, message: "redirect status 300"},
		{name: "not modified", code: http.StatusNotModified, location: func(*harness) string { return "/token" }, message: "redirect status 304"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, tokenHits := redirectingHarness(t, claimsForURI, func(h *harness, w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != statusPath {
					return false
				}
				if location := test.location(h); location != "" {
					w.Header().Set("Location", location)
				}
				w.WriteHeader(test.code)
				return true
			})
			_, err := h.checker().CheckReference(context.Background(), testIssuer, h.reference(0))
			assertSentinel(t, err, ErrStatusListFetchFailed)
			if !strings.Contains(err.Error(), test.message) || tokenHits.Load() != 0 || h.hookCalls.Load() != 0 {
				t.Fatalf("err = %v, token requested %d times, hook ran %d times", err, tokenHits.Load(), h.hookCalls.Load())
			}
		})
	}
}

// TestCheckReferenceBindsARedirectedTokenToTheReferencedURI shows why
// following a redirect is safe: a token whose `sub` names the redirect target
// rather than the `uri` the credential carries is not the token asked for.
func TestCheckReferenceBindsARedirectedTokenToTheReferencedURI(t *testing.T) {
	h, _ := redirectingHarness(t, func(h *harness) map[string]any {
		return defaultClaims(h.server.URL + "/token")
	}, func(_ *harness, w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != statusPath {
			return false
		}
		http.Redirect(w, r, "/token", http.StatusFound)
		return true
	})
	_, err := h.checker().CheckReference(context.Background(), testIssuer, h.reference(0))
	assertSentinel(t, err, ErrStatusListTokenInvalid)
}

// TestCheckReferenceAcceptsAURIWithAQuery covers Section 6.2, where `uri` is
// any RFC 3986 URI: a query is part of the resource and is sent as written,
// and the token's `sub` must equal the URI including it.
func TestCheckReferenceAcceptsAURIWithAQuery(t *testing.T) {
	h := newHarness(t)
	uri := h.uri + "?list=7&v=2"
	h.serveToken(signES256(t, h.key, defaultHeader(), defaultClaims(uri)))
	status, err := h.checker().CheckReference(context.Background(), testIssuer, Reference{URI: uri, Index: 1})
	if err != nil {
		t.Fatal(err)
	}
	if status.URI != uri || status.TokenSubject != uri {
		t.Fatalf("status = %+v", status)
	}
	if got := h.lastReq.Load().(*http.Request).URL.RawQuery; got != "list=7&v=2" {
		t.Fatalf("query sent = %q", got)
	}

	t.Run("a sub without the query is refused", func(t *testing.T) {
		h := newHarness(t)
		h.serveToken(signES256(t, h.key, defaultHeader(), defaultClaims(h.uri)))
		_, err := h.checker().CheckReference(context.Background(), testIssuer, Reference{URI: h.uri + "?list=7", Index: 1})
		assertSentinel(t, err, ErrStatusListTokenInvalid)
	})
}
