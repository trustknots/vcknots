package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// generatedFederation serves Entity Configurations and Subordinate Statements
// for any Entity name on demand, signed with a key minted per name, so a test
// can describe a large authority-hint graph as a function.
type generatedFederation struct {
	*httptest.Server
	hints  func(name string) []string
	anchor string

	mu       sync.Mutex
	keys     map[string]signingKey
	requests []string
}

const generatedRequestCap = 2000

func newGeneratedFederation(t *testing.T, anchor string, hints func(name string) []string) *generatedFederation {
	t.Helper()
	g := &generatedFederation{hints: hints, anchor: anchor, keys: map[string]signingKey{}}
	g.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.requests = append(g.requests, r.URL.RequestURI())
		count := len(g.requests)
		g.mu.Unlock()
		// Keeps an unbounded resolver from running for minutes.
		if count > generatedRequestCap {
			http.NotFound(w, r)
			return
		}
		name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/e/"), "/")
		var body string
		switch rest {
		case ".well-known/openid-federation":
			body = g.configuration(t, name)
		case "fetch":
			subject := strings.TrimPrefix(r.URL.Query().Get("sub"), g.URL+"/e/")
			body = g.subordinate(t, name, subject)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", entityStatementMediaType)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *generatedFederation) entity(name string) string { return g.URL + "/e/" + name }

func (g *generatedFederation) key(t *testing.T, name string) signingKey {
	g.mu.Lock()
	defer g.mu.Unlock()
	key, ok := g.keys[name]
	if !ok {
		key = newSigningKey(t, name+"-key")
		g.keys[name] = key
	}
	return key
}

func (g *generatedFederation) configuration(t *testing.T, name string) string {
	key := g.key(t, name)
	s := statement{
		issuer: g.entity(name), subject: g.entity(name), jwks: key.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 600,
		metadata: fetchEndpointMetadata(g.entity(name) + "/fetch"),
	}
	if name != g.anchor {
		var hints []string
		for _, hint := range g.hints(name) {
			hints = append(hints, g.entity(hint))
		}
		s.authorityHints = hints
	}
	return signStatement(t, s, key, header{})
}

func (g *generatedFederation) subordinate(t *testing.T, issuer, subject string) string {
	return signStatement(t, statement{
		issuer: g.entity(issuer), subject: g.entity(subject), jwks: g.key(t, subject).jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 300,
	}, g.key(t, issuer), header{})
}

func (g *generatedFederation) requested() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.requests...)
}

func (g *generatedFederation) resolver(t *testing.T) *Resolver {
	return &Resolver{
		HTTPClient:   g.Client(),
		TrustAnchors: []TrustAnchor{{EntityID: g.entity(g.anchor), JWKS: g.key(t, g.anchor).jwks}},
		Now:          func() time.Time { return testNow },
	}
}

// fanOut hints at n children of every Entity.
func fanOut(n int) func(string) []string {
	return func(name string) []string {
		hints := make([]string, n)
		for i := range hints {
			hints[i] = name + "." + string(rune('a'+i))
		}
		return hints
	}
}

func TestResolveTrustChainsStopsAHintExplosionWithinTheFetchBudget(t *testing.T) {
	g := newGeneratedFederation(t, "anchor", fanOut(12))
	_, err := g.resolver(t).ResolveTrustChains(context.Background(), g.entity("v"))
	requireCode(t, err, ErrTrustChainUnresolved, "fetch budget")
	if got := len(g.requested()); got > DefaultMaxFetches {
		t.Fatalf("%d fetches, budget %d", got, DefaultMaxFetches)
	}
}

func TestResolveTrustChainsHonoursTheConfiguredFetchBudget(t *testing.T) {
	g := newGeneratedFederation(t, "anchor", fanOut(3))
	resolver := g.resolver(t)
	resolver.MaxFetches = 5
	_, err := resolver.ResolveTrustChains(context.Background(), g.entity("v"))
	requireCode(t, err, ErrTrustChainUnresolved, "fetch budget")
	if got := len(g.requested()); got != 5 {
		t.Fatalf("%d fetches, want 5", got)
	}
}

func TestResolveTrustChainsFollowsOnlyTheFirstAuthorityHints(t *testing.T) {
	g := newGeneratedFederation(t, "anchor", fanOut(3))
	resolver := g.resolver(t)
	resolver.MaxFetches = 1000
	resolver.MaxDepth = 3
	resolver.MaxAuthorityHints = 2
	_, err := resolver.ResolveTrustChains(context.Background(), g.entity("v"))
	requireCode(t, err, ErrTrustChainUnresolved)
	requested := g.requested()
	for _, uri := range requested {
		if strings.Contains(uri, ".c") {
			t.Fatalf("a hint beyond the limit was followed: %s", uri)
		}
	}
	// v, v.a, v.b, and the two first hints of each of those.
	if len(requested) != 7 {
		t.Fatalf("requests = %v", requested)
	}
}

func TestResolveTrustChainsBoundsTheCandidatePathsOfADenseGraph(t *testing.T) {
	// v hints at four intermediates, each of which hints at the same four
	// intermediates one level up, which all hint at the anchor: 16 paths.
	layer := func(prefix string) []string {
		return []string{prefix + "0", prefix + "1", prefix + "2", prefix + "3"}
	}
	g := newGeneratedFederation(t, "anchor", func(name string) []string {
		switch {
		case name == "v":
			return layer("a")
		case strings.HasPrefix(name, "a"):
			return layer("b")
		default:
			return []string{"anchor"}
		}
	})
	resolver := g.resolver(t)
	resolver.MaxFetches = 100
	chains, err := resolver.ResolveTrustChains(context.Background(), g.entity("v"))
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != maxPathsPerEntity {
		t.Fatalf("%d chains, want %d", len(chains), maxPathsPerEntity)
	}
	seen := map[string]bool{}
	for _, uri := range g.requested() {
		if seen[uri] {
			t.Fatalf("%s was fetched twice", uri)
		}
		seen[uri] = true
	}
}

func TestResolveTrustChainsStopsAtTheDurationBound(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	t.Cleanup(server.Close)
	resolver := &Resolver{
		HTTPClient:   server.Client(),
		TrustAnchors: []TrustAnchor{{EntityID: server.URL + "/anchor"}},
		MaxDuration:  50 * time.Millisecond,
	}
	started := time.Now()
	_, err := resolver.ResolveTrustChains(context.Background(), server.URL+"/v")
	requireCode(t, err, ErrTrustChainUnresolved, "stopped")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("resolution took %v", elapsed)
	}
}
