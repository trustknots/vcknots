package federation

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestResolveTrustChainsDiscoversADirectChain(t *testing.T) {
	f := newDirectFederation(t, directOptions{})
	chains, err := f.resolver().ResolveTrustChains(context.Background(), f.verifier)
	if err != nil {
		t.Fatal(err)
	}
	chain := chains[0]
	if chain.SubjectEntityID != f.verifier || chain.TrustAnchorEntityID != f.anchor {
		t.Fatalf("unexpected chain ends: %+v", chain)
	}
	want := [][2]string{{f.verifier, f.verifier}, {f.anchor, f.verifier}, {f.anchor, f.anchor}}
	if got := statementPairs(chain); !reflect.DeepEqual(got, want) {
		t.Fatalf("statements = %v, want %v", got, want)
	}
	verifierURL, _ := EntityConfigurationURL(f.verifier)
	anchorURL, _ := EntityConfigurationURL(f.anchor)
	subordinateURL, _ := SubordinateStatementURL(f.server.fetchEndpoint("anchor"), f.verifier)
	if got := f.server.requested(); !reflect.DeepEqual(got, []string{verifierURL, anchorURL, subordinateURL}) {
		t.Fatalf("requests = %v", got)
	}
	for _, accept := range f.server.accepts {
		if accept != entityStatementMediaType {
			t.Fatalf("Accept = %q", accept)
		}
	}
}

func TestResolveTrustChainsResolvesAnAnchorItself(t *testing.T) {
	server := newFederationServer(t)
	anchor := server.entity("anchor")
	key := newSigningKey(t, "anchor-key")
	server.serveConfiguration(t, anchor, signStatement(t, statement{
		issuer: anchor, subject: anchor, jwks: key.jwks, issuedAt: testIssuedAt, expires: testIssuedAt + 900,
	}, key, header{}))

	chains, err := server.resolver(TrustAnchor{EntityID: anchor, JWKS: key.jwks}).ResolveTrustChains(context.Background(), anchor)
	if err != nil {
		t.Fatal(err)
	}
	if got := statementPairs(chains[0]); !reflect.DeepEqual(got, [][2]string{{anchor, anchor}}) {
		t.Fatalf("statements = %v", got)
	}
	if len(server.requested()) != 1 {
		t.Fatalf("requests = %v", server.requested())
	}
}

func TestResolveTrustChainsAppliesThePublicNetworkPolicyToDiscovery(t *testing.T) {
	f := newDirectFederation(t, directOptions{})
	resolver := f.resolver()
	resolver.RequirePublicNetworkHost = true
	_, err := resolver.ResolveTrustChains(context.Background(), f.verifier)
	requireCode(t, err, ErrStatementFetchFailed, "must use a public network host")
	if len(f.server.requested()) != 0 {
		t.Fatalf("a refused host was fetched: %v", f.server.requested())
	}
}

// hierarchy is verifier -> intermediate -> anchor, optionally with a direct
// verifier -> anchor edge as well.
type hierarchy struct {
	server                         *federationServer
	verifier, intermediate, anchor string
	anchorKey                      signingKey
}

type hierarchyOptions struct {
	verifierHints          func(h *hierarchy) []string
	intermediateHints      func(h *hierarchy) []string
	verifierMetadata       map[string]any
	leafPolicy             map[string]any
	intermediatePolicy     map[string]any
	direct                 bool
	directPolicy           map[string]any
	directSignedByVerifier bool
	noAnchor               bool
}

func newHierarchy(t *testing.T, opts hierarchyOptions) *hierarchy {
	t.Helper()
	server := newFederationServer(t)
	h := &hierarchy{server: server, verifier: server.entity("verifier"), intermediate: server.entity("intermediate"), anchor: server.entity("anchor")}
	leafKey, intermediateKey := newSigningKey(t, "leaf-key"), newSigningKey(t, "intermediate-key")
	h.anchorKey = newSigningKey(t, "anchor-key")
	verifierHints := []string{h.intermediate}
	if opts.verifierHints != nil {
		verifierHints = opts.verifierHints(h)
	}
	intermediateHints := []string{h.anchor}
	if opts.intermediateHints != nil {
		intermediateHints = opts.intermediateHints(h)
	}
	if opts.verifierMetadata == nil {
		opts.verifierMetadata = map[string]any{VerifierEntityType: map[string]any{"client_name": "Original verifier"}}
	}
	nonNil := func(policy map[string]any) any {
		if policy == nil {
			return nil
		}
		return policy
	}
	server.serveConfiguration(t, h.verifier, signStatement(t, statement{
		issuer: h.verifier, subject: h.verifier, jwks: leafKey.jwks, issuedAt: testIssuedAt, expires: testIssuedAt + 600,
		authorityHints: verifierHints, metadata: opts.verifierMetadata,
	}, leafKey, header{}))
	server.serveConfiguration(t, h.intermediate, signStatement(t, statement{
		issuer: h.intermediate, subject: h.intermediate, jwks: intermediateKey.jwks, issuedAt: testIssuedAt, expires: testIssuedAt + 700,
		authorityHints: intermediateHints, metadata: fetchEndpointMetadata(server.fetchEndpoint("intermediate")),
	}, intermediateKey, header{}))
	server.serveSubordinate(t, server.fetchEndpoint("intermediate"), h.verifier, signStatement(t, statement{
		issuer: h.intermediate, subject: h.verifier, jwks: leafKey.jwks, issuedAt: testIssuedAt, expires: testIssuedAt + 400,
		metadataPolicy: nonNil(opts.leafPolicy),
	}, intermediateKey, header{}))
	if opts.noAnchor {
		return h
	}
	server.serveSubordinate(t, server.fetchEndpoint("anchor"), h.intermediate, signStatement(t, statement{
		issuer: h.anchor, subject: h.intermediate, jwks: intermediateKey.jwks, issuedAt: testIssuedAt, expires: testIssuedAt + 500,
		metadataPolicy: nonNil(opts.intermediatePolicy),
	}, h.anchorKey, header{}))
	server.serveConfiguration(t, h.anchor, signStatement(t, statement{
		issuer: h.anchor, subject: h.anchor, jwks: h.anchorKey.jwks, issuedAt: testIssuedAt, expires: testIssuedAt + 900,
		metadata: fetchEndpointMetadata(server.fetchEndpoint("anchor")),
	}, h.anchorKey, header{}))
	if opts.direct {
		signer := h.anchorKey
		if opts.directSignedByVerifier {
			signer = leafKey
		}
		server.serveSubordinate(t, server.fetchEndpoint("anchor"), h.verifier, signStatement(t, statement{
			issuer: h.anchor, subject: h.verifier, jwks: leafKey.jwks, issuedAt: testIssuedAt, expires: testIssuedAt + 300,
			metadataPolicy: nonNil(opts.directPolicy),
		}, signer, header{}))
	}
	return h
}

func (h *hierarchy) resolver() *Resolver {
	return h.server.resolver(TrustAnchor{EntityID: h.anchor, JWKS: h.anchorKey.jwks})
}

func (h *hierarchy) viaIntermediate() [][2]string {
	return [][2]string{{h.verifier, h.verifier}, {h.intermediate, h.verifier}, {h.anchor, h.intermediate}, {h.anchor, h.anchor}}
}

func (h *hierarchy) direct() [][2]string {
	return [][2]string{{h.verifier, h.verifier}, {h.anchor, h.verifier}, {h.anchor, h.anchor}}
}

func bothHints(h *hierarchy) []string { return []string{h.intermediate, h.anchor} }

func TestResolveVerifierTrustThroughAnIntermediateAppliesItsPolicies(t *testing.T) {
	h := newHierarchy(t, hierarchyOptions{
		verifierMetadata: map[string]any{VerifierEntityType: map[string]any{"client_name": "Original verifier", "contacts": []string{"ops@example.test"}}},
		leafPolicy: map[string]any{VerifierEntityType: map[string]any{
			"client_name": map[string]any{"value": "Federated verifier"},
			"contacts":    map[string]any{"add": []string{"security@example.test"}},
		}},
		intermediatePolicy: map[string]any{VerifierEntityType: map[string]any{
			"logo_uri": map[string]any{"default": "https://verifier.example.test/logo.png"},
		}},
	})
	trust, err := h.resolver().ResolveVerifierTrust(context.Background(), h.verifier, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := statementPairs(trust.TrustChain); !reflect.DeepEqual(got, h.viaIntermediate()) {
		t.Fatalf("statements = %v", got)
	}
	requireJSON(t, trust.Metadata, `{
		"client_name": "Federated verifier",
		"contacts": ["ops@example.test", "security@example.test"],
		"logo_uri": "https://verifier.example.test/logo.png"
	}`)
}

func TestResolveTrustChainsChoosesAmongAuthorityHints(t *testing.T) {
	cases := []struct {
		name   string
		opts   hierarchyOptions
		remove func(h *hierarchy) string
		want   func(h *hierarchy) [][2]string
	}{
		{"shortest valid chain first", hierarchyOptions{verifierHints: bothHints, direct: true}, nil, (*hierarchy).direct},
		{"longer chain when the shortest is invalid", hierarchyOptions{verifierHints: bothHints, direct: true, directSignedByVerifier: true}, nil, (*hierarchy).viaIntermediate},
		{"other hint when one cannot be fetched", hierarchyOptions{verifierHints: bothHints, direct: true}, func(h *hierarchy) string { return h.intermediate }, (*hierarchy).direct},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHierarchy(t, tc.opts)
			if tc.remove != nil {
				h.server.remove(t, tc.remove(h))
			}
			chains, err := h.resolver().ResolveTrustChains(context.Background(), h.verifier)
			if err != nil {
				t.Fatal(err)
			}
			if got := statementPairs(chains[0]); !reflect.DeepEqual(got, tc.want(h)) {
				t.Fatalf("statements = %v, want %v", got, tc.want(h))
			}
		})
	}
}

func TestResolveVerifierTrustFallsBackWhenTheShortestChainCannotDeriveMetadata(t *testing.T) {
	h := newHierarchy(t, hierarchyOptions{
		verifierHints: bothHints, direct: true,
		directPolicy: map[string]any{VerifierEntityType: map[string]any{"required_parameter": map[string]any{"essential": true}}},
	})
	trust, err := h.resolver().ResolveVerifierTrust(context.Background(), h.verifier, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := statementPairs(trust.TrustChain); !reflect.DeepEqual(got, h.viaIntermediate()) {
		t.Fatalf("statements = %v", got)
	}
	requireJSON(t, trust.Metadata, `{"client_name": "Original verifier"}`)
}

func TestResolveTrustChainsFetchesEachEntityOnce(t *testing.T) {
	// Both the verifier and the intermediate hint at the anchor, so the
	// anchor's configuration is reached twice in one resolution.
	h := newHierarchy(t, hierarchyOptions{verifierHints: bothHints, direct: true})
	if _, err := h.resolver().ResolveTrustChains(context.Background(), h.verifier); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, requested := range h.server.requested() {
		seen[requested]++
		if seen[requested] > 1 {
			t.Fatalf("%s was fetched more than once: %v", requested, h.server.requested())
		}
	}
}

func TestResolveTrustChainsRefusals(t *testing.T) {
	loop := hierarchyOptions{noAnchor: true, intermediateHints: func(h *hierarchy) []string { return []string{h.verifier} }}
	cases := []struct {
		name     string
		opts     hierarchyOptions
		tweak    func(r *Resolver)
		sentinel error
		fragment string
	}{
		{"authority hint loop", loop, nil, ErrTrustChainUnresolved, "could not be resolved to a configured trust anchor"},
		{"no configured anchor", hierarchyOptions{}, func(r *Resolver) { r.TrustAnchors = nil }, ErrTrustAnchorNotConfigured, "trust anchors must be configured"},
		{"depth bound", hierarchyOptions{}, func(r *Resolver) { r.MaxDepth = 2 }, ErrTrustChainUnresolved, "exceeded maximum depth"},
		{"invalid depth bound", hierarchyOptions{}, func(r *Resolver) { r.MaxDepth = 1 }, ErrTrustChainUnresolved, "maximum depth is invalid"},
		{"superior without a fetch endpoint", hierarchyOptions{}, nil, ErrTrustChainUnresolved, "must include federation_entity metadata"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHierarchy(t, tc.opts)
			if strings.Contains(tc.name, "fetch endpoint") {
				// Replace the intermediate's configuration with one that
				// publishes no federation_entity metadata.
				key := newSigningKey(t, "intermediate-key")
				h.server.serveConfiguration(t, h.intermediate, signStatement(t, statement{
					issuer: h.intermediate, subject: h.intermediate, jwks: key.jwks, issuedAt: testIssuedAt, expires: testIssuedAt + 700,
					authorityHints: []string{h.anchor}, metadata: map[string]any{},
				}, key, header{}))
			}
			resolver := h.resolver()
			if tc.tweak != nil {
				tc.tweak(resolver)
			}
			_, err := resolver.ResolveTrustChains(context.Background(), h.verifier)
			requireCode(t, err, tc.sentinel, tc.fragment)
		})
	}
}

func TestResolveTrustChainsRefusesAMismatchedEntityConfiguration(t *testing.T) {
	f := newDirectFederation(t, directOptions{})
	// The anchor's well-known location serves the verifier's configuration.
	f.server.serveConfiguration(t, f.anchor, f.chain[0])
	_, err := f.resolver().ResolveTrustChains(context.Background(), f.verifier)
	requireCode(t, err, ErrTrustChainUnresolved, "entity configuration subject does not match entity identifier")
}
