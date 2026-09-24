package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"
)

const testRedirectURI = "https://verifier.example.test/callback"

var testVPFormats = map[string]any{"dc+sd-jwt": map[string]any{
	"sd-jwt_alg_values": []string{"ES256"}, "kb-jwt_alg_values": []string{"ES256"},
}}

func verifierFederationMetadata(entity map[string]any) map[string]any {
	metadata := map[string]any{VerifierEntityType: map[string]any{
		"redirect_uris": []string{testRedirectURI}, "vp_formats_supported": testVPFormats,
	}}
	if entity != nil {
		metadata[federationEntityType] = entity
	}
	return metadata
}

var localizedEntityMetadata = map[string]any{
	"organization_name":    "Example Verifier",
	"organization_name#en": "Example Verifier",
	"organization_name#ja": "検証者",
	"logo_uri":             "https://verifier.example.test/logo.png",
	"logo_uri#ja":          "https://verifier.example.test/logo-ja.png",
	"policy_uri":           "https://verifier.example.test/policy",
	"policy_uri#ja":        "https://verifier.example.test/policy-ja",
	"organization_uri":     "https://verifier.example.test/",
	"organization_uri#ja":  "https://verifier.example.test/ja",
}

// offlineResolver refuses every network request, so a carried chain is proven
// to need none.
func offlineResolver(t *testing.T, anchors []TrustAnchor) *Resolver {
	return &Resolver{
		HTTPClient:   &http.Client{Transport: failingTransport{t}},
		TrustAnchors: anchors,
		Now:          func() time.Time { return testNow },
	}
}

func TestResolveVerifierTrustFromACarriedChain(t *testing.T) {
	f := newDirectFederation(t, directOptions{verifierMetadata: verifierFederationMetadata(localizedEntityMetadata)})
	trust, err := offlineResolver(t, f.anchors()).ResolveVerifierTrust(context.Background(), f.verifier, f.chain, []string{"ja-JP"})
	if err != nil {
		t.Fatal(err)
	}
	encodedFormats, _ := json.Marshal(testVPFormats)
	requireJSON(t, trust.Metadata, `{"redirect_uris": ["`+testRedirectURI+`"], "vp_formats_supported": `+string(encodedFormats)+`, "vp_formats": `+string(encodedFormats)+`}`)
	if !reflect.DeepEqual(trust.RequestObjectJWKS.Keys[0].Key, f.verifierKey.jwks.Keys[0].Key) || trust.RequestObjectJWKS.Keys[0].KeyID != f.verifierKey.kid {
		t.Fatalf("request object keys are not the subject's: %+v", trust.RequestObjectJWKS)
	}
	if got := TrustPathEntityIDs(trust.TrustChain); !reflect.DeepEqual(got, []string{f.verifier, f.anchor}) {
		t.Fatalf("trust path = %v", got)
	}
	if want := time.Unix(testIssuedAt+300, 0).UTC(); !trust.TrustChain.ExpiresAt.Equal(want) || len(trust.TrustChain.Statements) != 3 {
		t.Fatalf("chain expiry %v / %d statements", trust.TrustChain.ExpiresAt, len(trust.TrustChain.Statements))
	}
	want := [4]string{"検証者", "https://verifier.example.test/logo-ja.png", "https://verifier.example.test/policy-ja", "https://verifier.example.test/ja"}
	if got := [4]string{trust.OrganizationName, trust.LogoURI, trust.PolicyURI, trust.HomepageURI}; got != want {
		t.Fatalf("display = %v, want %v", got, want)
	}
}

func TestResolveVerifierTrustSelectsDisplayMetadata(t *testing.T) {
	cases := []struct {
		name    string
		entity  map[string]any
		locales []string
		want    [4]string
	}{
		// A tagged value in another
		// language is preferred over the untagged one when no tag matches.
		{"default English", localizedEntityMetadata, nil, [4]string{"Example Verifier", "https://verifier.example.test/logo-ja.png", "https://verifier.example.test/policy-ja", "https://verifier.example.test/ja"}},
		{"untagged only", map[string]any{"organization_name": "Plain", "logo_uri": "https://verifier.example.test/logo.png"}, []string{"ja"}, [4]string{"Plain", "https://verifier.example.test/logo.png", "", ""}},
		{"primary language match", localizedEntityMetadata, []string{"ja"}, [4]string{"検証者", "https://verifier.example.test/logo-ja.png", "https://verifier.example.test/policy-ja", "https://verifier.example.test/ja"}},
		{"homepage_uri fallback", map[string]any{"homepage_uri": "https://verifier.example.test/home"}, nil, [4]string{"", "", "", "https://verifier.example.test/home"}},
		{"no federation_entity metadata", nil, nil, [4]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDirectFederation(t, directOptions{verifierMetadata: verifierFederationMetadata(tc.entity)})
			trust, err := offlineResolver(t, f.anchors()).ResolveVerifierTrust(context.Background(), f.verifier, f.chain, tc.locales)
			if err != nil {
				t.Fatal(err)
			}
			if got := [4]string{trust.OrganizationName, trust.LogoURI, trust.PolicyURI, trust.HomepageURI}; got != tc.want {
				t.Fatalf("display = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveVerifierTrustRefusesRelativeDisplayURIs(t *testing.T) {
	f := newDirectFederation(t, directOptions{verifierMetadata: verifierFederationMetadata(map[string]any{"logo_uri": "/logo.png"})})
	_, err := offlineResolver(t, f.anchors()).ResolveVerifierTrust(context.Background(), f.verifier, f.chain, nil)
	requireCode(t, err, ErrMetadataDerivationFailed, "logo_uri metadata must be an absolute URI")
}

func TestResolveVerifierTrustByDiscovery(t *testing.T) {
	f := newDirectFederation(t, directOptions{verifierMetadata: verifierFederationMetadata(nil)})
	trust, err := f.resolver().ResolveVerifierTrust(context.Background(), f.verifier, nil, []string{"en"})
	if err != nil {
		t.Fatal(err)
	}
	if trust.Metadata["vp_formats"] == nil || trust.Metadata["vp_formats_supported"] == nil {
		t.Fatalf("both format names must be present: %v", trust.Metadata)
	}
	if len(f.server.requested()) != 3 {
		t.Fatalf("requests = %v", f.server.requested())
	}
}

func TestResolveVerifierTrustRefusals(t *testing.T) {
	f := newDirectFederation(t, directOptions{})
	_, err := offlineResolver(t, nil).ResolveVerifierTrust(context.Background(), f.verifier, []string{"a.b.c"}, nil)
	requireCode(t, err, ErrTrustAnchorNotConfigured)

	entityOnly := newDirectFederation(t, directOptions{verifierMetadata: map[string]any{federationEntityType: map[string]any{}}})
	_, err = offlineResolver(t, entityOnly.anchors()).ResolveVerifierTrust(context.Background(), entityOnly.verifier, entityOnly.chain, nil)
	requireCode(t, err, ErrMetadataDerivationFailed, "subject metadata is missing")

	_, err = offlineResolver(t, f.anchors()).ResolveVerifierTrust(context.Background(), f.verifier, []string{""}, nil)
	requireCode(t, err, ErrTrustChainInvalid)

	f.server.remove(t, f.verifier)
	_, err = f.resolver().ResolveVerifierTrust(context.Background(), f.verifier, nil, nil)
	requireCode(t, err, ErrStatementFetchFailed, "returned HTTP 404")
}

func TestParseTrustChainParameter(t *testing.T) {
	want := []string{"a.b.c", "d.e.f"}
	for _, raw := range []any{[]any{"a.b.c", "d.e.f"}, []string{"a.b.c", "d.e.f"}, `["a.b.c","d.e.f"]`} {
		got, err := ParseTrustChainParameter(raw)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("ParseTrustChainParameter(%#v) = %v, %v", raw, got, err)
		}
	}
	for _, raw := range []any{nil, []any{}, []any{""}, []any{"a.b.c", 1}, "not json", `"a.b.c"`, `[]`, 42, map[string]any{}} {
		_, err := ParseTrustChainParameter(raw)
		requireCode(t, err, ErrTrustChainInvalid)
	}
}

func TestAssertResponseURIAllowed(t *testing.T) {
	metadata := map[string]any{"redirect_uris": []any{testRedirectURI}}
	if err := AssertResponseURIAllowed(metadata, testRedirectURI); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"https://verifier.example.test/other", testRedirectURI + "/", ""} {
		requireCode(t, AssertResponseURIAllowed(metadata, endpoint), ErrResponseURINotRegistered)
	}
	requireCode(t, AssertResponseURIAllowed(map[string]any{"redirect_uris": []any{testRedirectURI, 1}}, testRedirectURI), ErrResponseURINotRegistered)
	requireCode(t, AssertResponseURIAllowed(map[string]any{}, testRedirectURI), ErrResponseURINotRegistered)
}

func TestTrustPathEntityIDs(t *testing.T) {
	chain := &TrustChain{
		SubjectEntityID: "https://v", TrustAnchorEntityID: "https://a",
		Statements: []EntityStatement{
			{Issuer: "https://v", Subject: "https://v"},
			{Issuer: "https://i", Subject: "https://v"},
			{Issuer: "https://a", Subject: "https://i"},
			{Issuer: "https://a", Subject: "https://a"},
		},
	}
	if got := TrustPathEntityIDs(chain); !reflect.DeepEqual(got, []string{"https://v", "https://i", "https://a"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSelectLocale(t *testing.T) {
	cases := []struct {
		available, preferred []string
		want                 string
		ok                   bool
	}{
		{[]string{"de-DE", "en-US", "en-GB"}, []string{"EN-us"}, "en-US", true},
		{[]string{"de-DE", "en-US", "en-GB"}, []string{"en-AU"}, "en-US", true},
		{[]string{"de-DE", "en-US"}, []string{"fr-FR"}, "de-DE", true},
		{nil, []string{"en"}, "", false},
	}
	for _, tc := range cases {
		got, ok := selectLocale(tc.available, tc.preferred)
		if got != tc.want || ok != tc.ok {
			t.Errorf("selectLocale(%v, %v) = %q, %v", tc.available, tc.preferred, got, ok)
		}
	}
}
