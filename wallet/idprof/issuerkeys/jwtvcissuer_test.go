package issuerkeys

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestJWTVCIssuerMetadataRung(t *testing.T) {
	t.Parallel()
	runLadderCases(t, []ladderCase{
		{
			name: "a path-suffixed Issuer identifier reads the path-suffixed well-known document",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks": jwksObject(t, f.signer.public),
				})
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
			wantKeyIDs:     []string{"issuer-key-1"},
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, count: 1},
				RungIssuerMetadataJWKS:  {failure: "issuer metadata carries no signing key"},
			},
			check: func(t *testing.T, f *ladderFixture, resolution *Resolution, _ error) {
				if f.origin.requested("/.well-known/jwt-vc-issuer/tenant") != 1 {
					t.Errorf("path-suffixed document was not requested")
				}
				if got := resolution.Candidates[0].Issuer; got != f.issuer {
					t.Errorf("candidate issuer = %q, want %q", got, f.issuer)
				}
			},
		},
		{
			name: "a host-only Issuer identifier reads the bare well-known document",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.Issuer = f.origin.url()
				f.origin.json(t, "/.well-known/jwt-vc-issuer", map[string]any{
					"issuer": request.Issuer, "jwks": jwksObject(t, f.signer.public),
				})
				return request
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
		},
		{
			name: "jwks_uri is followed when remote key sets are enabled",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks_uri": f.origin.url() + "/jwks.json",
				})
				f.origin.json(t, "/jwks.json", jwksObject(t, f.signer.public))
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
		},
		{
			name:       "jwks_uri is not followed when remote key sets are disabled, and the switch is named",
			mechanisms: func(m *Mechanisms) { m.RemoteJWKS = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks_uri": f.origin.url() + "/jwks.json",
				})
				f.origin.json(t, "/jwks.json", jwksObject(t, f.signer.public))
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "jwt-vc-issuer metadata carries no inline jwks", disabledBy: []string{SwitchRemoteJWKS}},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requested("/jwks.json") != 0 {
					t.Errorf("jwks_uri was requested although RemoteJWKS is off")
				}
			},
		},
		{
			name: "an issuer member that is not exactly the credential iss is refused",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer + "/", "jwks": jwksObject(t, f.signer.public),
				})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "jwt-vc-issuer metadata names another issuer"},
			},
		},
		{
			name: "a redirect is refused and its target never requested",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.set("/.well-known/jwt-vc-issuer/tenant", testRoute{
					status: 302, headers: map[string]string{"Location": f.origin.url() + "/elsewhere"},
				})
				f.origin.json(t, "/elsewhere", map[string]any{"issuer": f.issuer, "jwks": jwksObject(t, f.signer.public)})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "redirects are not allowed"},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requested("/elsewhere") != 0 {
					t.Errorf("redirect target was requested")
				}
			},
		},
		{
			name: "a response not labelled as JSON is refused",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.set("/.well-known/jwt-vc-issuer/tenant", testRoute{contentType: "text/plain", body: []byte(`{}`)})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "response is not labelled as JSON"},
			},
		},
		{
			name: "a media type that merely contains application/json is refused",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.set("/.well-known/jwt-vc-issuer/tenant", testRoute{contentType: "application/jsonx", body: []byte(`{}`)})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "response is not labelled as JSON"},
			},
		},
		{
			name: "a jwks_uri served as a JWK Set media type is read",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks_uri": f.origin.url() + "/jwks.json",
				})
				body, err := json.Marshal(jwksObject(t, f.signer.public))
				if err != nil {
					t.Fatal(err)
				}
				f.origin.set("/jwks.json", testRoute{contentType: "application/jwk-set+json", body: body})
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
		},
		{
			name: "an error status is reported with its code only",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "fetch failed: HTTP 404"},
			},
		},
		{
			name:     "a declared oversized document is refused before it is read",
			maxBytes: 512,
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.set("/.well-known/jwt-vc-issuer/tenant", testRoute{
					contentType: "application/json", body: []byte(`{}`),
					headers: map[string]string{"Content-Length": "513"},
				})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "response is too large"},
			},
		},
		{
			name:     "an undeclared oversized document is cut off while it is read",
			maxBytes: 512,
			arrange: func(t *testing.T, f *ladderFixture) Request {
				body := `{"issuer":"` + f.issuer + `","padding":"` + strings.Repeat("a", 2048) + `"}`
				f.origin.set("/.well-known/jwt-vc-issuer/tenant", testRoute{contentType: "application/json", body: []byte(body), chunked: true})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "response is too large"},
			},
		},
		{
			name: "a document whose key set holds no key is not usable",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{"issuer": f.issuer, "jwks": map[string]any{"keys": []any{}}})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "jwks carries no readable public key"},
			},
		},
		{
			name: "every key stays a candidate after a stale kid match, the named key first",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer,
					"jwks":   jwksObject(t, f.signer.withKeyID("rotated-key", ""), f.decoy.withKeyID("issuer-key-1", "")),
				})
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata, MechanismJWTVCIssuerMetadata},
			wantKeyIDs:     []string{"issuer-key-1", "rotated-key"},
		},
		{
			name: "a key that states another algorithm is dropped",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				ed := newEd25519Key(t, "ed-key")
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer,
					"jwks":   jwksObject(t, ed.withKeyID("ed-key", "EdDSA"), f.signer.withKeyID("issuer-key-1", "ES256")),
				})
				return f.sdJWTRequest()
			},
			wantMechanisms: []Mechanism{MechanismJWTVCIssuerMetadata},
			wantKeyIDs:     []string{"issuer-key-1"},
		},
		{
			name: "the rung does not apply to W3C JWT VC, and nothing is requested",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatJWTVCJSON
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {failure: "not applicable for this credential format"},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name:       "a switched-off rung names its switch and requests nothing",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {failure: failureDisabled, disabledBy: []string{SwitchJWTVCIssuerMetadata}},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name: "an http Issuer identifier is refused without AllowHTTP",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.Issuer = "http://" + f.origin.hostPort() + "/tenant"
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "issuer identifier is not https"},
			},
		},
		{
			name: "an Issuer identifier with a query is refused",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.Issuer = f.issuer + "?tenant=a"
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "issuer identifier carries a query or fragment"},
			},
		},
		{
			name: "a jwks_uri with a fragment is refused and not requested",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks_uri": f.origin.url() + "/jwks.json#keys",
				})
				return f.sdJWTRequest()
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungJWTVCIssuerMetadata: {attempted: true, failure: "issuer identifier carries a query or fragment"},
			},
		},
	})
}

func TestJWTVCIssuerMetadataOverPlainHTTP(t *testing.T) {
	t.Parallel()
	origin := newPlainTestOrigin(t)
	signer := newES256Key(t, "issuer-key-1")
	issuer := origin.url() + "/tenant"
	origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{"issuer": issuer, "jwks": jwksObject(t, signer.public)})
	request := Request{Issuer: issuer, Algorithm: "ES256", CredentialFormat: FormatSDJWTVCDraft, CredentialIssuer: issuer}

	refusing := &Resolver{HTTPClient: origin.server.Client(), Mechanisms: allMechanisms()}
	if _, err := refusing.Resolve(context.Background(), request); !errors.Is(err, ErrNoIssuerKeyResolved) {
		t.Fatalf("Resolve without AllowHTTP = %v, want ErrNoIssuerKeyResolved", err)
	}
	if origin.requestCount() != 0 {
		t.Fatalf("an http origin was requested without AllowHTTP")
	}

	allowing := &Resolver{HTTPClient: origin.server.Client(), Mechanisms: allMechanisms(), AllowHTTP: true}
	resolution, err := allowing.Resolve(context.Background(), request)
	if err != nil {
		t.Fatalf("Resolve with AllowHTTP failed: %v", err)
	}
	if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, []Mechanism{MechanismJWTVCIssuerMetadata}) {
		t.Fatalf("candidate mechanisms = %v", got)
	}
}

func TestJWTVCIssuerMetadataURL(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"https://issuer.example.test":             "https://issuer.example.test/.well-known/jwt-vc-issuer",
		"https://issuer.example.test/":            "https://issuer.example.test/.well-known/jwt-vc-issuer",
		"https://issuer.example.test/tenant":      "https://issuer.example.test/.well-known/jwt-vc-issuer/tenant",
		"https://issuer.example.test/a/b/":        "https://issuer.example.test/.well-known/jwt-vc-issuer/a/b",
		"https://issuer.example.test:8443/tenant": "https://issuer.example.test:8443/.well-known/jwt-vc-issuer/tenant",
	}
	for issuer, want := range tests {
		parsed, err := url.Parse(issuer)
		if err != nil {
			t.Fatal(err)
		}
		if got := jwtVCIssuerMetadataURL(parsed).String(); got != want {
			t.Errorf("jwtVCIssuerMetadataURL(%q) = %q, want %q", issuer, got, want)
		}
	}
}
