package issuerkeys

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
)

// ladderFixture is the world one ladder case runs in: an https origin that
// hosts the issuer, the DID documents and the well-known documents, and the
// keys an issuer might sign with.
type ladderFixture struct {
	origin *testOrigin
	// signer is the issuer's signing key, `kid` "issuer-key-1".
	signer testKey
	// decoy is a key nobody signed with.
	decoy testKey
	// issuer is an Issuer identifier with a path, hosted by origin.
	issuer string
	// credentialIssuer is the Credential Issuer identifier of the issuance,
	// the same identifier as issuer.
	credentialIssuer string
}

func newLadderFixture(t *testing.T) *ladderFixture {
	t.Helper()
	origin := newTestOrigin(t)
	return &ladderFixture{
		origin:           origin,
		signer:           newES256Key(t, "issuer-key-1"),
		decoy:            newES256Key(t, "decoy-key"),
		issuer:           origin.url() + "/tenant",
		credentialIssuer: origin.url() + "/tenant",
	}
}

// sdJWTRequest is an SD-JWT VC signed by f.signer under f.issuer.
func (f *ladderFixture) sdJWTRequest() Request {
	return Request{
		Issuer:           f.issuer,
		KeyID:            "issuer-key-1",
		Algorithm:        "ES256",
		CredentialFormat: FormatSDJWTVC,
		CredentialIssuer: f.credentialIssuer,
	}
}

// jwtVCRequest is a W3C JWT VC signed by f.signer under the DID didValue.
func (f *ladderFixture) jwtVCRequest(didValue, kid string) Request {
	return Request{
		Issuer:           didValue,
		KeyID:            kid,
		Algorithm:        "ES256",
		CredentialFormat: FormatJWTVCJSON,
		CredentialIssuer: f.credentialIssuer,
		Payload:          map[string]any{"iss": didValue, "vc": map[string]any{"issuer": didValue}},
	}
}

// originString is the RFC 6454 serialization of the fixture origin.
func (f *ladderFixture) originString() string { return f.origin.url() }

// didWebDocument is a DID document for didValue whose assertionMethod refers
// to the verification method fragment with key.
func didWebDocument(t *testing.T, didValue, fragment string, key jose.JSONWebKey) map[string]any {
	t.Helper()
	id := didValue + "#" + fragment
	return map[string]any{
		"id": didValue,
		"verificationMethod": []any{map[string]any{
			"id": id, "type": "JsonWebKey2020", "controller": didValue, "publicKeyJwk": jwkMap(t, key),
		}},
		"assertionMethod": []any{id},
	}
}

type wantDiagnostic struct {
	attempted  bool
	count      int
	failure    string
	disabledBy []string
}

type ladderCase struct {
	name       string
	mechanisms func(*Mechanisms)
	maxBytes   int64
	arrange    func(t *testing.T, f *ladderFixture) Request
	// wantErr is the sentinel the error must match, nil for a resolution.
	wantErr        error
	wantMechanisms []Mechanism
	wantKeyIDs     []string
	wantDNSName    string
	diagnostics    map[string]wantDiagnostic
	check          func(t *testing.T, f *ladderFixture, resolution *Resolution, err error)
}

func runLadderCases(t *testing.T, cases []ladderCase) {
	t.Helper()
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newLadderFixture(t)
			mechanisms := allMechanisms()
			if test.mechanisms != nil {
				test.mechanisms(&mechanisms)
			}
			resolver := f.origin.resolver(mechanisms)
			resolver.MaxDocumentBytes = test.maxBytes
			request := test.arrange(t, f)

			resolution, err := resolver.Resolve(context.Background(), request)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("Resolve error = %v, want %v", err, test.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Resolve failed: %v", err)
			}
			if test.wantErr == nil {
				if got := mechanismsOf(resolution.Candidates); !slices.Equal(got, test.wantMechanisms) {
					t.Errorf("candidate mechanisms = %v, want %v", got, test.wantMechanisms)
				}
				if test.wantKeyIDs != nil {
					var got []string
					for _, candidate := range resolution.Candidates {
						got = append(got, candidate.Key.KeyID)
					}
					if !slices.Equal(got, test.wantKeyIDs) {
						t.Errorf("candidate key IDs = %v, want %v", got, test.wantKeyIDs)
					}
				}
				if resolution.IssuerDNSName != test.wantDNSName {
					t.Errorf("IssuerDNSName = %q, want %q", resolution.IssuerDNSName, test.wantDNSName)
				}
			}
			diagnostics := diagnosticsOf(t, resolution, err)
			for rung, want := range test.diagnostics {
				got := diagnosticFor(t, diagnostics, rung)
				if got.Attempted != want.attempted || got.CandidateCount != want.count || got.Failure != want.failure || !slices.Equal(got.DisabledBy, want.disabledBy) {
					t.Errorf("%s diagnostic = %+v, want %+v", rung, got, want)
				}
			}
			assertDiagnosticsCarryNoSecrets(t, f, diagnostics, err)
			if test.check != nil {
				test.check(t, f, resolution, err)
			}
		})
	}
}

// assertDiagnosticsCarryNoSecrets checks that nothing the ladder reports names
// the origin or carries key material: a diagnostic is rendered and logged.
func assertDiagnosticsCarryNoSecrets(t *testing.T, f *ladderFixture, diagnostics []MechanismDiagnostic, err error) {
	t.Helper()
	coordinates := jwkMap(t, f.signer.public)["x"].(string)
	texts := []string{}
	for _, diagnostic := range diagnostics {
		texts = append(texts, diagnostic.Failure)
	}
	if err != nil {
		texts = append(texts, err.Error())
	}
	for _, text := range texts {
		if strings.Contains(text, f.origin.hostPort()) || strings.Contains(text, coordinates) ||
			strings.Contains(text, "did:jwk:") || strings.Contains(text, "did:key:") || strings.Contains(text, "%3A") {
			t.Errorf("diagnostic text %q carries a URL, a DID or key material", text)
		}
	}
}

func TestEveryMechanismSwitchedOff(t *testing.T) {
	t.Parallel()
	f := newLadderFixture(t)
	ca := newTestCA(t, "root")
	leaf := newTestLeaf(t, ca, "127.0.0.1")
	didValue := f.origin.didWeb("bank")
	request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
	request.CredentialFormat = FormatSDJWTVC
	request.X5C = x5cOf(leaf)
	request.IssuerMetadataJWKS = keySet(f.signer.public)

	// Only the x5c rung left standing: an X.509-only issuer policy.
	resolver := f.origin.resolver(Mechanisms{X5C: true})
	_, err := resolver.Resolve(context.Background(), request)
	if !errors.Is(err, ErrNoIssuerKeyResolved) {
		t.Fatalf("Resolve error = %v, want ErrNoIssuerKeyResolved", err)
	}
	if f.origin.requestCount() != 0 {
		t.Fatalf("requests were made with every networked mechanism off: %d", f.origin.requestCount())
	}
	diagnostics := diagnosticsOf(t, nil, err)
	want := map[string][]string{
		RungX5C:                 nil,
		RungJWTVCIssuerMetadata: {SwitchJWTVCIssuerMetadata},
		RungDID:                 {SwitchDIDWeb},
		RungIssuerMetadataJWKS:  {SwitchIssuerMetadataJWKS},
	}
	for rung, disabledBy := range want {
		if got := diagnosticFor(t, diagnostics, rung).DisabledBy; !slices.Equal(got, disabledBy) {
			t.Errorf("%s DisabledBy = %v, want %v", rung, got, disabledBy)
		}
	}
	if code, _ := common.CodeOf(err); code != "issuer_keys_unresolved" {
		t.Errorf("code = %q", code)
	}
}

func TestResolveHonoursContext(t *testing.T) {
	t.Parallel()
	f := newLadderFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.origin.resolver(allMechanisms()).Resolve(ctx, f.sdJWTRequest())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve error = %v, want context.Canceled", err)
	}
}
