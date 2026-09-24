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

func TestDIDRungMethods(t *testing.T) {
	t.Parallel()
	runLadderCases(t, []ladderCase{
		{
			name: "a did:key bound by the issuer metadata",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didKey(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue+"#"+strings.TrimPrefix(didValue, "did:key:"))
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, count: 1},
			},
			check: func(t *testing.T, f *ladderFixture, resolution *Resolution, _ error) {
				didValue := didKey(t, f.signer.public)
				if got := resolution.Candidates[0]; got.Issuer != didValue || got.DID != didValue {
					t.Errorf("DID candidate = issuer %q did %q, want %q", got.Issuer, got.DID, didValue)
				}
			},
		},
		{
			name: "a did:key the metadata does not name is DID-only trust",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didKey(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue)
				request.IssuerMetadataJWKS = keySet(f.decoy.public)
				request.Payload = nil
				return request
			},
			mechanisms: func(m *Mechanisms) { m.DIDConfiguration = false },
			wantErr:    ErrDIDOnlyTrustUnsupported,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID-only trust not accepted without metadata/config binding", disabledBy: []string{SwitchDIDConfiguration}},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, err error) {
				var didOnly *DIDOnlyTrustError
				if !errors.As(err, &didOnly) || len(didOnly.Diagnostics) != 3 {
					t.Fatalf("DID-only error = %#v, want three diagnostics ending at the DID rung", err)
				}
				if code, _ := common.CodeOf(err); code != "issuer_keys_did_only_trust_unsupported" {
					t.Errorf("code = %q", code)
				}
			},
		},
		{
			name: "a did:jwk with a relative kid bound by the issuer metadata",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.jwtVCRequest(didValue, "#0")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
		},
		{
			name: "an Ed25519 did:jwk bound by the signed vc.issuer.credential_issuer",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				ed := newEd25519Key(t, "")
				didValue := didJWK(t, ed.public)
				request := f.jwtVCRequest(didValue, didValue+"#0")
				request.Algorithm = "EdDSA"
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": f.credentialIssuer}}
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDCredentialIssuerBinding},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("the credential_issuer binding made %d requests", f.origin.requestCount())
				}
			},
		},
		{
			name: "the credential_issuer binding switched off leaves the DID unbound",
			mechanisms: func(m *Mechanisms) {
				m.CredentialIssuerBinding = false
				m.DIDConfiguration = false
			},
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue+"#0")
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": f.credentialIssuer}}
				return request
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID-only trust not accepted without metadata/config binding", disabledBy: []string{SwitchCredentialIssuerBinding, SwitchDIDConfiguration}},
			},
		},
		{
			name:       "a credential_issuer naming another Credential Issuer does not bind",
			mechanisms: func(m *Mechanisms) { m.DIDConfiguration = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue+"#0")
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": "https://other.example.test/issuer"}}
				return request
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
		},
		{
			name:       "the credential_issuer binding does not apply to SD-JWT VC",
			mechanisms: func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue+"#0")
				request.CredentialFormat = FormatSDJWTVC
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": f.credentialIssuer}}
				return request
			},
			wantErr: ErrDIDOnlyTrustUnsupported,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID-only trust not accepted without metadata/config binding"},
			},
		},
		{
			name:       "a switched-off DID method names its switch and is not DID-only trust",
			mechanisms: func(m *Mechanisms) { m.DIDJWK = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.jwtVCRequest(didValue, didValue+"#0")
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": f.credentialIssuer}}
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {failure: failureDisabled, disabledBy: []string{SwitchDIDJWK}},
			},
		},
		{
			name: "a DID method this package does not resolve is reported as unsupported",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				return f.jwtVCRequest("did:example:issuer", "did:example:issuer#key-1")
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {failure: "DID method is not supported"},
			},
		},
		{
			name: "a kid that is not a DID with a URL issuer",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			mechanisms:     func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungDID: {failure: "issuer is not a DID"},
			},
		},
		{
			name: "no kid and a URL issuer",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.sdJWTRequest()
				request.KeyID = ""
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			mechanisms:     func(m *Mechanisms) { m.JWTVCIssuerMetadata = false },
			wantMechanisms: []Mechanism{MechanismCredentialIssuerMetadataJWKS},
			diagnostics: map[string]wantDiagnostic{
				RungDID: {failure: "issuer is not a DID"},
			},
		},
		{
			name: "a kid naming a DID under a URL issuer is not attributed to the issuer",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				request := f.sdJWTRequest()
				request.CredentialFormat = FormatJWTVCJSON
				request.KeyID = didValue + "#0"
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {failure: "kid names a DID but the issuer is not that DID"},
			},
		},
		{
			name: "a kid naming another DID than the issuer yields no DID key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				request := f.jwtVCRequest(didJWK(t, f.decoy.public), didJWK(t, f.signer.public)+"#0")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID:                {failure: "kid names a DID other than the issuer"},
				RungIssuerMetadataJWKS: {failure: "issuer is not the credential issuer"},
			},
		},
	})
}

func TestDIDRungDIDWeb(t *testing.T) {
	t.Parallel()
	runLadderCases(t, []ladderCase{
		{
			name: "a did:web document key bound by the issuer metadata",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.json(t, "/bank/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
			check: func(t *testing.T, f *ladderFixture, resolution *Resolution, _ error) {
				if got := f.origin.accept("/bank/did.json"); got != "application/did+json, application/json" {
					t.Errorf("Accept = %q", got)
				}
				if got, want := resolution.Candidates[0].Key.KeyID, f.origin.didWeb("bank")+"#issuer-key-1"; got != want {
					t.Errorf("DID candidate KeyID = %q, want the verification method id %q", got, want)
				}
			},
		},
		{
			name: "a bare kid narrows the document to its verification method",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				document := didWebDocument(t, didValue, "issuer-key-1", f.signer.public)
				document["assertionMethod"] = append(document["assertionMethod"].([]any), map[string]any{
					"id": didValue + "#decoy", "type": "JsonWebKey2020", "controller": didValue, "publicKeyJwk": jwkMap(t, f.decoy.public),
				})
				f.origin.json(t, "/bank/did.json", document)
				request := f.jwtVCRequest(didValue, "issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public, f.decoy.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, count: 1},
			},
		},
		{
			name: "a relative fragment kid narrows the document to its verification method",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.json(t, "/bank/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, "#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
		},
		{
			name: "a kid naming no verification method of the document yields no DID key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.json(t, "/bank/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, "#rotated")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID resolved to no verification key"},
			},
		},
		{
			name: "an embedded assertionMethod key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.json(t, "/bank/did.json", map[string]any{
					"id": didValue,
					"assertionMethod": []any{map[string]any{
						"id": didValue + "#issuer-key-1", "type": "JsonWebKey2020", "controller": didValue, "publicKeyJwk": jwkMap(t, f.signer.public),
					}},
				})
				request := f.jwtVCRequest(didValue, "#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
		},
		{
			name: "the JSON-LD DID document media type is accepted",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.jsonAs(t, "/bank/did.json", "application/did+ld+json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, "#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantMechanisms: []Mechanism{MechanismDIDMetadataBinding},
		},
		{
			name:       "an authentication-only verification method is never an issuer key",
			mechanisms: func(m *Mechanisms) { m.DIDConfiguration = false },
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				document := didWebDocument(t, didValue, "issuer-key-1", f.signer.public)
				document["authentication"] = document["assertionMethod"]
				delete(document, "assertionMethod")
				f.origin.json(t, "/bank/did.json", document)
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.Payload["vc"] = map[string]any{"issuer": map[string]any{"id": didValue, "credential_issuer": f.credentialIssuer}}
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID resolved to no verification key"},
			},
		},
		{
			name: "a did:web host other than the Credential Issuer's is refused before any request",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := "did:web:other.example.test:bank"
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "did:web host is not the credential issuer host"},
			},
		},
		{
			name: "a did:web on the Credential Issuer's host but another port is refused before any request",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := "did:web:127.0.0.1%3A1:bank"
				f.origin.json(t, "/bank/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "did:web host is not the credential issuer host"},
			},
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requestCount() != 0 {
					t.Errorf("requests were made: %d", f.origin.requestCount())
				}
			},
		},
		{
			name: "a did:web document that cannot be fetched yields no DID key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID resolved to no verification key"},
			},
		},
		{
			name: "a did:web document that is not labelled as JSON yields no DID key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.set("/bank/did.json", testRoute{contentType: "text/plain", body: []byte(`{}`)})
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID resolved to no verification key"},
			},
		},
		{
			name:     "an oversized did:web document yields no DID key",
			maxBytes: 512,
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.set("/bank/did.json", testRoute{contentType: "application/did+json", body: []byte(`{}`), headers: map[string]string{"Content-Length": "513"}})
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			diagnostics: map[string]wantDiagnostic{
				RungDID: {attempted: true, failure: "DID resolved to no verification key"},
			},
		},
		{
			name: "a did:web redirect is refused and its target never requested",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.set("/bank/did.json", testRoute{status: 302, headers: map[string]string{"Location": f.origin.url() + "/moved/did.json"}})
				f.origin.json(t, "/moved/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
			check: func(t *testing.T, f *ladderFixture, _ *Resolution, _ error) {
				if f.origin.requested("/moved/did.json") != 0 {
					t.Errorf("redirect target was requested")
				}
			},
		},
		{
			name: "a did:web document naming another DID yields no DID key",
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				document := didWebDocument(t, didValue, "issuer-key-1", f.signer.public)
				document["id"] = f.origin.didWeb("other")
				f.origin.json(t, "/bank/did.json", document)
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantErr: ErrNoIssuerKeyResolved,
		},
	})
}

func TestInjectedDIDResolverReceivesTheDID(t *testing.T) {
	t.Parallel()
	signer := newES256Key(t, "")
	var resolved []string
	resolver := &Resolver{
		Mechanisms: allMechanisms(),
		DID: didResolverFunc(func(_ context.Context, didValue string) (*jose.JSONWebKeySet, error) {
			resolved = append(resolved, didValue)
			return keySet(signer.withKeyID(didValue+"#0", "")), nil
		}),
	}
	didValue := "did:key:zDnaeFake"
	resolution, err := resolver.Resolve(context.Background(), Request{
		Issuer: didValue, KeyID: didValue + "#0", Algorithm: "ES256",
		CredentialFormat: FormatJWTVCJSON, CredentialIssuer: "https://issuer.example.test",
		IssuerMetadataJWKS: keySet(signer.public),
	})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if !slices.Equal(resolved, []string{didValue}) {
		t.Errorf("resolved DIDs = %v", resolved)
	}
	if resolution.Candidates[0].Mechanism != MechanismDIDMetadataBinding {
		t.Errorf("first candidate = %v", resolution.Candidates[0].Mechanism)
	}
}

type didResolverFunc func(context.Context, string) (*jose.JSONWebKeySet, error)

func (f didResolverFunc) Resolve(ctx context.Context, didValue string) (*jose.JSONWebKeySet, error) {
	return f(ctx, didValue)
}

func TestVerificationMethodID(t *testing.T) {
	t.Parallel()
	const didValue = "did:web:issuer.example.test"
	tests := map[string]string{
		"":                              "",
		didValue + "#key-1":             didValue + "#key-1",
		"#key-1":                        didValue + "#key-1",
		"key-1":                         didValue + "#key-1",
		"did:web:other.example.test#k":  "",
		"https://issuer.example.test/k": "",
		`a\b`:                           "",
	}
	for kid, want := range tests {
		if got := verificationMethodID(didValue, kid); got != want {
			t.Errorf("verificationMethodID(%q) = %q, want %q", kid, got, want)
		}
	}
}
