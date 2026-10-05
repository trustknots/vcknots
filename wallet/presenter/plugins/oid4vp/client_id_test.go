package oid4vp

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// TestParseOID4VPClientIDExported pins the exported Client Identifier parse an
// application reads a Client Identifier Prefix with, including the two prefixes
// only the Wallet itself may mint.
func TestParseOID4VPClientIDExported(t *testing.T) {
	testCases := []struct {
		name       string
		clientID   string
		wantPrefix OID4VPClientIDPrefix
		wantOrigin string
		wantSigned bool
	}{
		{name: "x509 san dns", clientID: "x509_san_dns:verifier.example", wantPrefix: OID4VPClientIDPrefixX509SanDNS, wantOrigin: "verifier.example", wantSigned: true},
		{name: "x509 hash", clientID: "x509_hash:abcd", wantPrefix: OID4VPClientIDPrefixX509Hash, wantOrigin: "abcd", wantSigned: true},
		{name: "redirect uri", clientID: "redirect_uri:https://verifier.example/cb", wantPrefix: OID4VPClientIDPrefixRedirectURI, wantOrigin: "https://verifier.example/cb"},
		{name: "federation", clientID: "openid_federation:https://verifier.example", wantPrefix: OID4VPClientIDPrefixOIDFederation, wantOrigin: "https://verifier.example", wantSigned: true},
		{name: "pre registered", clientID: "known-verifier", wantPrefix: OID4VPClientIDPrefixPreRegistered, wantOrigin: "known-verifier"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := ParseOID4VPClientID(testCase.clientID)
			if err != nil {
				t.Fatalf("ParseOID4VPClientID(%q) failed: %v", testCase.clientID, err)
			}
			if parsed.Prefix() != testCase.wantPrefix {
				t.Fatalf("prefix = %q, want %q", parsed.Prefix(), testCase.wantPrefix)
			}
			if parsed.Original() != testCase.wantOrigin {
				t.Fatalf("original = %q, want %q", parsed.Original(), testCase.wantOrigin)
			}
			if parsed.RequiresRequestObjectSignature() != testCase.wantSigned {
				t.Fatalf("RequiresRequestObjectSignature() = %v, want %v", parsed.RequiresRequestObjectSignature(), testCase.wantSigned)
			}
		})
	}
}

// TestParseDraft24OID4VPClientIDExported pins the Draft24 wire syntax: a
// whole https URL is an OpenID Federation Entity Identifier, and every other
// Client Identifier parses exactly as ParseOID4VPClientID parses it.
func TestParseDraft24OID4VPClientIDExported(t *testing.T) {
	parsed, err := ParseDraft24OID4VPClientID("https://verifier.example")
	if err != nil {
		t.Fatalf("ParseDraft24OID4VPClientID failed: %v", err)
	}
	if parsed.Prefix() != OID4VPClientIDPrefixOIDFederation || parsed.Original() != "https://verifier.example" {
		t.Fatalf("parsed = %q %q, want the Federation Entity Identifier", parsed.Prefix(), parsed.Original())
	}
	if _, err := ParseOID4VPClientID("https://verifier.example"); err == nil {
		t.Fatal("the Final syntax must not accept a bare https Client Identifier")
	}
	parsed, err = ParseDraft24OID4VPClientID("x509_san_dns:verifier.example")
	if err != nil || parsed.Prefix() != OID4VPClientIDPrefixX509SanDNS {
		t.Fatalf("Draft24 x509_san_dns = %v, %v", parsed, err)
	}
	parsed, err = ParseDraft24OID4VPClientID("registered-verifier")
	if err != nil || parsed.Prefix() != OID4VPClientIDPrefixPreRegistered {
		t.Fatalf("Draft24 pre-registered = %v, %v", parsed, err)
	}
	if _, err := ParseDraft24OID4VPClientID("web-origin:https://verifier.example"); !errors.Is(err, ErrClientIDPrefixReserved) {
		t.Fatalf("Draft24 web-origin error = %v, want ErrClientIDPrefixReserved", err)
	}
}

// TestParseDraft24OID4VPClientIDAcceptsOnlyDraft24Schemes covers Draft 24
// §5.10.4: the OpenID4VP 1.0 prefixes are not Draft 24 schemes, and the did and
// x509_san_uri schemes Draft 24 defines are refused as unsupported.
func TestParseDraft24OID4VPClientIDAcceptsOnlyDraft24Schemes(t *testing.T) {
	for _, clientID := range []string{
		"x509_hash:YWJj", "decentralized_identifier:did:example:123",
		"openid_federation:https://verifier.example", "origin:https://verifier.example",
	} {
		if _, err := ParseDraft24OID4VPClientID(clientID); err == nil || !strings.Contains(err.Error(), "not a Draft 24 Client Identifier Scheme") {
			t.Fatalf("ParseDraft24OID4VPClientID(%q) error = %v, want a refusal of a non-Draft 24 scheme", clientID, err)
		}
	}
	for _, clientID := range []string{"did:example:123", "x509_san_uri:https://verifier.example/cb"} {
		if _, err := ParseDraft24OID4VPClientID(clientID); !errors.Is(err, ErrRequestObjectClientAuthUnsupported) {
			t.Fatalf("ParseDraft24OID4VPClientID(%q) error = %v, want ErrRequestObjectClientAuthUnsupported", clientID, err)
		}
	}
}

// TestParseOID4VPClientIDReservedPrefixes keeps the reserved origin prefix
// (§5.9.3) refused with a code a caller can branch on. web-origin is not an
// OpenID4VP 1.0 prefix at all, and the Wallet never mints one.
func TestParseOID4VPClientIDReservedPrefixes(t *testing.T) {
	if _, err := ParseOID4VPClientID("origin:https://verifier.example"); !errors.Is(err, ErrClientIDPrefixReserved) {
		t.Fatalf("ParseOID4VPClientID(origin) error = %v, want ErrClientIDPrefixReserved", err)
	}
	if _, err := ParseOID4VPClientID("web-origin:https://verifier.example"); err == nil || !strings.Contains(err.Error(), "is not a supported Client Identifier Prefix") {
		t.Fatalf("ParseOID4VPClientID(web-origin) error = %v, want an unknown prefix", err)
	}
}

// TestParseOID4VPClientIDUnknownPrefix keeps an unknown prefix a plain syntax
// error rather than the reserved-prefix verdict.
func TestParseOID4VPClientIDUnknownPrefix(t *testing.T) {
	_, err := ParseOID4VPClientID("made_up:value")
	if err == nil {
		t.Fatal("expected an error for an unsupported Client Identifier Prefix")
	}
	if errors.Is(err, ErrClientIDPrefixReserved) {
		t.Fatalf("unsupported prefix reported as reserved: %v", err)
	}
}

// TestDraft24QueryParamX509ClientIDRefused is the Draft24 half of the OID4VP
// 1.0 §5.9.3 rule the Final parser already applied: an X.509 Client Identifier
// carried in plain query parameters has no signature to authenticate it.
func TestDraft24QueryParamX509ClientIDRefused(t *testing.T) {
	presenter := &Oid4vpPresenter{}
	for _, clientID := range []string{"x509_san_dns:verifier.example", "verifier_attestation:verifier.example"} {
		request := "openid4vp://?response_type=vp_token&client_id=" + clientID +
			"&response_mode=direct_post&response_uri=https://verifier.example/response&nonce=n"
		_, err := parseDraft24ForTest(presenter, request)
		if !errors.Is(err, ErrRequestObjectSignatureRequired) {
			t.Fatalf("ParseDraft24Request(%q) error = %v, want ErrRequestObjectSignatureRequired", clientID, err)
		}
	}
}

// TestFinalQueryParamX509ClientIDRefused keeps the Final parser reporting the
// same condition with the same code.
func TestFinalQueryParamX509ClientIDRefused(t *testing.T) {
	presenter := &Oid4vpPresenter{}
	for _, clientID := range []string{"x509_san_dns:verifier.example", "verifier_attestation:verifier.example"} {
		request := "openid4vp://?response_type=vp_token&client_id=" + clientID +
			"&response_mode=direct_post&response_uri=https://verifier.example/response&nonce=n"
		_, err := presenter.ParsePresentationRequest(request)
		if !errors.Is(err, ErrRequestObjectSignatureRequired) {
			t.Fatalf("ParsePresentationRequest(%q) error = %v, want ErrRequestObjectSignatureRequired", clientID, err)
		}
	}
}

// TestVerifierAttestationRequiresRequestObjectSignature: OID4VP 1.0 Section
// 5.9.3 has the Verifier sign the Request Object with the key its attestation
// confirms, so the identifier authenticates only a signed request.
func TestVerifierAttestationRequiresRequestObjectSignature(t *testing.T) {
	clientID, err := ParseOID4VPClientID("verifier_attestation:verifier.example")
	if err != nil {
		t.Fatal(err)
	}
	if !clientID.RequiresRequestObjectSignature() {
		t.Fatal("verifier_attestation must require a signed Request Object")
	}
	redirect, err := ParseOID4VPClientID("redirect_uri:https://verifier.example/cb")
	if err != nil {
		t.Fatal(err)
	}
	if redirect.RequiresRequestObjectSignature() {
		t.Fatal("redirect_uri must not require a signed Request Object")
	}
}

// TestMissingNonceNamesItsSentinel: OpenID4VP 1.0 Section 5.2 makes nonce
// REQUIRED, and the refusal is branchable with errors.Is on both wires and
// for a signed Request Object.
func TestMissingNonceNamesItsSentinel(t *testing.T) {
	presenter := &Oid4vpPresenter{}
	final := "openid4vp://?response_type=vp_token&client_id=redirect_uri:https://verifier.example/cb" +
		"&response_mode=fragment&dcql_query=" + url.QueryEscape(finalDcqlParam)
	if _, err := presenter.ParsePresentationRequest(final); !errors.Is(err, ErrNonceRequired) {
		t.Fatalf("Final error = %v, want ErrNonceRequired", err)
	}
	draft24 := "openid4vp://?response_type=vp_token&client_id=redirect_uri:https://verifier.example/cb" +
		"&response_mode=fragment&presentation_definition=" + url.QueryEscape(`{"id":"definition"}`)
	if _, err := parseDraft24ForTest(presenter, draft24); !errors.Is(err, ErrNonceRequired) {
		t.Fatalf("Draft24 error = %v, want ErrNonceRequired", err)
	}

	f := newRequestObjectFixture(t)
	claims := f.claims()
	delete(claims, "nonce")
	if _, err := f.parse(t, claims); !errors.Is(err, ErrNonceRequired) {
		t.Fatalf("Request Object error = %v, want ErrNonceRequired", err)
	}
}
