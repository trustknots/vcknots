package x509

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// x5cTestChain builds an anchor, an intermediate and a leaf with the package's
// existing fixture helper, so decoding is exercised against certificates a
// path verification would also accept.
func x5cTestChain(t *testing.T) (leaf, intermediate, anchor signingTestIdentity) {
	t.Helper()
	anchor = newSigningTestCertificate(t, "x5c anchor", nil, true, nil)
	intermediate = newSigningTestCertificate(t, "x5c intermediate", &anchor, true, nil)
	leaf = newSigningTestCertificate(t, "x5c leaf", &intermediate, false, nil)
	return leaf, intermediate, anchor
}

func x5cTestEncode(certificates ...*x509.Certificate) []string {
	encoded := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	return encoded
}

func x5cTestAssertChain(t *testing.T, decoded []*x509.Certificate, expected ...*x509.Certificate) {
	t.Helper()
	if len(decoded) != len(expected) {
		t.Fatalf("decoded %d certificates, want %d", len(decoded), len(expected))
	}
	for index, certificate := range expected {
		if !bytes.Equal(decoded[index].Raw, certificate.Raw) {
			t.Fatalf("certificate %d is not the encoded DER", index)
		}
	}
}

func TestDecodeX5CChainAcceptsStandardBase64DER(t *testing.T) {
	leaf, intermediate, _ := x5cTestChain(t)
	encoded := x5cTestEncode(leaf.certificate, intermediate.certificate)

	decoded, err := DecodeX5CChain(encoded)
	if err != nil {
		t.Fatalf("[]string x5c: %v", err)
	}
	x5cTestAssertChain(t, decoded, leaf.certificate, intermediate.certificate)

	// A header read as map[string]any carries []any of strings.
	generic := make([]any, 0, len(encoded))
	for _, entry := range encoded {
		generic = append(generic, entry)
	}
	decoded, err = DecodeX5CChain(generic)
	if err != nil {
		t.Fatalf("[]any x5c: %v", err)
	}
	x5cTestAssertChain(t, decoded, leaf.certificate, intermediate.certificate)

	// RFC 7515 Section 4.1.6 mandates base64, not base64url: unpadded
	// base64url DER is rejected rather than repaired.
	url := []string{base64.RawURLEncoding.EncodeToString(leaf.certificate.Raw)}
	if _, err := DecodeX5CChain(url); err == nil {
		t.Fatal("base64url encoded DER must not decode as an x5c entry")
	}
	if _, err := DecodeX5CChain([]any{1}); err == nil {
		t.Fatal("a non-string x5c entry must be rejected")
	}
}

func TestDecodeX5CChainRejectsEmptyChain(t *testing.T) {
	for name, raw := range map[string]any{
		"absent":    nil,
		"strings":   []string{},
		"generic":   []any{},
		"not array": "MIIB",
	} {
		if _, err := DecodeX5CChain(raw); err == nil {
			t.Fatalf("%s x5c header must be rejected", name)
		}
	}
}

func TestDecodeX5CChainRejectsOversizeChain(t *testing.T) {
	leaf, _, _ := x5cTestChain(t)
	entry := base64.StdEncoding.EncodeToString(leaf.certificate.Raw)
	oversize := make([]string, maxX5CCertificates+1)
	for index := range oversize {
		oversize[index] = entry
	}
	_, err := DecodeX5CChain(oversize)
	if err == nil || !strings.Contains(err.Error(), "between 1 and 16 certificates") {
		t.Fatalf("err = %v, want the 1..16 bound", err)
	}
	if _, err := DecodeX5CChain(oversize[:maxX5CCertificates]); err != nil {
		t.Fatalf("a chain at the bound must decode: %v", err)
	}
}

// TestDecodeX5CFailuresClassifyAsErrX5CInvalid proves a caller can tell a
// malformed x5c apart from any other error with errors.Is, for the empty,
// oversize and bad-base64 cases.
func TestDecodeX5CFailuresClassifyAsErrX5CInvalid(t *testing.T) {
	leaf, _, _ := x5cTestChain(t)
	entry := base64.StdEncoding.EncodeToString(leaf.certificate.Raw)
	oversize := make([]string, maxX5CCertificates+1)
	for index := range oversize {
		oversize[index] = entry
	}

	for name, raw := range map[string]any{
		"empty":      []string{},
		"oversize":   oversize,
		"bad base64": []string{"not base64 !!"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeX5CChain(raw)
			if !errors.Is(err, ErrX5CInvalid) {
				t.Fatalf("DecodeX5CChain(%s) err = %v, want ErrX5CInvalid", name, err)
			}
		})
	}

	// The compact-JWS entry point shares the classification: a missing x5c
	// member and a header that is not base64url are both invalid x5c.
	for name, obj := range map[string]string{
		"missing header": base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + ".payload.signature",
		"bad base64":     "not-a-compact-jws",
	} {
		t.Run("jwt "+name, func(t *testing.T) {
			_, err := DecodeX5CFromJWTHeader(obj)
			if !errors.Is(err, ErrX5CInvalid) {
				t.Fatalf("DecodeX5CFromJWTHeader(%s) err = %v, want ErrX5CInvalid", name, err)
			}
		})
	}
}

func TestDecodeX5CFromJWTHeaderRejectsMissingHeader(t *testing.T) {
	leaf, intermediate, _ := x5cTestChain(t)
	compact := func(header map[string]any) string {
		raw, err := json.Marshal(header)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw) + ".eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.c2ln"
	}

	decoded, err := DecodeX5CFromJWTHeader(compact(map[string]any{
		"alg": "ES256", "x5c": x5cTestEncode(leaf.certificate, intermediate.certificate),
	}))
	if err != nil {
		t.Fatalf("signed object with x5c: %v", err)
	}
	x5cTestAssertChain(t, decoded, leaf.certificate, intermediate.certificate)

	if _, err := DecodeX5CFromJWTHeader(compact(map[string]any{"alg": "ES256"})); err == nil {
		t.Fatal("a protected header without x5c must be rejected")
	}
	if _, err := DecodeX5CFromJWTHeader("not-a-compact-jws"); err == nil {
		t.Fatal("a value that is not a compact JWS must be rejected")
	}
	if _, err := DecodeX5CFromJWTHeader("!!.payload.signature"); err == nil {
		t.Fatal("a protected header that is not base64url must be rejected")
	}
}

func TestIsSelfSignedDetectsSelfIssuedRoot(t *testing.T) {
	leaf, _, anchor := x5cTestChain(t)
	if !isSelfSigned(anchor.certificate) {
		t.Fatal("a self-issued anchor must be reported as self-signed")
	}
	if isSelfSigned(leaf.certificate) {
		t.Fatal("an issued leaf must not be reported as self-signed")
	}
	if isSelfSigned(nil) {
		t.Fatal("a missing certificate must not be reported as self-signed")
	}

	// Same subject DN, different key: self-issued by name only. The signature
	// check is what separates it from a genuine self-signed certificate.
	sameName := newSigningTestCertificate(t, "impostor", nil, true, nil)
	impostor := newSigningTestCertificate(t, "impostor", &sameName, false, nil)
	if !bytes.Equal(impostor.certificate.RawIssuer, impostor.certificate.RawSubject) {
		t.Fatal("fixture must share the subject and issuer DN")
	}
	if isSelfSigned(impostor.certificate) {
		t.Fatal("a certificate signed by another key with the same DN is not self-signed")
	}
}

func TestRequireNonSelfSignedLeafAcceptsIssuedLeaf(t *testing.T) {
	leaf, intermediate, anchor := x5cTestChain(t)
	if err := RequireNonSelfSignedLeaf([]*x509.Certificate{leaf.certificate, intermediate.certificate}, "wallet attestation"); err != nil {
		t.Fatalf("an issued leaf must be accepted: %v", err)
	}

	err := RequireNonSelfSignedLeaf([]*x509.Certificate{anchor.certificate}, "wallet attestation")
	if err == nil || !strings.Contains(err.Error(), "wallet attestation x5c leaf certificate must not be self-signed") {
		t.Fatalf("err = %v, want the labelled self-signed rejection", err)
	}
	if err := RequireNonSelfSignedLeaf(nil, "key attestation"); err == nil {
		t.Fatal("an absent chain must be rejected")
	}
	if err := RequireNonSelfSignedLeaf([]*x509.Certificate{nil}, "key attestation"); err == nil {
		t.Fatal("an empty leaf must be rejected")
	}
}

// TestRequireLeafThumbprintMatchesTheX509HashClientID pins the OpenID4VP 1.0
// Section 5.9.3 x509_hash value: the base64url-encoded SHA-256 of the DER.
func TestRequireLeafThumbprintMatchesTheX509HashClientID(t *testing.T) {
	leaf, _, _ := x5cTestChain(t)
	digest := sha256.Sum256(leaf.certificate.Raw)
	expected := base64.RawURLEncoding.EncodeToString(digest[:])

	if got := LeafThumbprintB64u(leaf.certificate); got != expected {
		t.Fatalf("LeafThumbprintB64u = %q, want %q", got, expected)
	}
	if err := RequireLeafThumbprint(leaf.certificate, expected); err != nil {
		t.Fatalf("matching thumbprint: %v", err)
	}
	// Standard base64 of the same digest, which a wallet must not accept in
	// place of the base64url encoding the section defines.
	if err := RequireLeafThumbprint(leaf.certificate, base64.StdEncoding.EncodeToString(digest[:])); err == nil {
		t.Fatal("standard base64 thumbprint was accepted")
	}
	if err := RequireLeafThumbprint(leaf.certificate, ""); err == nil {
		t.Fatal("empty x509_hash was accepted")
	}
	if err := RequireLeafThumbprint(nil, expected); !errors.Is(err, ErrX5CInvalid) {
		t.Fatalf("nil leaf error = %v, want ErrX5CInvalid", err)
	}
	if got := LeafThumbprintB64u(nil); got != "" {
		t.Fatalf("LeafThumbprintB64u(nil) = %q, want the empty string", got)
	}
}

// TestRequireLeafDNSNameMatchesSANsExactly pins the Client Identifier rule of
// OpenID4VP 1.0 Section 5.9.3: the DNS name must match a dNSName SAN entry of
// the leaf. Matching is case-insensitive (RFC 4343) and, with wildcard false,
// never widened by a wildcard SAN.
func TestRequireLeafDNSNameMatchesSANsExactly(t *testing.T) {
	leaf := newSigningTestCertificate(t, "dns leaf", nil, false, func(template *x509.Certificate) {
		template.DNSNames = []string{"Client.Example.Org", "*.wild.example"}
	})

	if err := RequireLeafDNSName(leaf.certificate, "client.example.org", false); err != nil {
		t.Fatalf("case-insensitive exact match: %v", err)
	}
	if err := RequireLeafDNSName(leaf.certificate, "client.example.org.", false); err != nil {
		t.Fatalf("absolute name with a trailing dot: %v", err)
	}
	for _, host := range []string{"other.example.org", "sub.client.example.org", "a.wild.example", "", "wild.example"} {
		if err := RequireLeafDNSName(leaf.certificate, host, false); err == nil {
			t.Fatalf("host %q matched without a dNSName SAN entry", host)
		}
	}
	if err := RequireLeafDNSName(nil, "client.example.org", false); !errors.Is(err, ErrX5CInvalid) {
		t.Fatalf("nil leaf error = %v, want ErrX5CInvalid", err)
	}
}

// TestRequireLeafDNSNameWildcardCoversOneLabel documents the opt-in RFC 6125
// Section 6.4.3 rule, which authenticates a TLS server name rather than a
// protocol identifier: the wildcard is the whole left-most label and matches
// exactly one label.
func TestRequireLeafDNSNameWildcardCoversOneLabel(t *testing.T) {
	leaf := newSigningTestCertificate(t, "wildcard leaf", nil, false, func(template *x509.Certificate) {
		template.DNSNames = []string{"*.wild.example"}
	})

	if err := RequireLeafDNSName(leaf.certificate, "a.wild.example", true); err != nil {
		t.Fatalf("single-label wildcard match: %v", err)
	}
	for _, host := range []string{"wild.example", "a.b.wild.example", "wild.example.org"} {
		if err := RequireLeafDNSName(leaf.certificate, host, true); err == nil {
			t.Fatalf("host %q matched the wildcard SAN", host)
		}
	}
	partial := newSigningTestCertificate(t, "partial wildcard leaf", nil, false, func(template *x509.Certificate) {
		template.DNSNames = []string{"a*.wild.example", "*"}
	})
	for _, host := range []string{"abc.wild.example", "example"} {
		if err := RequireLeafDNSName(partial.certificate, host, true); err == nil {
			t.Fatalf("host %q matched a partial or bare wildcard SAN", host)
		}
	}
}
