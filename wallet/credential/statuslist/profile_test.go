package statuslist

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/profile"
)

// issueCertificate issues a certificate for key under parent (self-signed
// when parent is nil) and returns it in x5c encoding.
func issueCertificate(t *testing.T, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool) (*x509.Certificate, string) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: fmt.Sprintf("status list test %v", ca)},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, base64.StdEncoding.EncodeToString(der)
}

// x5cHeader is the default header carrying chain as its x5c.
func x5cHeader(chain ...string) map[string]any {
	header := defaultHeader()
	entries := make([]any, 0, len(chain))
	for _, entry := range chain {
		entries = append(entries, entry)
	}
	header["x5c"] = entries
	return header
}

func haipChecker(h *harness, keys ...jose.JSONWebKey) *Checker {
	checker := h.checker(keys...)
	checker.Profile = profile.HAIP()
	return checker
}

// TestCheckReferenceAppliesTheHAIPStatusListTokenX5CRules covers HAIP 1.0
// Section 6.1: "The public key used to validate the signature on the Status
// List Token ... MUST be included in the x5c JOSE header of the Token. ...
// The X.509 certificate signing the request MUST NOT be self-signed."
func TestCheckReferenceAppliesTheHAIPStatusListTokenX5CRules(t *testing.T) {
	caKey := testutil.NewP256Key(t)
	ca, _ := issueCertificate(t, caKey, nil, nil, true)

	t.Run("a token whose leaf carries the verifying key is read", func(t *testing.T) {
		h := newHarness(t)
		_, leaf := issueCertificate(t, h.key, ca, caKey, false)
		h.serveToken(signES256(t, h.key, x5cHeader(leaf), defaultClaims(h.uri)))
		var rules profile.X5CRules
		checker := haipChecker(h)
		checker.ResolveIssuerKeys = func(_ context.Context, request KeyRequest) ([]jose.JSONWebKey, error) {
			rules = request.X5C
			return []jose.JSONWebKey{publicJWK(h.key, "key-1")}, nil
		}
		if _, err := checker.CheckReference(context.Background(), testIssuer, h.reference(0)); err != nil {
			t.Fatal(err)
		}
		if rules != profile.HAIPOptions().StatusListTokenX5C {
			t.Fatalf("hook was given X5C = %+v", rules)
		}
	})

	t.Run("a token without x5c is refused before any key is resolved", func(t *testing.T) {
		h := newHarness(t)
		h.serveToken(signES256(t, h.key, defaultHeader(), defaultClaims(h.uri)))
		_, err := haipChecker(h).CheckReference(context.Background(), testIssuer, h.reference(0))
		assertSentinel(t, err, ErrStatusListCertificateRejected)
		if h.hookCalls.Load() != 0 {
			t.Fatal("the key resolution hook ran")
		}
	})

	t.Run("a self-signed leaf is refused before any key is resolved", func(t *testing.T) {
		h := newHarness(t)
		_, selfSigned := issueCertificate(t, h.key, nil, nil, false)
		h.serveToken(signES256(t, h.key, x5cHeader(selfSigned), defaultClaims(h.uri)))
		_, err := haipChecker(h).CheckReference(context.Background(), testIssuer, h.reference(0))
		assertSentinel(t, err, ErrStatusListCertificateRejected)
		if !strings.Contains(err.Error(), "self-signed") || h.hookCalls.Load() != 0 {
			t.Fatalf("err = %v, hook ran %d times", err, h.hookCalls.Load())
		}
	})

	t.Run("a malformed x5c is refused", func(t *testing.T) {
		h := newHarness(t)
		h.serveToken(signES256(t, h.key, x5cHeader("not base64 DER"), defaultClaims(h.uri)))
		_, err := haipChecker(h).CheckReference(context.Background(), testIssuer, h.reference(0))
		assertSentinel(t, err, ErrStatusListCertificateRejected)
	})

	t.Run("a verifying key that is not the x5c leaf's is refused", func(t *testing.T) {
		// The token is signed by h.key, which the hook returns (from issuer
		// metadata, say), but the x5c leaf certifies another key.
		h := newHarness(t)
		_, leaf := issueCertificate(t, testutil.NewP256Key(t), ca, caKey, false)
		h.serveToken(signES256(t, h.key, x5cHeader(leaf), defaultClaims(h.uri)))
		_, err := haipChecker(h).CheckReference(context.Background(), testIssuer, h.reference(0))
		assertSentinel(t, err, ErrStatusListCertificateRejected)
		if !strings.Contains(err.Error(), "leaf") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a hook's anchor refusal is reported as a certificate rejection", func(t *testing.T) {
		h := newHarness(t)
		_, leaf := issueCertificate(t, h.key, ca, caKey, false)
		h.serveToken(signES256(t, h.key, x5cHeader(leaf), defaultClaims(h.uri)))
		checker := haipChecker(h)
		refusal := fmt.Errorf("%w: the chain includes a trust anchor", ErrStatusListCertificateRejected)
		checker.ResolveIssuerKeys = func(context.Context, KeyRequest) ([]jose.JSONWebKey, error) { return nil, refusal }
		_, err := checker.CheckReference(context.Background(), testIssuer, h.reference(0))
		assertSentinel(t, err, ErrStatusListCertificateRejected)
		if !errors.Is(err, refusal) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("the Final profile leaves x5c to the hook", func(t *testing.T) {
		h := newHarness(t)
		_, selfSigned := issueCertificate(t, h.key, nil, nil, false)
		h.serveToken(signES256(t, h.key, x5cHeader(selfSigned), defaultClaims(h.uri)))
		if _, err := h.checker().CheckReference(context.Background(), testIssuer, h.reference(0)); err != nil {
			t.Fatal(err)
		}
		h2 := newHarness(t)
		h2.serveToken(signES256(t, h2.key, defaultHeader(), defaultClaims(h2.uri)))
		if _, err := h2.checker().CheckReference(context.Background(), testIssuer, h2.reference(0)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Final with only StatusListTokenX5C applies the rules", func(t *testing.T) {
		withRules, err := profile.Final().With(profile.Options{StatusListTokenX5C: profile.X5CRules{Require: true}})
		if err != nil {
			t.Fatal(err)
		}
		h := newHarness(t)
		h.serveToken(signES256(t, h.key, defaultHeader(), defaultClaims(h.uri)))
		checker := h.checker()
		checker.Profile = withRules
		_, err = checker.CheckReference(context.Background(), testIssuer, h.reference(0))
		assertSentinel(t, err, ErrStatusListCertificateRejected)
	})
}

// TestCheckReferenceForbidsCleartextUnderAProfileThatForbidsIt covers
// profile.Options.ForbidExperimental (HAIP 1.0 Section 4): the
// experimental transport is a test-only escape the profile refuses rather than
// ignores, for an https reference too, and before anything is fetched.
func TestCheckReferenceForbidsCleartextUnderAProfileThatForbidsIt(t *testing.T) {
	for name, uri := range map[string]func(h *harness) string{
		"http reference":  func(*harness) string { return "http://issuer.example.test/status/1" },
		"https reference": func(h *harness) string { return h.reference(0).URI },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			checker := haipChecker(h)
			checker.Experimental = experimental.Transport{AllowHTTP: true}
			_, err := checker.CheckReference(context.Background(), testIssuer, Reference{URI: uri(h)})
			assertSentinel(t, err, ErrStatusListInsecureTransportForbidden)
			var refused *profile.OptionError
			if !errors.As(err, &refused) || refused.Option != "ForbidExperimental" {
				t.Fatalf("the refusal does not name ForbidExperimental: %v", err)
			}
			if h.requests.Load() != 0 {
				t.Fatal("the endpoint was requested")
			}
		})
	}
}

// TestCheckReferencePassesTheTransportRuleToTheHook: a hook learns that the
// profile forbids experimental transports, and its refusal keeps its sentinel.
func TestCheckReferencePassesTheTransportRuleToTheHook(t *testing.T) {
	caKey := testutil.NewP256Key(t)
	ca, _ := issueCertificate(t, caKey, nil, nil, true)
	h := newHarness(t)
	_, leaf := issueCertificate(t, h.key, ca, caKey, false)
	h.serveToken(signES256(t, h.key, x5cHeader(leaf), defaultClaims(h.uri)))
	checker := haipChecker(h)
	var seen KeyRequest
	checker.ResolveIssuerKeys = func(_ context.Context, request KeyRequest) ([]jose.JSONWebKey, error) {
		seen = request
		return nil, fmt.Errorf("%w: resolver relaxes http", ErrStatusListInsecureTransportForbidden)
	}
	_, err := checker.CheckReference(context.Background(), testIssuer, h.reference(0))
	assertSentinel(t, err, ErrStatusListInsecureTransportForbidden)
	if !seen.ForbidExperimental {
		t.Fatal("the hook was not told the profile forbids experimental transports")
	}
}
