package x509

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"
)

var signingTestTime = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

type signingTestIdentity struct {
	certificate *x509.Certificate
	key         crypto.Signer
}

// Certificates are signed independently with the standard library: Ed25519
// CAs certify an ECDSA signing leaf. No production path helper builds fixtures.
func newSigningTestCertificate(t *testing.T, name string, parent *signingTestIdentity, ca bool, change func(*x509.Certificate)) signingTestIdentity {
	t.Helper()
	var key crypto.Signer
	if ca {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = private
	} else {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = private
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: signingTestTime.Add(-time.Hour), NotAfter: signingTestTime.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: ca, MaxPathLen: -1,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.DNSNames = []string{"signer.example"}
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	if change != nil {
		change(template)
	}
	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent.certificate, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return signingTestIdentity{certificate: certificate, key: key}
}

type signingTestNoNetwork struct{ t *testing.T }

func (transport signingTestNoNetwork) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.t.Errorf("unexpected network request before trust or above the anchor: %s", request.URL)
	return nil, errors.New("network must not be used by this fixture")
}

func signingTestOptions(t *testing.T, anchors ...*x509.Certificate) SigningChainOptions {
	t.Helper()
	checker, err := NewCRLChecker(CRLCheckerOptions{
		HTTPClient: &http.Client{Transport: signingTestNoNetwork{t}}, RequireStatus: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return SigningChainOptions{TrustAnchors: anchors, CurrentTime: signingTestTime, Revocation: checker}
}

func assertSigningTestPath(t *testing.T, result *SigningChainResult, expected ...*x509.Certificate) {
	t.Helper()
	if result == nil || len(result.Chain) != len(expected) || len(result.Fingerprints) != len(expected) {
		t.Fatalf("result = %#v, want %d certificates and fingerprints", result, len(expected))
	}
	for index, certificate := range expected {
		if !bytes.Equal(result.Chain[index].Raw, certificate.Raw) {
			t.Fatalf("chain[%d] does not contain the expected signed certificate", index)
		}
		digest := sha256.Sum256(certificate.Raw)
		if result.Fingerprints[index] != hex.EncodeToString(digest[:]) {
			t.Fatalf("fingerprint[%d] is not SHA-256 of the original DER", index)
		}
	}
	if result.Revocation.CheckedCertificates != 0 || result.Revocation.NoMechanismCertificates != len(expected)-1 {
		t.Fatalf("no-mechanism certificates must not be described as checked: %#v", result.Revocation)
	}
}

func TestVerifySigningCertificateChainMixedAlgorithmsAndRootPolicies(t *testing.T) {
	root := newSigningTestCertificate(t, "Root", nil, true, nil)
	issuer := newSigningTestCertificate(t, "Issuer", &root, true, nil)
	leaf := newSigningTestCertificate(t, "Signer", &issuer, false, nil)
	for _, source := range []string{"anchors", "pool"} {
		t.Run(source, func(t *testing.T) {
			options := signingTestOptions(t, root.certificate)
			if source == "pool" {
				options.TrustAnchors = nil
				options.Roots = x509.NewCertPool()
				options.Roots.AddCert(root.certificate)
			}
			result, err := VerifySigningCertificateChain(context.Background(), []*x509.Certificate{leaf.certificate, issuer.certificate}, options)
			if err != nil {
				t.Fatal(err)
			}
			assertSigningTestPath(t, result, leaf.certificate, issuer.certificate, root.certificate)
		})
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageServerAuth} {
		t.Run(fmt.Sprintf("explicit-EKU-%d", usage), func(t *testing.T) {
			options := signingTestOptions(t, root.certificate)
			options.KeyUsages = []x509.ExtKeyUsage{usage}
			result, err := VerifySigningCertificateChain(context.Background(), []*x509.Certificate{leaf.certificate, issuer.certificate}, options)
			if usage == x509.ExtKeyUsageCodeSigning {
				if err != nil {
					t.Fatal(err)
				}
				assertSigningTestPath(t, result, leaf.certificate, issuer.certificate, root.certificate)
			} else if err == nil || result != nil {
				t.Fatalf("incompatible EKU accepted: %#v, %v", result, err)
			}
		})
	}
}

func TestVerifySigningCertificateChainRejectsUntrustedOrInvalidCertificates(t *testing.T) {
	for _, scenario := range []string{
		"untrusted-root", "self-signed-leaf", "self-signed-leaf-explicitly-trusted", "CA-leaf",
		"leaf-no-digital-signature", "issuer-no-key-cert-sign", "expired-leaf", "expired-issuer",
		"unknown-critical-leaf", "unknown-critical-issuer", "missing-issuer", "wrong-issuer-key", "invalid-leaf-signature",
	} {
		t.Run(scenario, func(t *testing.T) {
			critical := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 99}, Critical: true, Value: []byte{5, 0}}
			root := newSigningTestCertificate(t, "Root", nil, true, nil)
			issuer := newSigningTestCertificate(t, "Issuer", &root, true, func(c *x509.Certificate) {
				switch scenario {
				case "issuer-no-key-cert-sign":
					c.KeyUsage = x509.KeyUsageCRLSign
				case "expired-issuer":
					c.NotAfter = signingTestTime.Add(-time.Minute)
				case "unknown-critical-issuer":
					c.ExtraExtensions = []pkix.Extension{critical}
				}
			})
			leaf := newSigningTestCertificate(t, "Signer", &issuer, false, func(c *x509.Certificate) {
				switch scenario {
				case "leaf-no-digital-signature":
					c.KeyUsage = x509.KeyUsageKeyEncipherment
				case "expired-leaf":
					c.NotAfter = signingTestTime.Add(-time.Minute)
				case "unknown-critical-leaf":
					c.ExtraExtensions = []pkix.Extension{critical}
				}
			})
			options := signingTestOptions(t, root.certificate)
			switch scenario {
			case "untrusted-root":
				otherRoot := newSigningTestCertificate(t, "Root", nil, true, nil)
				options.TrustAnchors = []*x509.Certificate{otherRoot.certificate}
			case "self-signed-leaf", "self-signed-leaf-explicitly-trusted":
				leaf = newSigningTestCertificate(t, "Signer", nil, false, nil)
				if scenario == "self-signed-leaf-explicitly-trusted" {
					options.TrustAnchors = []*x509.Certificate{leaf.certificate}
				}
			case "CA-leaf":
				leaf = issuer
			case "wrong-issuer-key":
				issuer = newSigningTestCertificate(t, "Issuer", &root, true, nil)
			case "invalid-leaf-signature":
				der := append([]byte(nil), leaf.certificate.Raw...)
				der[len(der)-1] ^= 1
				var err error
				leaf.certificate, err = x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
			}
			certificates := []*x509.Certificate{leaf.certificate, issuer.certificate, root.certificate}
			if scenario == "missing-issuer" {
				certificates = []*x509.Certificate{leaf.certificate, root.certificate}
			}
			result, err := VerifySigningCertificateChain(context.Background(), certificates, options)
			if err == nil || result != nil {
				t.Fatalf("invalid signing chain accepted: %#v, %v", result, err)
			}
			var structured *SigningChainError
			if !errors.As(err, &structured) || (structured.Kind != "certificate" && structured.Kind != "path") {
				t.Fatalf("certificate/path failure lost its classification: %v", err)
			}
			// Only a chain with no valid path to a configured anchor is
			// ErrNoTrustAnchor; a certificate that is itself unacceptable is not.
			noAnchor := map[string]bool{
				"untrusted-root": true, "missing-issuer": true, "wrong-issuer-key": true,
				"invalid-leaf-signature": true, "issuer-no-key-cert-sign": true,
			}[scenario]
			if got := errors.Is(err, ErrNoTrustAnchor); got != noAnchor {
				t.Fatalf("errors.Is(err, ErrNoTrustAnchor) = %v, want %v: %v", got, noAnchor, err)
			}
		})
	}
}

func TestVerifySigningCertificateChainStopsAtNearestAnchor(t *testing.T) {
	root := newSigningTestCertificate(t, "Expired upper root", nil, true, func(c *x509.Certificate) {
		c.NotAfter = signingTestTime.Add(-time.Minute)
		c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 99}, Critical: true, Value: []byte{5, 0}}}
		c.CRLDistributionPoints = []string{"https://upper.invalid/root.crl"}
	})
	issuer := newSigningTestCertificate(t, "Trusted issuer", &root, true, func(c *x509.Certificate) {
		c.CRLDistributionPoints = []string{"https://upper.invalid/issuer.crl"}
	})
	leaf := newSigningTestCertificate(t, "Signer", &issuer, false, nil)
	options := signingTestOptions(t, root.certificate, issuer.certificate)
	result, err := VerifySigningCertificateChain(context.Background(), []*x509.Certificate{leaf.certificate, issuer.certificate, root.certificate}, options)
	if err != nil {
		t.Fatal(err)
	}
	assertSigningTestPath(t, result, leaf.certificate, issuer.certificate)
}

func TestVerifySigningCertificateChainPreservesNameConstraints(t *testing.T) {
	root := newSigningTestCertificate(t, "Root", nil, true, nil)
	issuer := newSigningTestCertificate(t, "Constrained issuer", &root, true, func(c *x509.Certificate) {
		c.PermittedDNSDomainsCritical = true
		c.PermittedDNSDomains = []string{"permitted.example"}
	})
	for _, name := range []string{"signer.permitted.example", "signer.other.example"} {
		t.Run(name, func(t *testing.T) {
			leaf := newSigningTestCertificate(t, "Signer", &issuer, false, func(c *x509.Certificate) { c.DNSNames = []string{name} })
			result, err := VerifySigningCertificateChain(context.Background(), []*x509.Certificate{leaf.certificate, issuer.certificate}, signingTestOptions(t, root.certificate))
			if name == "signer.permitted.example" {
				if err != nil {
					t.Fatal(err)
				}
				assertSigningTestPath(t, result, leaf.certificate, issuer.certificate, root.certificate)
			} else {
				var invalid x509.CertificateInvalidError
				if result != nil || !errors.As(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
					t.Fatalf("name constraint was not retained: %#v, %v", result, err)
				}
			}
		})
	}
}

func TestVerifySigningCertificateChainCountsOnlyNonSelfIssuedCAs(t *testing.T) {
	for _, selfIssued := range []bool{true, false} {
		for _, source := range []string{"anchors", "pool"} {
			t.Run(fmt.Sprintf("self-issued=%t/%s", selfIssued, source), func(t *testing.T) {
				root := newSigningTestCertificate(t, "Root", nil, true, func(c *x509.Certificate) { c.MaxPathLen = 1 })
				old := newSigningTestCertificate(t, "Rollover issuer", &root, true, func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 0, true })
				name := "Subordinate issuer"
				if selfIssued {
					name = "Rollover issuer"
				}
				newIssuer := newSigningTestCertificate(t, name, &old, true, func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 0, true })
				leaf := newSigningTestCertificate(t, "Signer", &newIssuer, false, nil)
				if bytes.Equal(newIssuer.certificate.RawSubject, newIssuer.certificate.RawIssuer) != selfIssued {
					t.Fatal("fixture did not encode the intended issuer/subject relationship")
				}
				if err := newIssuer.certificate.CheckSignatureFrom(newIssuer.certificate); err == nil {
					t.Fatal("rollover fixture must use a different key, not be self-signed")
				}
				options := signingTestOptions(t, root.certificate)
				if source == "pool" {
					options.TrustAnchors = nil
					options.Roots = x509.NewCertPool()
					options.Roots.AddCert(root.certificate)
				}
				result, err := VerifySigningCertificateChain(context.Background(), []*x509.Certificate{leaf.certificate, newIssuer.certificate, old.certificate}, options)
				if selfIssued && source == "anchors" {
					if err != nil {
						t.Fatal(err)
					}
					assertSigningTestPath(t, result, leaf.certificate, newIssuer.certificate, old.certificate, root.certificate)
				} else {
					var invalid x509.CertificateInvalidError
					if result != nil || !errors.As(err, &invalid) || invalid.Reason != x509.TooManyIntermediates {
						t.Fatalf("expected original path-length policy (or documented legacy-pool limitation): %#v, %v", result, err)
					}
				}
				if root.certificate.MaxPathLen != 1 || old.certificate.MaxPathLen != 0 || !old.certificate.MaxPathLenZero || newIssuer.certificate.MaxPathLen != 0 || !newIssuer.certificate.MaxPathLenZero {
					t.Fatal("verification mutated the caller's certificate constraints")
				}
			})
		}
	}
}

func TestVerifySigningCertificateChainRequiresExplicitConfiguration(t *testing.T) {
	root := newSigningTestCertificate(t, "Root", nil, true, nil)
	leaf := newSigningTestCertificate(t, "Signer", &root, false, nil)
	for _, scenario := range []string{"no-trust", "both-trust-sources", "no-time", "no-revocation", "nil-context"} {
		t.Run(scenario, func(t *testing.T) {
			options := signingTestOptions(t, root.certificate)
			ctx := context.Background()
			switch scenario {
			case "no-trust":
				options.TrustAnchors = nil
			case "both-trust-sources":
				options.Roots = x509.NewCertPool()
			case "no-time":
				options.CurrentTime = time.Time{}
			case "no-revocation":
				options.Revocation = nil
			case "nil-context":
				ctx = nil
			}
			result, err := VerifySigningCertificateChain(ctx, []*x509.Certificate{leaf.certificate}, options)
			var structured *SigningChainError
			if result != nil || !errors.As(err, &structured) || structured.Kind != "configuration" {
				t.Fatalf("invalid configuration did not fail explicitly: %#v, %v", result, err)
			}
		})
	}
}

// TestVerifySigningChainWithPolicyDerivesRevocationStrictness pins the exported
// policy entry point: RequireStatus is derived from AllowUnadvertisedRevocation,
// a chain to an unconfigured anchor is refused, and setting the contradicting
// policy pair is a configuration error.
func TestVerifySigningChainWithPolicyDerivesRevocationStrictness(t *testing.T) {
	root := newSigningTestCertificate(t, "Root", nil, true, nil)
	issuer := newSigningTestCertificate(t, "Issuer", &root, true, nil)
	leaf := newSigningTestCertificate(t, "Signer", &issuer, false, nil)
	chain := []*x509.Certificate{leaf.certificate, issuer.certificate}

	t.Run("trusted-chain-with-unadvertised-revocation", func(t *testing.T) {
		result, err := VerifySigningChainWithPolicy(context.Background(), chain, SigningChainPolicy{
			TrustAnchors:                []*x509.Certificate{root.certificate},
			CurrentTime:                 signingTestTime,
			AllowUnadvertisedRevocation: true,
			HTTPClient:                  &http.Client{Transport: signingTestNoNetwork{t}},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertSigningTestPath(t, result, leaf.certificate, issuer.certificate, root.certificate)
	})
	t.Run("revocation-required-but-unadvertised", func(t *testing.T) {
		result, err := VerifySigningChainWithPolicy(context.Background(), chain, SigningChainPolicy{
			TrustAnchors: []*x509.Certificate{root.certificate},
			CurrentTime:  signingTestTime,
			HTTPClient:   &http.Client{Transport: signingTestNoNetwork{t}},
		})
		if err == nil || result != nil {
			t.Fatalf("chain without a revocation mechanism accepted under RequireStatus: %#v, %v", result, err)
		}
	})
	t.Run("untrusted-anchor", func(t *testing.T) {
		otherRoot := newSigningTestCertificate(t, "OtherRoot", nil, true, nil)
		_, err := VerifySigningChainWithPolicy(context.Background(), chain, SigningChainPolicy{
			TrustAnchors:                []*x509.Certificate{otherRoot.certificate},
			CurrentTime:                 signingTestTime,
			AllowUnadvertisedRevocation: true,
			HTTPClient:                  &http.Client{Transport: signingTestNoNetwork{t}},
		})
		if err == nil {
			t.Fatal("chain to an unconfigured anchor was accepted")
		}
	})
	t.Run("conflicting-revocation-policies", func(t *testing.T) {
		_, err := VerifySigningChainWithPolicy(context.Background(), chain, SigningChainPolicy{
			TrustAnchors:                []*x509.Certificate{root.certificate},
			CurrentTime:                 signingTestTime,
			AllowUnadvertisedRevocation: true,
			CRL:                         CRLCheckerOptions{RequireStatus: true, HTTPClient: &http.Client{Transport: signingTestNoNetwork{t}}},
		})
		if err == nil {
			t.Fatal("CRL.RequireStatus=true with AllowUnadvertisedRevocation=true was accepted")
		}
	})
}
