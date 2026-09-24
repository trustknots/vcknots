package x509

import (
	"crypto/x509"
	"testing"
	"time"
)

func anchorTestContains(t *testing.T, chain []*x509.Certificate, anchors []*x509.Certificate, roots *x509.CertPool) bool {
	t.Helper()
	contains, err := ContainsTrustAnchor(chain, anchors, roots)
	if err != nil {
		t.Fatalf("ContainsTrustAnchor: %v", err)
	}
	return contains
}

func TestContainsTrustAnchorWithExplicitAnchors(t *testing.T) {
	leaf, intermediate, anchor := x5cTestChain(t)
	other := newSigningTestCertificate(t, "unrelated anchor", nil, true, nil)
	full := []*x509.Certificate{leaf.certificate, intermediate.certificate, anchor.certificate}

	if !anchorTestContains(t, full, []*x509.Certificate{anchor.certificate}, nil) {
		t.Fatal("an anchor carried in x5c must be detected")
	}
	// A nil entry in the configured set is skipped, not dereferenced.
	if !anchorTestContains(t, full, []*x509.Certificate{nil, other.certificate, anchor.certificate}, nil) {
		t.Fatal("a nil anchor must not hide a configured one")
	}
	if anchorTestContains(t, full, []*x509.Certificate{other.certificate}, nil) {
		t.Fatal("an unrelated anchor must not match by chance")
	}
	if anchorTestContains(t, full, nil, nil) {
		t.Fatal("with no trust configured no certificate is an anchor")
	}

	if _, err := ContainsTrustAnchor([]*x509.Certificate{nil}, []*x509.Certificate{anchor.certificate}, nil); err == nil {
		t.Fatal("an empty certificate in the chain must be reported")
	}
}

func TestContainsTrustAnchorWithRootCAsPool(t *testing.T) {
	leaf, intermediate, anchor := x5cTestChain(t)
	pool := x509.NewCertPool()
	pool.AddCert(anchor.certificate)
	full := []*x509.Certificate{leaf.certificate, intermediate.certificate, anchor.certificate}
	issued := []*x509.Certificate{leaf.certificate, intermediate.certificate}

	if !anchorTestContains(t, full, nil, pool) {
		t.Fatal("a pool anchor carried in x5c must be detected")
	}
	if anchorTestContains(t, issued, nil, pool) {
		t.Fatal("a chain that stops below the pool anchor must be accepted")
	}

	empty := x509.NewCertPool()
	if anchorTestContains(t, full, nil, empty) {
		t.Fatal("an empty pool configures no anchor")
	}

	// The certificate probe behind the pool branch is exercised directly:
	// only a member of the pool verifies at depth 0.
	if !verifiesAsPoolAnchor(anchor.certificate, pool) {
		t.Fatal("the pool member must verify as its own path")
	}
	if verifiesAsPoolAnchor(intermediate.certificate, pool) {
		t.Fatal("a certificate issued below the anchor must not verify at depth 0")
	}
	if verifiesAsPoolAnchor(leaf.certificate, pool) {
		t.Fatal("a leaf must not verify at depth 0")
	}
	// That negative is about depth, not about failing to verify: the
	// intermediate does chain to the pool anchor, two certificates deep.
	paths, err := intermediate.certificate.Verify(x509.VerifyOptions{
		Roots: pool, Intermediates: x509.NewCertPool(),
		CurrentTime: signingTestTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil || len(paths) != 1 || len(paths[0]) != 2 {
		t.Fatalf("intermediate paths = %d, err = %v; want one path of two certificates", len(paths), err)
	}

	// Membership does not depend on the anchor still being valid: an expired
	// anchor is one HAIP still forbids inside x5c.
	expired := newSigningTestCertificate(t, "expired anchor", nil, true, func(template *x509.Certificate) {
		template.NotBefore = signingTestTime.Add(-72 * time.Hour)
		template.NotAfter = signingTestTime.Add(-48 * time.Hour)
	})
	expiredPool := x509.NewCertPool()
	expiredPool.AddCert(expired.certificate)
	if !verifiesAsPoolAnchor(expired.certificate, expiredPool) {
		t.Fatal("an expired pool anchor must still be recognised as an anchor")
	}
}

func TestContainsTrustAnchorFalseForIntermediateOnlyChain(t *testing.T) {
	leaf, intermediate, anchor := x5cTestChain(t)
	pool := x509.NewCertPool()
	pool.AddCert(anchor.certificate)
	conforming := []*x509.Certificate{leaf.certificate, intermediate.certificate}

	if anchorTestContains(t, conforming, []*x509.Certificate{anchor.certificate}, nil) {
		t.Fatal("a HAIP conforming chain must not be reported as carrying its anchor")
	}
	if anchorTestContains(t, conforming, []*x509.Certificate{anchor.certificate}, pool) {
		t.Fatal("configuring both anchor forms must not change the verdict")
	}
	if !anchorTestContains(t, append(conforming, anchor.certificate), []*x509.Certificate{anchor.certificate}, pool) {
		t.Fatal("the same chain with the anchor appended must be detected")
	}
}
