package x509

import (
	"bytes"
	"crypto/x509"
	"fmt"
)

// ContainsTrustAnchor reports whether any certificate in chain is one of the
// configured trust anchors. HAIP Sections 5 and 6.1.1 require that "The X.509
// certificate of the trust anchor MUST NOT be included in the x5c JOSE
// header", so a true result is a reason to reject the chain, never a trust
// decision: trust is established by VerifySigningCertificateChain, which
// resolves the anchor itself from the same configuration.
//
// Both anchor forms may be supplied and either may be empty; only the supplied
// ones are consulted, and a caller with neither configured gets false.
//
// anchors are compared by raw DER equality. roots is an *x509.CertPool, which
// cannot be enumerated as certificates, so each chain certificate is verified
// against the pool as a leaf with an empty intermediate set; a certificate that
// verifies at depth 0 is the anchor itself. That probe identifies the exact
// pool member, unlike a subject-DN comparison, which cannot tell a pool anchor
// apart from a different certificate carrying the same subject DN, such as a
// re-keyed CA of the same name.
func ContainsTrustAnchor(chain []*x509.Certificate, anchors []*x509.Certificate, roots *x509.CertPool) (bool, error) {
	for index, certificate := range chain {
		if certificate == nil || len(certificate.Raw) == 0 {
			return false, fmt.Errorf("x5c certificate %d is empty", index)
		}
	}
	for _, anchor := range anchors {
		if anchor == nil || len(anchor.Raw) == 0 {
			continue
		}
		for _, certificate := range chain {
			if bytes.Equal(certificate.Raw, anchor.Raw) {
				return true, nil
			}
		}
	}
	if roots == nil {
		return false, nil
	}
	for _, certificate := range chain {
		if verifiesAsPoolAnchor(certificate, roots) {
			return true, nil
		}
	}
	return false, nil
}

// verifiesAsPoolAnchor reports whether certificate is itself a member of an
// opaque pool. crypto/x509 answers that through Verify: a leaf contained in
// the root pool yields the single-certificate path [certificate], while any
// other trusted leaf yields a longer one.
//
// The probe verifies at the certificate's own NotBefore and with
// ExtKeyUsageAny on purpose. Membership in the configured anchor set does not
// depend on the certificate still being valid today or on any EKU policy, and
// an expired anchor is still an anchor HAIP forbids inside x5c. A verification
// failure therefore only means "not a configured anchor"; it never reports a
// misconfiguration, which VerifySigningCertificateChain is responsible for.
func verifiesAsPoolAnchor(certificate *x509.Certificate, roots *x509.CertPool) bool {
	paths, err := certificate.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   certificate.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return false
	}
	for _, path := range paths {
		if len(path) == 1 {
			return true
		}
	}
	return false
}
