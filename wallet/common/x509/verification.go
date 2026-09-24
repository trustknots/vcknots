package x509

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// CheckIfCertsRevoked checks the CRL status of every certificate in certChain
// except the last, which is the trust anchor of a leaf-first path such as
// x509.Certificate.Verify returns. It runs the bounded CRL checker of this
// package with a default client and without RequireStatus: a certificate that
// publishes no revocation information passes. A certificate that advertises
// only OCSP is refused, because OCSP is not consulted.
//
// Deprecated: Use VerifySigningChainWithPolicy, which verifies the path and its
// revocation under one policy and takes a context and an HTTP client.
func CheckIfCertsRevoked(certChain []*x509.Certificate) error {
	for index, cert := range certChain {
		if index == len(certChain)-1 || cert == nil || cert.SerialNumber == nil {
			break
		}
		urls, advertised, err := certificateCRLURLs(cert)
		if err != nil || advertised || len(urls) > 0 {
			continue // Check reports these
		}
		if ocsp, _ := certificateAdvertisesOCSP(cert); ocsp {
			return crlError(CRLErrorUnsupported, cert, "", "certificate advertises only OCSP, which is not consulted", nil)
		}
	}
	checker, err := NewCRLChecker(CRLCheckerOptions{HTTPClient: httpfetch.NewClient()})
	if err != nil {
		return err
	}
	_, err = checker.Check(context.Background(), certChain, time.Now())
	return err
}
