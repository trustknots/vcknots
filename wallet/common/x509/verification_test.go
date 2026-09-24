package x509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type testCerts struct {
	issuerCert *x509.Certificate
	issuerKey  *ecdsa.PrivateKey
	leafCert   *x509.Certificate
}

func genCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	return cert, key
}

// genLeaf issues the leaf with its revocation endpoints in the signed
// certificate, where the checker reads them.
func genLeaf(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, crlURL, ocspURL string) *x509.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if crlURL != "" {
		tmpl.CRLDistributionPoints = []string{crlURL}
	}
	if ocspURL != "" {
		tmpl.OCSPServer = []string{ocspURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}
	return cert
}

func setupCRLServer(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, revoked bool, stale bool, signWithOther bool, includeNonMatching bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revokedEntries := []x509.RevocationListEntry{}
		if revoked {
			revokedEntries = append(revokedEntries, x509.RevocationListEntry{SerialNumber: big.NewInt(2), RevocationTime: time.Now()})
		}
		if includeNonMatching {
			revokedEntries = append(revokedEntries, x509.RevocationListEntry{SerialNumber: big.NewInt(9999), RevocationTime: time.Now()})
		}
		nextUpdate := time.Now().Add(30 * time.Minute)
		if stale {
			nextUpdate = time.Now().Add(-1 * time.Minute)
		}
		signingKey := issuerKey
		if signWithOther {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			signingKey = k
		}
		crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Issuer:                    issuer.Subject,
			ThisUpdate:                time.Now().Add(-5 * time.Minute),
			NextUpdate:                nextUpdate,
			RevokedCertificateEntries: revokedEntries,
			Number:                    big.NewInt(1),
		}, issuer, signingKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(crlBytes)
	}))
}

func prepareCerts(t *testing.T, crlURL, ocspURL string) *testCerts {
	issuer, issuerKey := genCA(t, "Test CA")
	leaf := genLeaf(t, issuer, issuerKey, crlURL, ocspURL)
	return &testCerts{issuerCert: issuer, issuerKey: issuerKey, leafCert: leaf}
}

func TestCheckIfCertsRevoked_NoEndpoints(t *testing.T) {
	c := prepareCerts(t, "", "")
	if err := CheckIfCertsRevoked([]*x509.Certificate{c.leafCert, c.issuerCert}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestCheckIfCertsRevoked_OCSPOnlyIsRefused pins that OCSP is not consulted:
// a certificate whose only revocation mechanism is OCSP has no established
// status, so it is refused without contacting the responder.
func TestCheckIfCertsRevoked_OCSPOnlyIsRefused(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1) }))
	defer srv.Close()
	c := prepareCerts(t, "", srv.URL)
	err := CheckIfCertsRevoked([]*x509.Certificate{c.leafCert, c.issuerCert})
	assertCRLTestKind(t, err, CRLErrorUnsupported)
	if requests.Load() != 0 {
		t.Fatal("the OCSP responder was contacted")
	}
}

func TestCheckIfCertsRevoked_CRL(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		revoked, stale, signWithOther bool
		wantKind                      CRLCheckErrorKind
	}{
		{name: "current CRL without the serial"},
		{name: "revoked", revoked: true, wantKind: CRLErrorRevoked},
		{name: "stale", stale: true, wantKind: CRLErrorStale},
		{name: "signed by another key", signWithOther: true, wantKind: CRLErrorSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer, issuerKey := genCA(t, "Test CA")
			srv := setupCRLServer(t, issuer, issuerKey, tc.revoked, tc.stale, tc.signWithOther, true)
			defer srv.Close()
			leaf := genLeaf(t, issuer, issuerKey, srv.URL+"/ca.crl", "")
			err := CheckIfCertsRevoked([]*x509.Certificate{leaf, issuer})
			if tc.wantKind == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			assertCRLTestKind(t, err, tc.wantKind)
		})
	}
}
