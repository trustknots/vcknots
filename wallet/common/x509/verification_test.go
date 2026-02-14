package x509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

type testCerts struct {
	issuerCert *x509.Certificate
	issuerKey  *ecdsa.PrivateKey
	leafCert   *x509.Certificate
	leafKey    *ecdsa.PrivateKey
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

func genLeaf(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to gen key: %v", err)
	}
	serial := big.NewInt(2)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}
	return cert, key
}

func setupOCSPServer(t *testing.T, tc *testCerts, status int, stale bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = io.ReadAll(r.Body)
		thisUpdate := time.Now().Add(-5 * time.Minute)
		nextUpdate := time.Now().Add(30 * time.Minute)
		if stale {
			nextUpdate = time.Now().Add(-1 * time.Minute)
		}
		resp, err := ocsp.CreateResponse(tc.issuerCert, tc.issuerCert, ocsp.Response{
			Status:       status,
			SerialNumber: tc.leafCert.SerialNumber,
			ThisUpdate:   thisUpdate,
			NextUpdate:   nextUpdate,
		}, tc.issuerKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(resp)
	}))
}

func setupCRLServer(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, revoked bool, stale bool, signWithOther bool, includeNonMatching bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		revokedEntries := []pkix.RevokedCertificate{}
		if revoked {
			revokedEntries = append(revokedEntries, pkix.RevokedCertificate{SerialNumber: big.NewInt(2), RevocationTime: time.Now()})
		}
		if includeNonMatching {
			revokedEntries = append(revokedEntries, pkix.RevokedCertificate{SerialNumber: big.NewInt(9999), RevocationTime: time.Now()})
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
			Issuer:              issuer.Subject,
			ThisUpdate:          time.Now().Add(-5 * time.Minute),
			NextUpdate:          nextUpdate,
			RevokedCertificates: revokedEntries,
			Number:              big.NewInt(1),
		}, issuer, signingKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(crlBytes)
	}))
}

func prepareCerts(t *testing.T) *testCerts {
	issuer, issuerKey := genCA(t, "Test CA")
	leaf, leafKey := genLeaf(t, issuer, issuerKey)
	return &testCerts{issuerCert: issuer, issuerKey: issuerKey, leafCert: leaf, leafKey: leafKey}
}

func TestCheckIfCertsRevoked_NoEndpoints(t *testing.T) {
	c := prepareCerts(t)
	// no OCSP/CRL endpoints
	if err := CheckIfCertsRevoked([]*x509.Certificate{c.leafCert, c.issuerCert}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckIfCertsRevoked_OCSP_ServerError(t *testing.T) {
	c := prepareCerts(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	c.leafCert.OCSPServer = []string{srv.URL}
	if err := CheckIfCertsRevoked([]*x509.Certificate{c.leafCert, c.issuerCert}); err == nil {
		t.Fatalf("expected OCSP error")
	}
}

func TestCheckIfCertsRevoked_OCSP_Good(t *testing.T) {
	c := prepareCerts(t)
	srv := setupOCSPServer(t, c, ocsp.Good, false)
	defer srv.Close()
	c.leafCert.OCSPServer = []string{srv.URL}
	if err := CheckIfCertsRevoked([]*x509.Certificate{c.leafCert, c.issuerCert}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckIfCertsRevoked_OCSP_Revoked(t *testing.T) {
	c := prepareCerts(t)
	srv := setupOCSPServer(t, c, ocsp.Revoked, false)
	defer srv.Close()
	c.leafCert.OCSPServer = []string{srv.URL}
	if err := CheckIfCertsRevoked([]*x509.Certificate{c.leafCert, c.issuerCert}); err == nil {
		t.Fatalf("expected revoked error")
	}
}

func TestCheckIfCertsRevoked_OCSP_Stale(t *testing.T) {
	c := prepareCerts(t)
	srv := setupOCSPServer(t, c, ocsp.Good, true)
	defer srv.Close()
	c.leafCert.OCSPServer = []string{srv.URL}
	if err := CheckIfCertsRevoked([]*x509.Certificate{c.leafCert, c.issuerCert}); err == nil {
		t.Fatalf("expected stale OCSP error")
	}
}

func TestCheckIfCertsRevoked_CRL_Success(t *testing.T) {
	c := prepareCerts(t)
	srv := setupCRLServer(t, c.issuerCert, c.issuerKey, false, false, false, true)
	defer srv.Close()
	c.leafCert.CRLDistributionPoints = []string{srv.URL}
	if err := CheckIfCertsRevoked([]*x509.Certificate{c.leafCert, c.issuerCert}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckIfCertsRevoked_CRL_Revoked(t *testing.T) {
	c := prepareCerts(t)
	srv := setupCRLServer(t, c.issuerCert, c.issuerKey, true, false, false, false)
	defer srv.Close()
	c.leafCert.CRLDistributionPoints = []string{srv.URL}
	if err := CheckIfCertsRevoked([]*x509.Certificate{c.leafCert, c.issuerCert}); err == nil {
		t.Fatalf("expected CRL revoked error")
	}
}

func TestCheckIfCertsRevoked_CRL_SignatureInvalid(t *testing.T) {
	c := prepareCerts(t)
	srv := setupCRLServer(t, c.issuerCert, c.issuerKey, false, false, true, false)
	defer srv.Close()
	c.leafCert.CRLDistributionPoints = []string{srv.URL}
	if err := CheckIfCertsRevoked([]*x509.Certificate{c.leafCert, c.issuerCert}); err == nil {
		t.Fatalf("expected CRL signature error")
	}
}
