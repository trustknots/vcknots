package x509

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type crlTestAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	now  time.Time
}

func newCRLTestAuthority(t *testing.T, change func(*x509.Certificate)) crlTestAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CRL Test Root"},
		NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if change != nil {
		change(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return crlTestAuthority{cert: cert, key: key, now: now}
}

func issueCRLTestCertificate(t *testing.T, ca crlTestAuthority, change func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "CRL Test Leaf"},
		NotBefore: ca.now.Add(-time.Hour), NotAfter: ca.now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	if change != nil {
		change(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func issueCRLTestDER(t *testing.T, ca crlTestAuthority, change func(*x509.RevocationList)) []byte {
	t.Helper()
	template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: ca.now.Add(-time.Hour), NextUpdate: ca.now.Add(time.Hour)}
	if change != nil {
		change(template)
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func crlTestMarshal(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func crlTestRaw(t *testing.T, der []byte) asn1.RawValue {
	t.Helper()
	value, err := crlDERValue(der)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func rewriteCRLTestDER(t *testing.T, ca crlTestAuthority, der []byte, change func([]asn1.RawValue) []asn1.RawValue) []byte {
	t.Helper()
	outer, err := crlDERSequence(der)
	if err != nil {
		t.Fatal(err)
	}
	tbs, err := crlDERSequence(outer[0].FullBytes)
	if err != nil {
		t.Fatal(err)
	}
	tbsDER := crlTestMarshal(t, change(tbs))
	digest := sha256.Sum256(tbsDER)
	signature, err := ca.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	outer[0] = crlTestRaw(t, tbsDER)
	outer[2] = crlTestRaw(t, crlTestMarshal(t, asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}))
	return crlTestMarshal(t, outer)
}

func assertCRLTestKind(t *testing.T, err error, kind CRLCheckErrorKind) {
	t.Helper()
	var typed *CRLCheckError
	if !errors.As(err, &typed) || typed.Kind != kind {
		t.Fatalf("expected CRL error %q, got %v", kind, err)
	}
}

func newCRLTestChecker(t *testing.T, options CRLCheckerOptions) *CRLChecker {
	t.Helper()
	checker, err := NewCRLChecker(options)
	if err != nil {
		t.Fatal(err)
	}
	return checker
}

func TestCRLCurrentIssuerSignedListAcceptsAndListedSerialRejects(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		ca := newCRLTestAuthority(t, nil)
		der := issueCRLTestDER(t, ca, func(list *x509.RevocationList) {
			if revoked {
				list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: ca.now.Add(-time.Minute)}}
			}
		})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Accept") == "" {
				t.Error("unexpected CRL request")
			}
			_, _ = w.Write(der)
		}))
		leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{server.URL + "/issuer.crl"} })
		checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client()})
		result, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
		server.Close()
		if revoked {
			assertCRLTestKind(t, err, CRLErrorRevoked)
		} else if err != nil || result.CheckedCertificates != 1 || result.NoMechanismCertificates != 0 {
			t.Fatalf("unexpected positive result: %+v, %v", result, err)
		}
	}
}

func TestCRLNoMechanismIsDistinctFromCheckedAndCanBeRequired(t *testing.T) {
	ca := newCRLTestAuthority(t, func(cert *x509.Certificate) { cert.OCSPServer = []string{"http://unreachable.invalid/anchor"} })
	leaf := issueCRLTestCertificate(t, ca, nil)
	for _, require := range []bool{false, true} {
		checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: &http.Client{}, RequireStatus: require})
		result, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
		if require {
			assertCRLTestKind(t, err, CRLErrorUnsupported)
		} else if err != nil || result.CheckedCertificates != 0 || result.NoMechanismCertificates != 1 {
			t.Fatalf("unadvertised certificate misreported: %+v, %v", result, err)
		}
		result, err = checker.Check(context.Background(), []*x509.Certificate{ca.cert}, ca.now)
		if err != nil || result != (CRLCheckResult{}) {
			t.Fatalf("anchor must be excluded: %+v, %v", result, err)
		}
	}
	// OCSP is never consulted, so an OCSP-only certificate has no established
	// status: it is refused under RequireStatus and counted as having no
	// mechanism otherwise.
	ocspOnly := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.OCSPServer = []string{"http://unreachable.invalid/ocsp"} })
	for _, require := range []bool{false, true} {
		checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: &http.Client{Transport: signingTestNoNetwork{t}}, RequireStatus: require})
		result, err := checker.Check(context.Background(), []*x509.Certificate{ocspOnly, ca.cert}, ca.now)
		if require {
			assertCRLTestKind(t, err, CRLErrorUnsupported)
		} else if err != nil || result.CheckedCertificates != 0 || result.NoMechanismCertificates != 1 {
			t.Fatalf("OCSP-only certificate misreported: %+v, %v", result, err)
		}
	}
}

func TestCRLRejectsInvalidTimeIssuerSignatureAndMalformedInput(t *testing.T) {
	ca := newCRLTestAuthority(t, nil)
	other := newCRLTestAuthority(t, func(cert *x509.Certificate) { cert.Subject.CommonName = "Other Root" })
	valid := issueCRLTestDER(t, ca, nil)
	tests := []struct {
		name string
		der  []byte
		kind CRLCheckErrorKind
	}{
		{"stale", issueCRLTestDER(t, ca, func(list *x509.RevocationList) {
			list.ThisUpdate = ca.now.Add(-2 * time.Hour)
			list.NextUpdate = ca.now.Add(-time.Hour)
		}), CRLErrorStale},
		{"future", issueCRLTestDER(t, ca, func(list *x509.RevocationList) { list.ThisUpdate = ca.now.Add(10 * time.Minute) }), CRLErrorStale},
		{"no nextUpdate", rewriteCRLTestDER(t, ca, valid, func(tbs []asn1.RawValue) []asn1.RawValue { return append(tbs[:4], tbs[5:]...) }), CRLErrorStale},
		{"wrong issuer", issueCRLTestDER(t, other, nil), CRLErrorIssuer},
		{"bad signature", append(append([]byte(nil), valid[:len(valid)-1]...), valid[len(valid)-1]^1), CRLErrorSignature},
		{"empty DER", nil, CRLErrorFetch},
		{"invalid DER", []byte("not a CRL"), CRLErrorParse},
		{"trailing DER", append(append([]byte(nil), valid...), 0x05, 0x00), CRLErrorParse},
		{"signed trailing TBS field", rewriteCRLTestDER(t, ca, valid, func(tbs []asn1.RawValue) []asn1.RawValue { return append(tbs, asn1.RawValue{Tag: asn1.TagNull}) }), CRLErrorParse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tt.der) }))
			defer server.Close()
			leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{server.URL} })
			checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client()})
			_, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
			assertCRLTestKind(t, err, tt.kind)
		})
	}
}

// TestCRLThisUpdateToleratesClockSkew pins that a CRL issued moments ahead of
// the wallet clock is current: the default skew is five minutes, and
// ClockSkew replaces it.
func TestCRLThisUpdateToleratesClockSkew(t *testing.T) {
	ca := newCRLTestAuthority(t, nil)
	der := issueCRLTestDER(t, ca, func(list *x509.RevocationList) { list.ThisUpdate = ca.now.Add(2 * time.Minute) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(der) }))
	defer server.Close()
	leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{server.URL} })

	checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client()})
	if _, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now); err != nil {
		t.Fatalf("CRL within the default skew rejected: %v", err)
	}
	strict := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client(), ClockSkew: time.Minute})
	_, err := strict.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
	assertCRLTestKind(t, err, CRLErrorStale)
	if _, err := NewCRLChecker(CRLCheckerOptions{HTTPClient: server.Client(), ClockSkew: -time.Second}); err == nil {
		t.Fatal("negative clock skew accepted")
	}
}

// TestCRLIssuerWithoutKeyUsageMaySignCRLs pins RFC 5280 Section 6.3.3(f):
// cRLSign is checked only when the issuer carries a key usage extension, as
// keyCertSign is on the certification path.
func TestCRLIssuerWithoutKeyUsageMaySignCRLs(t *testing.T) {
	ca := newCRLTestAuthority(t, func(cert *x509.Certificate) { cert.KeyUsage = 0 })
	if hasKeyUsage(ca.cert) {
		t.Fatal("fixture issuer must carry no key usage extension")
	}
	// crypto/x509 refuses to sign a CRL for an issuer without cRLSign, so the
	// CRL is produced from an in-memory copy that claims it; the DER issuer
	// name and key are the same.
	signer := *ca.cert
	signer.KeyUsage = x509.KeyUsageCRLSign
	der := issueCRLTestDER(t, crlTestAuthority{cert: &signer, key: ca.key, now: ca.now}, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(der) }))
	defer server.Close()
	leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{server.URL} })
	checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client()})
	result, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
	if err != nil || result.CheckedCertificates != 1 {
		t.Fatalf("CRL from an issuer without key usage rejected: %+v, %v", result, err)
	}
}

func TestCRLIssuerMustHaveCRLSignBeforeDownload(t *testing.T) {
	ca := newCRLTestAuthority(t, func(cert *x509.Certificate) { cert.KeyUsage = x509.KeyUsageCertSign })
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{server.URL} })
	checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client()})
	_, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
	assertCRLTestKind(t, err, CRLErrorIssuer)
	if requests.Load() != 0 {
		t.Fatal("download occurred before issuer cRLSign guard")
	}
}

func TestCRLRejectsInvalidSessionOptionsAndPaths(t *testing.T) {
	for _, options := range []CRLCheckerOptions{{}, {HTTPClient: &http.Client{}, MaxFetches: -1}, {HTTPClient: &http.Client{}, FetchTimeout: -1}} {
		if _, err := NewCRLChecker(options); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	ca := newCRLTestAuthority(t, nil)
	checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: &http.Client{}})
	for _, path := range [][]*x509.Certificate{nil, {nil, ca.cert}, {ca.cert, nil}, {{}, ca.cert}} {
		_, err := checker.Check(context.Background(), path, ca.now)
		assertCRLTestKind(t, err, CRLErrorUnsupported)
	}
	_, err := checker.Check(context.Background(), []*x509.Certificate{ca.cert}, time.Time{})
	assertCRLTestKind(t, err, CRLErrorUnsupported)
}

func TestCRLChecksIntermediateBelowAnchor(t *testing.T) {
	root := newCRLTestAuthority(t, nil)
	intermediate := newCRLTestAuthority(t, func(cert *x509.Certificate) { cert.Subject.CommonName = "CRL Intermediate" })
	var rootDER, intermediateDER []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/root" {
			_, _ = w.Write(rootDER)
		} else {
			_, _ = w.Write(intermediateDER)
		}
	}))
	defer server.Close()
	template := *intermediate.cert
	template.SerialNumber = big.NewInt(3)
	template.CRLDistributionPoints = []string{server.URL + "/root"}
	der, err := x509.CreateCertificate(rand.Reader, &template, root.cert, &intermediate.key.PublicKey, root.key)
	if err != nil {
		t.Fatal(err)
	}
	intermediate.cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf := issueCRLTestCertificate(t, intermediate, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{server.URL + "/intermediate"} })
	intermediateDER = issueCRLTestDER(t, intermediate, nil)
	for _, revoked := range []bool{false, true} {
		rootDER = issueCRLTestDER(t, root, func(list *x509.RevocationList) {
			if revoked {
				list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: root.now.Add(-time.Minute)}}
			}
		})
		checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client()})
		result, err := checker.Check(context.Background(), []*x509.Certificate{leaf, intermediate.cert, root.cert}, root.now)
		if revoked {
			assertCRLTestKind(t, err, CRLErrorRevoked)
		} else if err != nil || result.CheckedCertificates != 2 {
			t.Fatalf("intermediate not checked: %+v, %v", result, err)
		}
	}
}

func TestCRLParserAcceptsPublicShardScaleAndBoundsHostileASN1(t *testing.T) {
	ca := newCRLTestAuthority(t, nil)
	der := issueCRLTestDER(t, ca, func(list *x509.RevocationList) {
		for serial := int64(100); serial < 6100; serial++ {
			list.RevokedCertificateEntries = append(list.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: big.NewInt(serial), RevocationTime: ca.now.Add(-time.Minute)})
		}
	})
	parsed, err := parseStrictCRL(der)
	if err != nil || len(parsed.RevokedCertificateEntries) != 6000 {
		t.Fatalf("real shard rejected: %v", err)
	}
	nested := []byte{5, 0}
	for range 34 {
		nested = crlTestMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: nested})
	}
	if _, err := parseStrictCRL(nested); err == nil {
		t.Fatal("excessive nesting accepted")
	}
	packed := make([]asn1.RawValue, 5000)
	for i := range packed {
		packed[i] = asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true}
	}
	if _, err := parseStrictCRL(crlTestMarshal(t, packed)); err == nil {
		t.Fatal("excessive ASN.1 nodes accepted")
	}
}

func TestCRLTypedErrorPreservesCancelledContext(t *testing.T) {
	ca := newCRLTestAuthority(t, nil)
	leaf := issueCRLTestCertificate(t, ca, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: &http.Client{}})
	_, err := checker.Check(ctx, []*x509.Certificate{leaf, ca.cert}, ca.now)
	assertCRLTestKind(t, err, CRLErrorFetch)
	if !errors.Is(err, context.Canceled) || err.Error() == "" {
		t.Fatalf("context cause lost: %v", err)
	}
}
