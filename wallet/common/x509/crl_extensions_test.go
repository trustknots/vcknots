package x509

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func crlTestPointName(t *testing.T, location string) asn1.RawValue {
	t.Helper()
	uri := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(location)}
	fullName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: crlTestMarshal(t, uri)}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: crlTestMarshal(t, fullName)}
}

func crlTestIDP(t *testing.T, location string, fields ...asn1.RawValue) pkix.Extension {
	t.Helper()
	if location != "" {
		fields = append([]asn1.RawValue{crlTestPointName(t, location)}, fields...)
	}
	return pkix.Extension{Id: crlIssuingPointOID, Critical: true, Value: crlTestMarshal(t, fields)}
}

func crlTestFlag(tag int) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: []byte{0xff}}
}

func TestCRLIssuingDistributionPointScope(t *testing.T) {
	tests := []struct {
		name   string
		isCA   bool
		extras func(*testing.T, string) []pkix.Extension
		kind   CRLCheckErrorKind
	}{
		{"matching URI", false, func(t *testing.T, url string) []pkix.Extension { return []pkix.Extension{crlTestIDP(t, url)} }, ""},
		{"wrong URI", false, func(t *testing.T, _ string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, "https://other.invalid/shard")}
		}, CRLErrorScope},
		{"user scope covers leaf", false, func(t *testing.T, url string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, url, crlTestFlag(1))}
		}, ""},
		{"user scope excludes CA", true, func(t *testing.T, url string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, url, crlTestFlag(1))}
		}, CRLErrorScope},
		{"CA scope covers CA", true, func(t *testing.T, url string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, url, crlTestFlag(2))}
		}, ""},
		{"CA scope excludes leaf", false, func(t *testing.T, url string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, url, crlTestFlag(2))}
		}, CRLErrorScope},
		{"reason partition", false, func(t *testing.T, url string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, url, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, Bytes: []byte{7, 0x80}})}
		}, CRLErrorScope},
		{"indirect", false, func(t *testing.T, url string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, url, crlTestFlag(4))}
		}, CRLErrorScope},
		{"attribute only", false, func(t *testing.T, url string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, url, crlTestFlag(5))}
		}, CRLErrorScope},
		{"relative name", false, func(t *testing.T, _ string) []pkix.Extension {
			relative := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true}
			return []pkix.Extension{crlTestIDP(t, "", asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: crlTestMarshal(t, relative)})}
		}, CRLErrorScope},
		{"non HTTP name", false, func(t *testing.T, _ string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, "ldap://other.invalid/shard")}
		}, CRLErrorScope},
		{"directory name", false, func(t *testing.T, _ string) []pkix.Extension {
			name := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: crlTestMarshal(t, pkix.Name{CommonName: "Shard"}.ToRDNSequence())}
			fullName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: crlTestMarshal(t, name)}
			return []pkix.Extension{crlTestIDP(t, "", asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: crlTestMarshal(t, fullName)})}
		}, CRLErrorScope},
		{"duplicate IDP", false, func(t *testing.T, url string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, url), crlTestIDP(t, url)}
		}, CRLErrorParse},
		{"malformed boolean", false, func(t *testing.T, url string) []pkix.Extension {
			return []pkix.Extension{crlTestIDP(t, url, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte{1}})}
		}, CRLErrorScope},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newCRLTestAuthority(t, nil)
			var der []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(der) }))
			defer server.Close()
			location := server.URL + "/shard.crl"
			der = issueCRLTestDER(t, ca, func(list *x509.RevocationList) { list.ExtraExtensions = tt.extras(t, location) })
			leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) {
				cert.CRLDistributionPoints = []string{location}
				cert.IsCA = tt.isCA
				if tt.isCA {
					cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
				}
			})
			checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client()})
			result, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
			if tt.kind != "" {
				assertCRLTestKind(t, err, tt.kind)
			} else if err != nil || result.CheckedCertificates != 1 {
				t.Fatalf("supported scope rejected: %+v, %v", result, err)
			}
		})
	}
}

func TestCRLRawCertificateDistributionPointRestrictions(t *testing.T) {
	ca := newCRLTestAuthority(t, nil)
	for _, extra := range []asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte{7, 0x80}},
		{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: crlTestMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte("http://other.invalid/")})},
	} {
		point := crlTestRaw(t, crlTestMarshal(t, []asn1.RawValue{crlTestPointName(t, "http://issuer.invalid/crl"), extra}))
		leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) {
			cert.ExtraExtensions = []pkix.Extension{{Id: crlDistributionPointsOID, Value: crlTestMarshal(t, []asn1.RawValue{point})}}
		})
		if len(leaf.CRLDistributionPoints) != 1 {
			t.Fatal("fixture must demonstrate URI extraction despite ignored restriction")
		}
		checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: &http.Client{}})
		_, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
		assertCRLTestKind(t, err, CRLErrorUnsupported)
	}
	for _, location := range []string{"ftp://issuer.invalid/crl", "file:///tmp/crl", "http://user:pass@issuer.invalid/crl", "https://issuer.invalid/crl#fragment"} {
		leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{location} })
		checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: &http.Client{}})
		_, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
		assertCRLTestKind(t, err, CRLErrorUnsupported)
	}
	leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) {
		cert.ExtraExtensions = []pkix.Extension{{Id: crlDistributionPointsOID, Value: crlTestMarshal(t, []asn1.RawValue{})}}
	})
	checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: &http.Client{}})
	_, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
	assertCRLTestKind(t, err, CRLErrorUnsupported)
}

func TestCRLExtensionsAndAllEntryExtensionsAreChecked(t *testing.T) {
	ca := newCRLTestAuthority(t, nil)
	unknown := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}
	tests := []struct {
		name   string
		change func(*x509.RevocationList)
		kind   CRLCheckErrorKind
	}{
		{"unknown critical", func(list *x509.RevocationList) { list.ExtraExtensions = []pkix.Extension{unknown} }, CRLErrorUnsupported},
		{"unknown noncritical", func(list *x509.RevocationList) {
			e := unknown
			e.Critical = false
			list.ExtraExtensions = []pkix.Extension{e}
		}, ""},
		{"delta", func(list *x509.RevocationList) {
			list.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Value: crlTestMarshal(t, 1)}}
		}, CRLErrorUnsupported},
		{"unrelated entry critical", func(list *x509.RevocationList) {
			list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(999), RevocationTime: ca.now.Add(-time.Minute), ExtraExtensions: []pkix.Extension{unknown}}}
		}, CRLErrorUnsupported},
		{"indirect entry", func(list *x509.RevocationList) {
			list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(999), RevocationTime: ca.now.Add(-time.Minute), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Value: crlTestMarshal(t, []asn1.RawValue{})}}}}
		}, CRLErrorUnsupported},
		{"known entry extensions", func(list *x509.RevocationList) {
			date, err := asn1.MarshalWithParams(ca.now.Add(-time.Hour), "generalized")
			if err != nil {
				t.Fatal(err)
			}
			list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(999), RevocationTime: ca.now.Add(-time.Minute), ReasonCode: 1, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 24}, Critical: true, Value: date}}}}
		}, ""},
		{"malformed known entry extension", func(list *x509.RevocationList) {
			list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(999), RevocationTime: ca.now.Add(-time.Minute), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 24}, Critical: true, Value: []byte{5, 0}}}}}
		}, CRLErrorParse},
		{"duplicate entry extension", func(list *x509.RevocationList) {
			list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(999), RevocationTime: ca.now.Add(-time.Minute), ExtraExtensions: []pkix.Extension{unknown, unknown}}}
		}, CRLErrorParse},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der := issueCRLTestDER(t, ca, tt.change)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(der) }))
			defer server.Close()
			leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = []string{server.URL} })
			checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client()})
			_, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
			if tt.kind != "" {
				assertCRLTestKind(t, err, tt.kind)
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestCRLIssuingDistributionPointMatchesAnyCertificateDistributionPoint pins
// RFC 5280 Section 6.3.3(b)(2)(i): the IDP scope must name one of the
// certificate's distribution points, not necessarily the one fetched.
func TestCRLIssuingDistributionPointMatchesAnyCertificateDistributionPoint(t *testing.T) {
	ca := newCRLTestAuthority(t, nil)
	var der []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(der) }))
	defer server.Close()
	fetched := server.URL + "/shard.crl"
	mirror := "https://mirror.invalid/shard.crl"
	for _, tc := range []struct {
		name string
		idp  string
		dps  []string
		kind CRLCheckErrorKind
	}{
		{"IDP names another DP of the certificate", mirror, []string{fetched, mirror}, ""},
		{"IDP names a DP the certificate does not list", mirror, []string{fetched}, CRLErrorScope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der = issueCRLTestDER(t, ca, func(list *x509.RevocationList) {
				list.ExtraExtensions = []pkix.Extension{crlTestIDP(t, tc.idp)}
			})
			leaf := issueCRLTestCertificate(t, ca, func(cert *x509.Certificate) { cert.CRLDistributionPoints = tc.dps })
			checker := newCRLTestChecker(t, CRLCheckerOptions{HTTPClient: server.Client()})
			result, err := checker.Check(context.Background(), []*x509.Certificate{leaf, ca.cert}, ca.now)
			if tc.kind != "" {
				assertCRLTestKind(t, err, tc.kind)
			} else if err != nil || result.CheckedCertificates != 1 {
				t.Fatalf("CRL in scope rejected: %+v, %v", result, err)
			}
		})
	}
}
