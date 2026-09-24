package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestIssuerMetadataDoesNotRetryInvalidOrForbiddenResponses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError, http.StatusNotFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if requests == 1 {
					w.WriteHeader(status)
					fmt.Fprint(w, `{"credential_request_encryption":{"encryption_required":"invalid"}}`)
					return
				}
				fmt.Fprint(w, `{"credential_request_encryption":{"encryption_required":false}}`)
			}))
			defer server.Close()
			endpoint, err := common.ParseURIField(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
			metadata, err := receiver.FetchIssuerMetadata(*endpoint, types.Oid4vci)
			if err == nil || metadata != nil {
				t.Fatalf("metadata = %v, error = %v; want failure", metadata, err)
			}
			if requests != 1 {
				t.Fatalf("requests = %d, want 1", requests)
			}
		})
	}
}

func TestIssuerMetadataRetriesOnlyMissingDistinctLocalDiscoveryPath(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("https_%t", secure), func(t *testing.T) {
			testAppendedMetadataPathFallback(t, secure)
		})
	}
}

func testAppendedMetadataPathFallback(t *testing.T, secure bool) {
	var paths []string
	var acceptedIdentifier string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/.well-known/openid-credential-issuer/tenant" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"credential_issuer":"https://discarded.example","credential_request_encryption":{"encryption_required":true}}`)
			return
		}
		// §12.2.4 binds credential_issuer to the requested identifier, which
		// for this tenant is the base URL plus the /tenant path.
		acceptedIdentifier = serverURLFor(r) + "/tenant"
		fmt.Fprint(w, `{"credential_issuer":"`+acceptedIdentifier+`"}`)
	})
	server := httptest.NewUnstartedServer(handler)
	if secure {
		server.StartTLS()
	} else {
		server.Start()
	}
	defer server.Close()
	endpoint, err := common.ParseURIField(server.URL + "/tenant")
	if err != nil {
		t.Fatal(err)
	}
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: !secure, AppendedMetadataPathFallback: true}
	metadata, err := receiver.FetchIssuerMetadata(*endpoint, types.Oid4vci)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[1] != "/tenant/.well-known/openid-credential-issuer" {
		t.Fatalf("paths = %v", paths)
	}
	if metadata.CredentialIssuer != acceptedIdentifier || metadata.CredentialRequestEncryption != nil {
		t.Fatalf("metadata from discarded response leaked: %+v", metadata)
	}
}

func serverURLFor(r *http.Request) string {
	if r.TLS != nil {
		return "https://" + r.Host
	}
	return "http://" + r.Host
}

// The Draft 13 location is tried only on request: AllowHTTP alone does not
// enable it, and HAIP, which is Final-only, never uses it.
func TestIssuerMetadataAppendedPathFallbackIsOptIn(t *testing.T) {
	cases := map[string]struct {
		secure, allowHTTP, fallback bool
		profile                     profile.Profile
	}{
		"AllowHTTP only": {allowHTTP: true},
		"HAIP":           {secure: true, fallback: true, profile: profile.HAIP},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var paths []string
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				http.NotFound(w, r)
			}))
			if tc.secure {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: tc.allowHTTP, Profile: tc.profile, AppendedMetadataPathFallback: tc.fallback}
			endpoint, err := common.ParseURIField(server.URL + "/tenant")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := receiver.FetchIssuerMetadata(*endpoint, types.Oid4vci); err == nil {
				t.Fatal("expected the 404 to be reported")
			}
			if len(paths) != 1 {
				t.Fatalf("paths = %v, want only the Section 12.2.2 location", paths)
			}
		})
	}
}

// signedMetadataFixture issues the certificates and JWTs the §12.2.3 signed
// Credential Issuer Metadata tests need.
type signedMetadataFixture struct {
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
}

func newSignedMetadataFixture(t *testing.T) signedMetadataFixture {
	t.Helper()
	return newSignedMetadataFixtureWithDNSNames(t)
}

// newSignedMetadataFixtureWithDNSNames issues the same fixture with dNSName
// Subject Alternative Names on the leaf, for the signer-to-host binding.
func newSignedMetadataFixtureWithDNSNames(t *testing.T, dnsNames ...string) signedMetadataFixture {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Signed Metadata Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Signed Metadata Test Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return signedMetadataFixture{caCert: caCert, caKey: caKey, leaf: leaf, leafKey: leafKey}
}

// sign serializes claims as signed metadata carrying chain in its x5c header.
func (f signedMetadataFixture) sign(t *testing.T, claims map[string]any, chain []*x509.Certificate) string {
	t.Helper()
	return f.signWithType(t, signedIssuerMetadataJWTType, claims, chain)
}

// signWithType serializes claims under a caller-chosen typ JOSE header, for the
// §12.2.3 rule that the header must be openidvci-issuer-metadata+jwt.
func (f signedMetadataFixture) signWithType(t *testing.T, typ string, claims map[string]any, chain []*x509.Certificate) string {
	t.Helper()
	encoded := make([]string, 0, len(chain))
	for _, certificate := range chain {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: f.leafKey},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("x5c", encoded),
	)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return serialized
}

// serveIssuerMetadata starts a Credential Issuer that answers the §12.2.2
// well-known path with a document the test supplies, and records the Accept
// header the wallet negotiated with.
func serveIssuerMetadata(t *testing.T, tls bool, document func(identifier string) (contentType string, body string)) (serverURL string, client *http.Client, acceptHeader func() string) {
	t.Helper()
	var accept atomic.Value
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		accept.Store(r.Header.Get("Accept"))
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		contentType, body := document(scheme + "://" + r.Host)
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	server := httptest.NewUnstartedServer(handler)
	if tls {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server.URL, server.Client(), func() string {
		stored, _ := accept.Load().(string)
		return stored
	}
}

func TestFetchIssuerMetadataVerifiesSignedMetadata(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	var compact string
	serverURL, client, acceptHeader := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		compact = fixture.sign(t, map[string]any{
			"sub":                 identifier,
			"iss":                 identifier,
			"iat":                 time.Now().Add(-time.Minute).Unix(),
			"exp":                 time.Now().Add(time.Hour).Unix(),
			"credential_issuer":   identifier,
			"credential_endpoint": identifier + "/credential",
			"nonce_endpoint":      identifier + "/nonce",
		}, []*x509.Certificate{fixture.leaf})
		return "application/jwt", compact
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err != nil {
		t.Fatalf("FetchIssuerMetadata() error = %v", err)
	}
	if !strings.Contains(acceptHeader(), "application/jwt") {
		t.Fatalf("Accept = %q, want signed metadata to be requested", acceptHeader())
	}
	// §12.2.3 requires every metadata parameter to be a top-level claim of the
	// payload, so the payload is the whole document: nothing is merged in from
	// an unsigned response.
	if metadata.CredentialIssuer != serverURL {
		t.Fatalf("credential_issuer = %q, want %q", metadata.CredentialIssuer, serverURL)
	}
	if metadata.NonceEndpoint == nil || !strings.HasSuffix(url.URL(*metadata.NonceEndpoint).Path, "/nonce") {
		t.Fatalf("nonce_endpoint = %#v", metadata.NonceEndpoint)
	}
	if metadata.SignedMetadata != compact {
		t.Fatalf("SignedMetadata = %q, want the compact JWS", metadata.SignedMetadata)
	}
	if metadata.MetadataSignature == nil {
		t.Fatal("MetadataSignature is nil, want the signer identity")
	}
	digest := sha256.Sum256(fixture.leaf.Raw)
	if metadata.MetadataSignature.LeafCertificateSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("LeafCertificateSHA256 = %q", metadata.MetadataSignature.LeafCertificateSHA256)
	}
	if metadata.MetadataSignature.Subject != fixture.leaf.Subject.String() {
		t.Fatalf("Subject = %q", metadata.MetadataSignature.Subject)
	}
	if metadata.MetadataSignature.IssuedAt.IsZero() || metadata.MetadataSignature.ExpiresAt == nil {
		t.Fatalf("MetadataSignature = %#v", metadata.MetadataSignature)
	}
}

func TestFetchIssuerMetadataRejectsUntrustedSignedMetadata(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	foreign := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		return "application/jwt", foreign.sign(t, map[string]any{
			"sub":                 identifier,
			"iat":                 time.Now().Unix(),
			"credential_issuer":   identifier,
			"credential_endpoint": identifier + "/credential",
		}, []*x509.Certificate{foreign.leaf})
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !errors.Is(err, ErrIssuerMetadataSignatureInvalid) {
		t.Fatalf("errors.Is(ErrIssuerMetadataSignatureInvalid) = false, err = %v", err)
	}
}

func TestFetchIssuerMetadataRejectsIssuerMismatchInSignedMetadata(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		return "application/jwt", fixture.sign(t, map[string]any{
			// §12.2.3: sub is "REQUIRED. String matching the Credential Issuer
			// Identifier".
			"sub":                 "https://other-issuer.example",
			"iat":                 time.Now().Unix(),
			"credential_issuer":   identifier,
			"credential_endpoint": identifier + "/credential",
		}, []*x509.Certificate{fixture.leaf})
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !errors.Is(err, ErrIssuerMetadataSubjectMismatch) ||
		!strings.Contains(err.Error(), `sub "https://other-issuer.example" does not match the credential issuer`) {
		t.Fatalf("error = %v", err)
	}
}

// TestFetchIssuerMetadataRejectsTrailingSlashInSignedMetadataSub pins that the
// sub comparison is exact. §12.2.4 states the rule for a Credential Issuer's
// identity: "The value MUST be identical to the Credential Issuer's identifier
// value into which the well-known URI string was inserted to create the URL used
// to retrieve the metadata. If these values are not identical (when compared
// using a simple string comparison with no normalization), the data contained in
// the response MUST NOT be used." A sub that differs only by a trailing slash is
// therefore a different identifier, not the same one written differently.
func TestFetchIssuerMetadataRejectsTrailingSlashInSignedMetadataSub(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		return "application/jwt", fixture.sign(t, map[string]any{
			"sub":                 identifier + "/",
			"iat":                 time.Now().Unix(),
			"credential_issuer":   identifier,
			"credential_endpoint": identifier + "/credential",
		}, []*x509.Certificate{fixture.leaf})
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !strings.Contains(err.Error(), `does not match the credential issuer "`+serverURL+`"`) {
		t.Fatalf("error = %v", err)
	}
}

// TestFetchIssuerMetadataRejectsCredentialIssuerMismatchInSignedMetadata pins
// that §12.2.4 also binds the credential_issuer member of a signed payload: the
// sub claim and the credential_issuer parameter must both name the requested
// Credential Issuer Identifier.
func TestFetchIssuerMetadataRejectsCredentialIssuerMismatchInSignedMetadata(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		return "application/jwt", fixture.sign(t, map[string]any{
			"sub":                 identifier,
			"iat":                 time.Now().Unix(),
			"credential_issuer":   "https://other-issuer.example",
			"credential_endpoint": identifier + "/credential",
		}, []*x509.Certificate{fixture.leaf})
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !errors.Is(err, ErrIssuerIdentifierMismatch) {
		t.Fatalf("errors.Is(ErrIssuerIdentifierMismatch) = false, err = %v", err)
	}
}

// HAIP §4.1: "the X.509 certificate of the trust anchor MUST NOT be included in
// the `x5c` JOSE header of the signed request."
func TestFetchIssuerMetadataRejectsAnchorInSignedMetadataX5C(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, true, func(identifier string) (string, string) {
		return "application/jwt", fixture.sign(t, map[string]any{
			"sub":                 identifier,
			"iat":                 time.Now().Unix(),
			"credential_issuer":   identifier,
			"credential_endpoint": identifier + "/credential",
		}, []*x509.Certificate{fixture.leaf, fixture.caCert})
	})
	signing := &IssuerMetadataSigningOptions{
		Request:                     true,
		TrustAnchors:                []*x509.Certificate{fixture.caCert},
		AllowUnadvertisedRevocation: true,
	}

	haip := &Oid4vciReceiver{HTTPClient: client, Profile: profile.HAIP, IssuerMetadataSigning: signing}
	metadata, err := haip.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !strings.Contains(err.Error(), "HAIP forbids including the trust anchor certificate in the x5c header") {
		t.Fatalf("error = %v", err)
	}

	// The same chain is accepted outside HAIP, where the rule does not apply.
	final := &Oid4vciReceiver{HTTPClient: client, Profile: profile.Final, IssuerMetadataSigning: signing}
	if _, err := final.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci); err != nil {
		t.Fatalf("Final FetchIssuerMetadata() error = %v", err)
	}
}

func TestFetchIssuerMetadataRequireRejectsUnsignedResponse(t *testing.T) {
	fixture := newSignedMetadataFixture(t)
	serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
		return "application/json", `{"credential_issuer":"` + identifier + `","credential_endpoint":"` + identifier + `/credential"}`
	})

	receiver := &Oid4vciReceiver{
		HTTPClient: client,
		AllowHTTP:  true,
		IssuerMetadataSigning: &IssuerMetadataSigningOptions{
			Request:                     true,
			Require:                     true,
			TrustAnchors:                []*x509.Certificate{fixture.caCert},
			AllowUnadvertisedRevocation: true,
		},
	}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err == nil {
		t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
	}
	if !errors.Is(err, ErrIssuerMetadataSignatureRequired) {
		t.Fatalf("errors.Is(ErrIssuerMetadataSignatureRequired) = false, err = %v", err)
	}

	t.Run("requiring signed metadata without trust material is a configuration error", func(t *testing.T) {
		unconfigured := &Oid4vciReceiver{
			HTTPClient:            client,
			AllowHTTP:             true,
			IssuerMetadataSigning: &IssuerMetadataSigningOptions{Require: true},
		}
		_, err := unconfigured.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
		if !errors.Is(err, ErrIssuerMetadataSignatureRequired) ||
			!strings.Contains(err.Error(), "no trust anchors are configured") {
			t.Fatalf("error = %v", err)
		}
	})
}

// HAIP §4.1 makes signed metadata conditional -- "When Ecosystem policies
// require Issuer Authentication to a higher level than possible with TLS alone"
// -- so a HAIP wallet must still accept the unsigned document every Credential
// Issuer publishes.
func TestFetchIssuerMetadataHAIPAcceptsUnsignedByDefault(t *testing.T) {
	serverURL, client, acceptHeader := serveIssuerMetadata(t, true, func(identifier string) (string, string) {
		return "application/json", `{"credential_issuer":"` + identifier + `","credential_endpoint":"` + identifier + `/credential"}`
	})

	receiver := &Oid4vciReceiver{HTTPClient: client, Profile: profile.HAIP}

	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
	if err != nil {
		t.Fatalf("FetchIssuerMetadata() error = %v", err)
	}
	if metadata.CredentialIssuer != serverURL {
		t.Fatalf("credential_issuer = %q, want %q", metadata.CredentialIssuer, serverURL)
	}
	if metadata.SignedMetadata != "" || metadata.MetadataSignature != nil {
		t.Fatalf("unsigned metadata must not claim a signature: %#v", metadata.MetadataSignature)
	}
	// Without trust material the wallet cannot authenticate a signed document,
	// so it does not ask for one it would have to reject.
	if strings.Contains(acceptHeader(), "application/jwt") {
		t.Fatalf("Accept = %q, want application/json only", acceptHeader())
	}
}

// signedMetadataReceiver builds a wallet that accepts fixture's anchor for
// signed Credential Issuer Metadata, with the caller's extra signing policy.
func signedMetadataReceiver(client *http.Client, fixture signedMetadataFixture, adjust func(*IssuerMetadataSigningOptions)) *Oid4vciReceiver {
	signing := &IssuerMetadataSigningOptions{
		Request:                     true,
		TrustAnchors:                []*x509.Certificate{fixture.caCert},
		AllowUnadvertisedRevocation: true,
	}
	if adjust != nil {
		adjust(signing)
	}
	return &Oid4vciReceiver{HTTPClient: client, AllowHTTP: true, IssuerMetadataSigning: signing}
}

func signedMetadataClaims(identifier string) map[string]any {
	return map[string]any{
		"sub":                 identifier,
		"iat":                 time.Now().Add(-time.Minute).Unix(),
		"credential_issuer":   identifier,
		"credential_endpoint": identifier + "/credential",
	}
}

// TestFetchIssuerMetadataBindsSignerToIssuerHost pins the ecosystem binding
// IssuerMetadataSigningOptions.RequireIssuerDNSBinding asks for: the chain
// authenticates the signer against the configured anchors, and the dNSName SAN
// is what says which Credential Issuer that signer may speak for.
func TestFetchIssuerMetadataBindsSignerToIssuerHost(t *testing.T) {
	t.Run("a leaf carrying the issuer host is accepted", func(t *testing.T) {
		fixture := newSignedMetadataFixtureWithDNSNames(t, "127.0.0.1")
		serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
			return "application/jwt", fixture.sign(t, signedMetadataClaims(identifier), []*x509.Certificate{fixture.leaf})
		})
		receiver := signedMetadataReceiver(client, fixture, func(signing *IssuerMetadataSigningOptions) {
			signing.RequireIssuerDNSBinding = true
		})

		metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
		if err != nil {
			t.Fatalf("FetchIssuerMetadata() error = %v", err)
		}
		verification := metadata.MetadataSignature
		if verification == nil {
			t.Fatal("MetadataSignature is nil")
		}
		leafDigest := sha256.Sum256(fixture.leaf.Raw)
		anchorDigest := sha256.Sum256(fixture.caCert.Raw)
		want := []string{hex.EncodeToString(leafDigest[:]), hex.EncodeToString(anchorDigest[:])}
		if !slices.Equal(verification.CertificateSHA256, want) {
			t.Fatalf("CertificateSHA256 = %v, want the accepted path %v", verification.CertificateSHA256, want)
		}
		if verification.AnchorSHA256 != want[1] {
			t.Fatalf("AnchorSHA256 = %q, want the anchor the path reached %q", verification.AnchorSHA256, want[1])
		}
		if verification.LeafCertificateSHA256 != want[0] {
			t.Fatalf("LeafCertificateSHA256 = %q", verification.LeafCertificateSHA256)
		}
	})

	t.Run("a leaf without the issuer host is rejected", func(t *testing.T) {
		fixture := newSignedMetadataFixtureWithDNSNames(t, "issuer.example")
		serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
			return "application/jwt", fixture.sign(t, signedMetadataClaims(identifier), []*x509.Certificate{fixture.leaf})
		})
		receiver := signedMetadataReceiver(client, fixture, func(signing *IssuerMetadataSigningOptions) {
			signing.RequireIssuerDNSBinding = true
		})

		metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
		if err == nil {
			t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
		}
		if !errors.Is(err, ErrIssuerMetadataLeafDNSMismatch) || !errors.Is(err, ErrIssuerMetadataSignatureInvalid) {
			t.Fatalf("error = %v, want the DNS binding and the umbrella sentinel", err)
		}

		// The same document is accepted when the caller names the DNS name the
		// ecosystem binds the signer to instead of the identifier's host.
		named := signedMetadataReceiver(client, fixture, func(signing *IssuerMetadataSigningOptions) {
			signing.ExpectedLeafDNSName = "issuer.example"
		})
		if _, err := named.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci); err != nil {
			t.Fatalf("FetchIssuerMetadata() with ExpectedLeafDNSName error = %v", err)
		}
	})

	// Without the binding the signer is authenticated by the chain alone, which
	// is what §12.2.3 itself requires; a wallet that did not opt in keeps
	// accepting a leaf with no dNSName SAN.
	t.Run("the binding is not applied unless it is asked for", func(t *testing.T) {
		fixture := newSignedMetadataFixture(t)
		serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
			return "application/jwt", fixture.sign(t, signedMetadataClaims(identifier), []*x509.Certificate{fixture.leaf})
		})
		if _, err := signedMetadataReceiver(client, fixture, nil).
			FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci); err != nil {
			t.Fatalf("FetchIssuerMetadata() error = %v", err)
		}
	})
}

// TestFetchIssuerMetadataReportsTypedSignatureFailures pins that every §12.2.3
// rejection is recoverable with errors.Is, so a caller reports the condition
// instead of matching message text.
func TestFetchIssuerMetadataReportsTypedSignatureFailures(t *testing.T) {
	cases := []struct {
		name     string
		document func(t *testing.T, fixture signedMetadataFixture, identifier string) (string, string)
		want     []error
		notWant  []error
	}{
		{
			name: "sub names another credential issuer",
			document: func(t *testing.T, fixture signedMetadataFixture, identifier string) (string, string) {
				claims := signedMetadataClaims(identifier)
				claims["sub"] = "https://other-issuer.example"
				return "application/jwt", fixture.sign(t, claims, []*x509.Certificate{fixture.leaf})
			},
			want: []error{ErrIssuerMetadataSubjectMismatch, ErrIssuerMetadataSignatureInvalid},
		},
		{
			name: "typ is not the signed metadata media type",
			document: func(t *testing.T, fixture signedMetadataFixture, identifier string) (string, string) {
				return "application/jwt", fixture.signWithType(t, "jwt", signedMetadataClaims(identifier),
					[]*x509.Certificate{fixture.leaf})
			},
			want: []error{ErrIssuerMetadataSignatureInvalid},
		},
		{
			name: "exp has passed",
			document: func(t *testing.T, fixture signedMetadataFixture, identifier string) (string, string) {
				claims := signedMetadataClaims(identifier)
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
				return "application/jwt", fixture.sign(t, claims, []*x509.Certificate{fixture.leaf})
			},
			want: []error{ErrIssuerMetadataExpired, ErrIssuerMetadataSignatureInvalid},
		},
		{
			name: "the signer is not anchored",
			document: func(t *testing.T, _ signedMetadataFixture, identifier string) (string, string) {
				foreign := newSignedMetadataFixture(t)
				return "application/jwt", foreign.sign(t, signedMetadataClaims(identifier),
					[]*x509.Certificate{foreign.leaf})
			},
			want: []error{ErrIssuerMetadataSignatureInvalid},
		},
		{
			name: "the issuer answers unsigned while signed metadata is required",
			document: func(_ *testing.T, _ signedMetadataFixture, identifier string) (string, string) {
				return "application/json", `{"credential_issuer":"` + identifier + `","credential_endpoint":"` + identifier + `/credential"}`
			},
			want: []error{ErrIssuerMetadataSignatureRequired},
			// A policy outcome is not a rejected signature: nothing was signed.
			notWant: []error{ErrIssuerMetadataSignatureInvalid},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newSignedMetadataFixture(t)
			serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
				return testCase.document(t, fixture, identifier)
			})
			receiver := signedMetadataReceiver(client, fixture, func(signing *IssuerMetadataSigningOptions) {
				signing.Require = true
			})

			metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
			if err == nil {
				t.Fatalf("FetchIssuerMetadata() = %#v, want an error", metadata)
			}
			for _, sentinel := range testCase.want {
				if !errors.Is(err, sentinel) {
					t.Fatalf("errors.Is(err, %v) = false, err = %v", sentinel, err)
				}
			}
			for _, sentinel := range testCase.notWant {
				if errors.Is(err, sentinel) {
					t.Fatalf("errors.Is(err, %v) = true, err = %v", sentinel, err)
				}
			}
		})
	}

	t.Run("requiring signed metadata without trust material is reported the same way", func(t *testing.T) {
		serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
			return "application/json", `{"credential_issuer":"` + identifier + `"}`
		})
		unconfigured := &Oid4vciReceiver{
			HTTPClient:            client,
			AllowHTTP:             true,
			IssuerMetadataSigning: &IssuerMetadataSigningOptions{Require: true},
		}
		_, err := unconfigured.FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
		if !errors.Is(err, ErrIssuerMetadataSignatureRequired) {
			t.Fatalf("error = %v", err)
		}
	})
}

// TestFetchIssuerMetadataKeepsTheAcceptedDocument pins that the bytes the
// Credential Issuer published survive the fetch. §12.2.2 allows metadata
// members this library does not model, so a caller that stores or re-displays
// the document must not have to re-serialize the parsed struct.
func TestFetchIssuerMetadataKeepsTheAcceptedDocument(t *testing.T) {
	for _, signedResponse := range []bool{false, true} {
		t.Run(fmt.Sprintf("signed=%v", signedResponse), func(t *testing.T) {
			fixture := newSignedMetadataFixture(t)
			var published string
			serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
				claims := signedMetadataClaims(identifier)
				claims["jwks_uri"] = identifier + "/jwks"
				if !signedResponse {
					encoded, err := json.Marshal(claims)
					if err != nil {
						t.Fatal(err)
					}
					published = string(encoded)
					return "application/json", published
				}
				published = fixture.sign(t, claims, []*x509.Certificate{fixture.leaf})
				return "application/jwt", published
			})

			metadata, err := signedMetadataReceiver(client, fixture, nil).
				FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
			if err != nil {
				t.Fatalf("FetchIssuerMetadata() error = %v", err)
			}
			var document map[string]any
			if err := json.Unmarshal(metadata.RawDocument, &document); err != nil {
				t.Fatalf("RawDocument = %q: %v", metadata.RawDocument, err)
			}
			if document["jwks_uri"] != serverURL+"/jwks" {
				t.Fatalf("RawDocument dropped the unmodeled member: %v", document)
			}
			if document["credential_issuer"] != serverURL {
				t.Fatalf("RawDocument = %v, want the accepted document", document)
			}
		})
	}
}

// RFC 8414 Section 3.3: "The "issuer" value returned MUST be identical to the
// authorization server's issuer identifier value into which the well-known URI
// string was inserted to create the URL used to retrieve the metadata. If
// these values are not identical, the data contained in the response MUST NOT
// be used." Every caller, Draft 13 included, gets the check from the plugin.
func TestAuthorizationServerMetadataIssuerMustMatch(t *testing.T) {
	var published string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":"https://as.example/token"}`, published)
	}))
	defer server.Close()
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}

	for name, tc := range map[string]struct {
		endpoint, issuer string
		ok               bool
	}{
		"identical":                       {endpoint: server.URL + "/as", issuer: server.URL + "/as", ok: true},
		"another issuer":                  {endpoint: server.URL + "/as", issuer: "https://attacker.example/as"},
		"trailing slash differs":          {endpoint: server.URL + "/as", issuer: server.URL + "/as/"},
		"well-known endpoint, identical":  {endpoint: server.URL + "/.well-known/oauth-authorization-server/as", issuer: server.URL + "/as", ok: true},
		"well-known endpoint, other path": {endpoint: server.URL + "/.well-known/oauth-authorization-server/as", issuer: server.URL + "/other"},
	} {
		t.Run(name, func(t *testing.T) {
			published = tc.issuer
			endpoint, err := common.ParseURIField(tc.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := receiver.FetchAuthorizationServerMetadata(*endpoint, types.Oid4vci)
			if tc.ok {
				if err != nil || metadata.Issuer.String() != tc.issuer {
					t.Fatalf("metadata = %+v, err = %v", metadata, err)
				}
				return
			}
			if !errors.Is(err, ErrAuthorizationServerIssuerMismatch) || metadata != nil {
				t.Fatalf("metadata = %+v, err = %v; want ErrAuthorizationServerIssuerMismatch", metadata, err)
			}
		})
	}
}
