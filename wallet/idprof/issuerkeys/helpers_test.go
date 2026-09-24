package issuerkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/idprof/plugins/did"
)

// testNow is the clock every test resolver reads.
var testNow = time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return testNow }

// allMechanisms enables every rung and binding.
func allMechanisms() Mechanisms {
	return Mechanisms{
		X5C:                     true,
		JWTVCIssuerMetadata:     true,
		RemoteJWKS:              true,
		DIDKey:                  true,
		DIDJWK:                  true,
		DIDWeb:                  true,
		DIDConfiguration:        true,
		CredentialIssuerBinding: true,
		IssuerMetadataJWKS:      true,
	}
}

// testKey is a signing key and its public JWK.
type testKey struct {
	private crypto.Signer
	public  jose.JSONWebKey
	alg     jose.SignatureAlgorithm
}

func newES256Key(t *testing.T, kid string) testKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{private: private, public: jose.JSONWebKey{Key: &private.PublicKey, KeyID: kid}, alg: jose.ES256}
}

func newEd25519Key(t *testing.T, kid string) testKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{private: private, public: jose.JSONWebKey{Key: public, KeyID: kid}, alg: jose.EdDSA}
}

// withKeyID returns key's public JWK under another `kid` (and `alg`, when set).
func (k testKey) withKeyID(kid string, alg string) jose.JSONWebKey {
	public := k.public
	public.KeyID = kid
	public.Algorithm = alg
	return public
}

// jwkMap is a key's JSON representation as a generic object, the form a
// metadata document or a DID document carries it in.
func jwkMap(t *testing.T, key jose.JSONWebKey) map[string]any {
	t.Helper()
	raw, err := key.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func jwksObject(t *testing.T, keys ...jose.JSONWebKey) map[string]any {
	t.Helper()
	entries := make([]any, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, jwkMap(t, key))
	}
	return map[string]any{"keys": entries}
}

func keySet(keys ...jose.JSONWebKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: keys}
}

func didJWK(t *testing.T, key jose.JSONWebKey) string {
	t.Helper()
	public := key
	public.KeyID = ""
	raw, err := public.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return "did:jwk:" + base64.RawURLEncoding.EncodeToString(raw)
}

func didKey(t *testing.T, key jose.JSONWebKey) string {
	t.Helper()
	profile, err := did.NewDIDKeyProfile(&did.DIDKeyProfileCreateOptions{PublicKey: &key})
	if err != nil {
		t.Fatal(err)
	}
	return profile.ID
}

// signJWT signs claims as a compact JWS with the given protected header
// members (`alg` is set from the key).
func signJWT(t *testing.T, key testKey, header map[string]any, claims map[string]any) string {
	t.Helper()
	options := &jose.SignerOptions{}
	for name, value := range header {
		options = options.WithHeader(jose.HeaderKey(name), value)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: key.alg, Key: key.private}, options)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// domainLinkage returns the header and claims of a DIF Well Known DID
// Configuration Domain Linkage Credential in JWT form, for a test to adjust.
func domainLinkage(didValue, kid, origin string) (map[string]any, map[string]any) {
	header := map[string]any{"kid": kid}
	claims := map[string]any{
		"iss": didValue,
		"sub": didValue,
		"nbf": testNow.Add(-24 * time.Hour).Unix(),
		"exp": testNow.Add(24 * time.Hour).Unix(),
		"vc": map[string]any{
			"@context":          []any{"https://www.w3.org/2018/credentials/v1", "https://identity.foundation/.well-known/did-configuration/v1"},
			"type":              []any{"VerifiableCredential", "DomainLinkageCredential"},
			"issuer":            didValue,
			"issuanceDate":      testNow.Add(-24 * time.Hour).Format(time.RFC3339),
			"expirationDate":    testNow.Add(24 * time.Hour).Format(time.RFC3339),
			"credentialSubject": map[string]any{"id": didValue, "origin": origin},
		},
	}
	return header, claims
}

// testRoute is one canned response of a testOrigin.
type testRoute struct {
	status      int
	contentType string
	body        []byte
	headers     map[string]string
	// chunked streams body without a Content-Length.
	chunked bool
}

// testOrigin is an https origin serving canned documents, which records every
// request it receives.
type testOrigin struct {
	server *httptest.Server

	mu       sync.Mutex
	routes   map[string]testRoute
	requests []string
	accepts  map[string]string
}

func newTestOrigin(t *testing.T) *testOrigin {
	t.Helper()
	origin := &testOrigin{routes: map[string]testRoute{}, accepts: map[string]string{}}
	origin.server = httptest.NewTLSServer(http.HandlerFunc(origin.serve))
	t.Cleanup(origin.server.Close)
	return origin
}

// newPlainTestOrigin is a testOrigin over plain http, for the AllowHTTP cases.
func newPlainTestOrigin(t *testing.T) *testOrigin {
	t.Helper()
	origin := &testOrigin{routes: map[string]testRoute{}, accepts: map[string]string{}}
	origin.server = httptest.NewServer(http.HandlerFunc(origin.serve))
	t.Cleanup(origin.server.Close)
	return origin
}

func (o *testOrigin) serve(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	o.requests = append(o.requests, r.URL.Path)
	o.accepts[r.URL.Path] = r.Header.Get("Accept")
	route, ok := o.routes[r.URL.Path]
	o.mu.Unlock()
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{}`))
		return
	}
	for name, value := range route.headers {
		w.Header().Set(name, value)
	}
	if route.contentType != "" {
		w.Header().Set("Content-Type", route.contentType)
	}
	if !route.chunked && w.Header().Get("Content-Length") == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(route.body)))
	}
	status := route.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if route.chunked {
		flusher, _ := w.(http.Flusher)
		for start := 0; start < len(route.body); start += 256 {
			end := min(start+256, len(route.body))
			_, _ = w.Write(route.body[start:end])
			if flusher != nil {
				flusher.Flush()
			}
		}
		return
	}
	_, _ = w.Write(route.body)
}

func (o *testOrigin) set(path string, route testRoute) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.routes[path] = route
}

func (o *testOrigin) json(t *testing.T, path string, value any) {
	t.Helper()
	o.jsonAs(t, path, "application/json", value)
}

func (o *testOrigin) jsonAs(t *testing.T, path, contentType string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	o.set(path, testRoute{contentType: contentType, body: body})
}

func (o *testOrigin) url() string { return o.server.URL }

// hostPort is the origin's authority, e.g. 127.0.0.1:43210.
func (o *testOrigin) hostPort() string { return o.server.Listener.Addr().String() }

// didWeb names a did:web DID hosted by this origin under path.
func (o *testOrigin) didWeb(path ...string) string {
	parts := append([]string{strings.ReplaceAll(o.hostPort(), ":", "%3A")}, path...)
	return "did:web:" + strings.Join(parts, ":")
}

func (o *testOrigin) requested(path string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	count := 0
	for _, requested := range o.requests {
		if requested == path {
			count++
		}
	}
	return count
}

func (o *testOrigin) requestCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.requests)
}

func (o *testOrigin) accept(path string) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.accepts[path]
}

func (o *testOrigin) resolver(mechanisms Mechanisms) *Resolver {
	return &Resolver{HTTPClient: o.server.Client(), Mechanisms: mechanisms, Now: fixedNow}
}

// failingTransport fails every request, for a test that asserts the ladder made
// none.
type failingTransport struct {
	mu    sync.Mutex
	calls int
}

func (f *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return nil, errors.New("unexpected request")
}

func (f *failingTransport) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// diagnosticsOf returns the per-rung diagnostics of a resolution or of the
// error Resolve returned.
func diagnosticsOf(t *testing.T, resolution *Resolution, err error) []MechanismDiagnostic {
	t.Helper()
	if err == nil {
		return resolution.Diagnostics
	}
	var unresolved *UnresolvedError
	if errors.As(err, &unresolved) {
		return unresolved.Diagnostics
	}
	var didOnly *DIDOnlyTrustError
	if errors.As(err, &didOnly) {
		return didOnly.Diagnostics
	}
	t.Fatalf("error %v carries no diagnostics", err)
	return nil
}

func diagnosticFor(t *testing.T, diagnostics []MechanismDiagnostic, rung string) MechanismDiagnostic {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Mechanism == rung {
			return diagnostic
		}
	}
	t.Fatalf("no %q diagnostic in %+v", rung, diagnostics)
	return MechanismDiagnostic{}
}

func mechanismsOf(candidates []Candidate) []Mechanism {
	mechanisms := make([]Mechanism, 0, len(candidates))
	for _, candidate := range candidates {
		mechanisms = append(mechanisms, candidate.Mechanism)
	}
	return mechanisms
}

// testCertificate is a certificate and its signing key.
type testCertificate struct {
	certificate *x509.Certificate
	key         crypto.Signer
}

// newTestCA returns a self-signed CA certificate valid around testNow.
func newTestCA(t *testing.T, name string) testCertificate {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return createCertificate(t, template, nil, private)
}

// newTestLeaf returns an end-entity signing certificate for dnsNames issued by
// parent.
func newTestLeaf(t *testing.T, parent testCertificate, dnsNames ...string) testCertificate {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "issuer signing key"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		DNSNames:              dnsNames,
	}
	return createCertificate(t, template, &parent, private)
}

func createCertificate(t *testing.T, template *x509.Certificate, parent *testCertificate, key crypto.Signer) testCertificate {
	t.Helper()
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
	return testCertificate{certificate: certificate, key: key}
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

// x5cOf is the `x5c` header value of certificates.
func x5cOf(certificates ...testCertificate) []string {
	chain := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		chain = append(chain, base64.StdEncoding.EncodeToString(certificate.certificate.Raw))
	}
	return chain
}

// leafJWK is the public key of a certificate as a JWK.
func leafJWK(certificate testCertificate, kid string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: certificate.certificate.PublicKey, KeyID: kid}
}
