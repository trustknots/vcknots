package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/trustknots/vcknots/wallet/profile"
)

type requestObjectFixture struct {
	root, leaf    *x509.Certificate
	rootKey, key  *ecdsa.PrivateKey
	now           time.Time
	server        *httptest.Server
	mu            sync.RWMutex
	crl           []byte
	crlRequests   int
	requestObject []byte
	// requestObjectHandler, when set, serves /request-object instead of the
	// static requestObject. It lets a test sign a Request Object from the
	// received request_uri POST form (for example to echo wallet_nonce).
	requestObjectHandler http.HandlerFunc
}

func newRequestObjectFixture(t *testing.T, dnsNames ...string) *requestObjectFixture {
	t.Helper()
	f := &requestObjectFixture{now: time.Now().UTC().Truncate(time.Second)}
	var err error
	f.rootKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Verifier test root"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &f.rootKey.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	f.root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f.setCRL(t, false)
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.RLock()
		crl := f.crl
		requestObject := f.requestObject
		requestObjectHandler := f.requestObjectHandler
		f.mu.RUnlock()
		switch r.URL.Path {
		case "/root.crl":
			f.mu.Lock()
			f.crlRequests++
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(crl)
		case "/request-object":
			if requestObjectHandler != nil {
				requestObjectHandler(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
			_, _ = w.Write(requestObject)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Verifier signing key"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		DNSNames: dnsNames, CRLDistributionPoints: []string{f.server.URL + "/root.crl"},
	}
	der, err = x509.CreateCertificate(rand.Reader, leaf, f.root, &f.key.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	f.leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *requestObjectFixture) setCRL(t *testing.T, revoked bool) {
	t.Helper()
	list := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: f.now.Add(-time.Minute), NextUpdate: f.now.Add(time.Hour)}
	if revoked {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: f.now.Add(-time.Minute)}}
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, f.root, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.crl = der
	f.mu.Unlock()
}

func (f *requestObjectFixture) setRequestObjectHandler(handler http.HandlerFunc) {
	f.mu.Lock()
	f.requestObjectHandler = handler
	f.mu.Unlock()
}

func (f *requestObjectFixture) clientID() string {
	hash := sha256.Sum256(f.leaf.Raw)
	return "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
}

func (f *requestObjectFixture) options() RequestObjectValidationOptions {
	return RequestObjectValidationOptions{TrustAnchors: []*x509.Certificate{f.root}, Now: func() time.Time { return f.now }}
}

func (f *requestObjectFixture) presenter() *Oid4vpPresenter {
	options := f.options()
	return &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options}
}

func (f *requestObjectFixture) claims() map[string]any {
	return map[string]any{
		// The HAIP profile requires a bounded Request Object lifetime, so the
		// shared claims carry one; tests that exercise the missing or
		// excessive case override exp themselves.
		"iat": f.now.Unix(), "exp": f.now.Add(5 * time.Minute).Unix(),
		"aud": "https://self-issued.me/v2", "client_id": f.clientID(),
		"nonce": "nonce", "response_type": "vp_token", "response_mode": "direct_post.jwt",
		"response_uri":    "https://verifier.example/response",
		"client_metadata": responseEncryptionClientMetadataClaim(),
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:eudi:pid:1"}},
		}}},
	}
}

func (f *requestObjectFixture) sign(t *testing.T, claims map[string]any, options *jose.SignerOptions) string {
	t.Helper()
	if options == nil {
		options = (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt").WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: f.key}, options)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (f *requestObjectFixture) parse(t *testing.T, claims map[string]any) (*CredentialPresentationRequest, error) {
	t.Helper()
	uri := "openid4vp://authorize?" + url.Values{"client_id": []string{f.clientID()}, "request": []string{f.sign(t, claims, nil)}}.Encode()
	return f.presenter().ParsePresentationRequest(uri)
}

type requestDelivery string

const (
	deliverByValue     requestDelivery = "value"
	deliverByReference requestDelivery = "reference"
	deliverByQuery     requestDelivery = "query"
)

// requestFixtureOptions selects how a signed Request Object is delivered and
// which Final/HAIP policy the presenter enforces.
type requestFixtureOptions struct {
	Profile      profile.Profile
	Delivery     requestDelivery
	ResponseMode string
	DCQLFormat   string
	IncludeRoot  bool
	AllowHTTP    bool
	Insecure     bool
	// RequireExpiry sets the opt-in hardening option on the validation options.
	RequireExpiry bool
}

func (f *requestObjectFixture) presenterWith(opts requestFixtureOptions) *Oid4vpPresenter {
	validation := f.options()
	validation.RequireExpiry = opts.RequireExpiry
	return &Oid4vpPresenter{
		HTTPClient:              f.server.Client(),
		RequestObjectValidation: &validation,
		Profile:                 opts.Profile,
		AllowHTTP:               opts.AllowHTTP,
		InsecureSkipX509Verify:  opts.Insecure,
	}
}

// parseRequest signs the claims with the fixture certificate and parses the
// Authorization Request using the requested delivery method and profile.
func (f *requestObjectFixture) parseRequest(t *testing.T, claims map[string]any, opts requestFixtureOptions) (*CredentialPresentationRequest, error) {
	t.Helper()
	if opts.ResponseMode != "" {
		claims["response_mode"] = opts.ResponseMode
	}
	if opts.DCQLFormat != "" {
		query := claims["dcql_query"].(map[string]any)
		credentials := query["credentials"].([]any)
		credentials[0].(map[string]any)["format"] = opts.DCQLFormat
		if opts.DCQLFormat == "jwt_vc_json" {
			credentials[0].(map[string]any)["meta"] = map[string]any{"type_values": []any{[]any{"VerifiableCredential"}}}
		}
	}
	clientID, _ := claims["client_id"].(string)

	switch opts.Delivery {
	case deliverByQuery:
		values := url.Values{}
		for key, value := range claims {
			if text, ok := value.(string); ok {
				values.Set(key, text)
				continue
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			values.Set(key, string(encoded))
		}
		return f.presenterWith(opts).ParsePresentationRequest("openid4vp://authorize?" + values.Encode())
	case deliverByReference:
		f.mu.Lock()
		f.requestObject = []byte(f.signWithRoot(t, claims, opts.IncludeRoot))
		f.mu.Unlock()
		uri := "openid4vp://authorize?" + url.Values{
			"client_id":   {clientID},
			"request_uri": {f.server.URL + "/request-object"},
		}.Encode()
		return f.presenterWith(opts).ParsePresentationRequest(uri)
	default:
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {clientID},
			"request":   {f.signWithRoot(t, claims, opts.IncludeRoot)},
		}.Encode()
		return f.presenterWith(opts).ParsePresentationRequest(uri)
	}
}

// signWithRoot signs the claims with x5c containing the leaf, and optionally
// the trust-anchor root as well.
func (f *requestObjectFixture) signWithRoot(t *testing.T, claims map[string]any, includeRoot bool) string {
	t.Helper()
	x5c := []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)}
	if includeRoot {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(f.root.Raw))
	}
	return f.sign(t, claims, (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt").WithHeader("x5c", x5c))
}
