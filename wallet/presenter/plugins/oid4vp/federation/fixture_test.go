package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/trustknots/vcknots/wallet/common"
)

// testNow is the fixed validation time of the tests.
var testNow = time.Date(2026, 5, 19, 4, 0, 0, 0, time.UTC)

// testIssuedAt is one minute before testNow.
var testIssuedAt = testNow.Unix() - 60

type signingKey struct {
	kid     string
	private *ecdsa.PrivateKey
	jwks    jose.JSONWebKeySet
}

func newSigningKey(t *testing.T, kid string) signingKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := jose.JSONWebKey{Key: &private.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
	return signingKey{kid: kid, private: private, jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}}}
}

// statement describes one Entity Statement a test signs. Nil optional claims
// are left out of the payload.
type statement struct {
	issuer, subject    string
	jwks               jose.JSONWebKeySet
	issuedAt, expires  int64
	metadata           any
	metadataPolicy     any
	metadataPolicyCrit any
	constraints        any
	authorityHints     any
	crit               any
	extra              map[string]any
}

// header overrides the protected header of a signed statement.
type header struct {
	omitKid bool
	typ     string
}

func signStatement(t *testing.T, s statement, key signingKey, h header) string {
	t.Helper()
	claims := map[string]any{}
	for name, value := range s.extra {
		claims[name] = value
	}
	claims["iss"], claims["sub"] = s.issuer, s.subject
	claims["iat"], claims["exp"] = s.issuedAt, s.expires
	claims["jwks"] = s.jwks
	for name, value := range map[string]any{
		"metadata": s.metadata, "metadata_policy": s.metadataPolicy,
		"metadata_policy_crit": s.metadataPolicyCrit, "constraints": s.constraints,
		"authority_hints": s.authorityHints, "crit": s.crit,
	} {
		if value != nil {
			claims[name] = value
		}
	}
	typ := h.typ
	if typ == "" {
		typ = entityStatementTyp
	}
	var signingKeyValue any = jose.JSONWebKey{Key: key.private, KeyID: key.kid}
	if h.omitKid {
		signingKeyValue = key.private
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: signingKeyValue},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)),
	)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// requireCode asserts err wraps sentinel and mentions every fragment.
func requireCode(t *testing.T, err error, sentinel error, fragments ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %v, got success", sentinel)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected %v, got %v", sentinel, err)
	}
	code, _ := common.CodeOf(err)
	if want, _ := common.CodeOf(sentinel); code != want {
		t.Fatalf("expected code %q, got %q", want, code)
	}
	for _, fragment := range fragments {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q does not mention %q", err, fragment)
		}
	}
}

// federationServer serves Entity Statements by URL from one TLS server, so
// Entity Identifiers of the tests are paths on it.
type federationServer struct {
	*httptest.Server
	mu        sync.Mutex
	responses map[string]string
	requests  []string
	accepts   []string
}

func newFederationServer(t *testing.T) *federationServer {
	t.Helper()
	server := &federationServer{responses: map[string]string{}}
	server.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested := "https://" + r.Host + r.URL.RequestURI()
		server.mu.Lock()
		server.requests = append(server.requests, requested)
		server.accepts = append(server.accepts, r.Header.Get("Accept"))
		body, ok := server.responses[requested]
		server.mu.Unlock()
		if !ok {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", entityStatementMediaType)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func (s *federationServer) entity(name string) string { return s.URL + "/" + name }

func (s *federationServer) fetchEndpoint(name string) string { return s.URL + "/" + name + "/fetch" }

// serveConfiguration publishes the Entity Configuration of entityID.
func (s *federationServer) serveConfiguration(t *testing.T, entityID, jwt string) {
	t.Helper()
	statementURL, err := EntityConfigurationURL(entityID)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.responses[statementURL] = jwt
	s.mu.Unlock()
}

// serveSubordinate publishes a Subordinate Statement at a fetch endpoint.
func (s *federationServer) serveSubordinate(t *testing.T, endpoint, subject, jwt string) {
	t.Helper()
	statementURL, err := SubordinateStatementURL(endpoint, subject)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.responses[statementURL] = jwt
	s.mu.Unlock()
}

func (s *federationServer) remove(t *testing.T, entityID string) {
	t.Helper()
	statementURL, err := EntityConfigurationURL(entityID)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	delete(s.responses, statementURL)
	s.mu.Unlock()
}

func (s *federationServer) requested() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

func (s *federationServer) resolver(anchors ...TrustAnchor) *Resolver {
	return &Resolver{HTTPClient: s.Client(), TrustAnchors: anchors, Now: func() time.Time { return testNow }}
}

func fetchEndpointMetadata(endpoint string) map[string]any {
	return map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": endpoint}}
}

// directFederation is a verifier directly below the anchor, discoverable
// through the server.
type directFederation struct {
	server           *federationServer
	verifier, anchor string
	verifierKey      signingKey
	anchorKey        signingKey
	chain            []string
}

type directOptions struct {
	verifierMetadata  map[string]any
	subordinatePolicy map[string]any
	anchorMetadata    map[string]any
	verifierKid       string
}

func newDirectFederation(t *testing.T, opts directOptions) *directFederation {
	t.Helper()
	server := newFederationServer(t)
	f := &directFederation{server: server, verifier: server.entity("verifier"), anchor: server.entity("anchor")}
	kid := opts.verifierKid
	if kid == "" {
		kid = "verifier-key"
	}
	f.verifierKey = newSigningKey(t, kid)
	f.anchorKey = newSigningKey(t, "anchor-key")
	if opts.verifierMetadata == nil {
		opts.verifierMetadata = map[string]any{VerifierEntityType: map[string]any{"client_name": "Original verifier"}}
	}
	if opts.anchorMetadata == nil {
		opts.anchorMetadata = fetchEndpointMetadata(server.fetchEndpoint("anchor"))
	}
	configuration := signStatement(t, statement{
		issuer: f.verifier, subject: f.verifier, jwks: f.verifierKey.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 600,
		authorityHints: []string{f.anchor}, metadata: opts.verifierMetadata,
	}, f.verifierKey, header{})
	var policy any
	if opts.subordinatePolicy != nil {
		policy = opts.subordinatePolicy
	}
	subordinate := signStatement(t, statement{
		issuer: f.anchor, subject: f.verifier, jwks: f.verifierKey.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 300, metadataPolicy: policy,
	}, f.anchorKey, header{})
	anchorConfiguration := signStatement(t, statement{
		issuer: f.anchor, subject: f.anchor, jwks: f.anchorKey.jwks,
		issuedAt: testIssuedAt, expires: testIssuedAt + 900, metadata: opts.anchorMetadata,
	}, f.anchorKey, header{})
	server.serveConfiguration(t, f.verifier, configuration)
	server.serveConfiguration(t, f.anchor, anchorConfiguration)
	server.serveSubordinate(t, server.fetchEndpoint("anchor"), f.verifier, subordinate)
	f.chain = []string{configuration, subordinate, anchorConfiguration}
	return f
}

func (f *directFederation) anchors() []TrustAnchor {
	return []TrustAnchor{{EntityID: f.anchor, JWKS: f.anchorKey.jwks}}
}

func (f *directFederation) resolver() *Resolver { return f.server.resolver(f.anchors()...) }

func statementPairs(chain *TrustChain) [][2]string {
	pairs := make([][2]string, len(chain.Statements))
	for i, s := range chain.Statements {
		pairs[i] = [2]string{s.Issuer, s.Subject}
	}
	return pairs
}
