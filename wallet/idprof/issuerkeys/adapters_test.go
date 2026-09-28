package issuerkeys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// stubTransport answers GET requests from canned JSON documents keyed by URL
// and refuses every other request, so a fixture can publish documents under
// any https origin without a network.
type stubTransport struct {
	mu        sync.Mutex
	documents map[string]any
}

func newStubTransport() *stubTransport {
	return &stubTransport{documents: map[string]any{}}
}

func (s *stubTransport) publish(url string, document any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents[url] = document
}

func (s *stubTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	s.mu.Lock()
	document, ok := s.documents[request.URL.String()]
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("unexpected request")
	}
	body, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}, nil
}

func TestResolutionCandidateFor(t *testing.T) {
	t.Parallel()
	signer := newES256Key(t, "issuer-key-1")
	network := newStubTransport()
	network.publish("https://issuer.example.test/.well-known/jwt-vc-issuer", map[string]any{
		"issuer": "https://issuer.example.test", "jwks": jwksObject(t, signer.public),
	})
	resolver := &Resolver{HTTPClient: &http.Client{Transport: network}, Mechanisms: Mechanisms{JWTVCIssuerMetadata: true}, Now: fixedNow}
	resolution, err := resolver.Resolve(context.Background(), Request{
		Issuer: "https://issuer.example.test", Algorithm: "ES256",
		CredentialFormat: FormatSDJWTVC, CredentialIssuer: "https://issuer.example.test",
	})
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	// The verified key comes back from the acceptor without its kid; the
	// thumbprint still finds its candidate.
	candidate, ok := resolution.CandidateFor(jose.JSONWebKey{Key: signer.public.Key})
	if !ok || candidate.Mechanism != MechanismJWTVCIssuerMetadata || candidate.Issuer != "https://issuer.example.test" {
		t.Errorf("CandidateFor = %+v, %v", candidate, ok)
	}
	if _, ok := resolution.CandidateFor(newES256Key(t, "").public); ok {
		t.Errorf("CandidateFor found a key the resolver never produced")
	}
}
