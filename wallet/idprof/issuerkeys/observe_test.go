package issuerkeys

import (
	"context"
	"net/http"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/observetest"
)

// TestObserveLabelsIssuerKeyMaterialFetches: every fetch of the ladder (JWT VC
// Issuer Metadata, the jwks_uri it names, a did:web document and a DID
// Configuration) is labelled as issuer key material.
func TestObserveLabelsIssuerKeyMaterialFetches(t *testing.T) {
	t.Parallel()
	const configurationPath = "/.well-known/did-configuration.json"
	for name, test := range map[string]struct {
		arrange   func(t *testing.T, f *ladderFixture) Request
		wantPaths []string
	}{
		"JWT VC Issuer Metadata and its jwks_uri": {
			arrange: func(t *testing.T, f *ladderFixture) Request {
				f.origin.json(t, "/.well-known/jwt-vc-issuer/tenant", map[string]any{
					"issuer": f.issuer, "jwks_uri": f.origin.url() + "/jwks.json",
				})
				f.origin.json(t, "/jwks.json", jwksObject(t, f.signer.public))
				return f.sdJWTRequest()
			},
			wantPaths: []string{"/.well-known/jwt-vc-issuer/tenant", "/jwks.json"},
		},
		"a did:web document": {
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := f.origin.didWeb("bank")
				f.origin.json(t, "/bank/did.json", didWebDocument(t, didValue, "issuer-key-1", f.signer.public))
				request := f.jwtVCRequest(didValue, didValue+"#issuer-key-1")
				request.IssuerMetadataJWKS = keySet(f.signer.public)
				return request
			},
			wantPaths: []string{"/bank/did.json"},
		},
		"a DID Configuration": {
			arrange: func(t *testing.T, f *ladderFixture) Request {
				didValue := didJWK(t, f.signer.public)
				header, claims := domainLinkage(didValue, didValue+"#0", f.originString())
				f.origin.json(t, configurationPath, map[string]any{
					"@context":    "https://identity.foundation/.well-known/did-configuration/v1",
					"linked_dids": []any{signJWT(t, f.signer, header, claims)},
				})
				return f.jwtVCRequest(didValue, didValue+"#0")
			},
			wantPaths: []string{configurationPath},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newLadderFixture(t)
			resolver := f.origin.resolver(allMechanisms())
			recorder := &observetest.Recorder{}
			client := *resolver.HTTPClient
			client.Transport = observe.Transport(client.Transport, recorder)
			resolver.HTTPClient = &client
			request := test.arrange(t, f)

			if _, err := resolver.Resolve(context.Background(), request); err != nil {
				t.Fatalf("Resolve failed: %v", err)
			}

			exchanges := recorder.Exchanges()
			if len(exchanges) != len(test.wantPaths) {
				t.Fatalf("recorded %d exchanges, want %d: %+v", len(exchanges), len(test.wantPaths), exchanges)
			}
			for i, exchange := range exchanges {
				if exchange.Endpoint != observe.EndpointIssuerKeyMaterial || exchange.Request.Method != http.MethodGet || exchange.Request.URL.Path != test.wantPaths[i] {
					t.Errorf("exchange %d = %s %s labelled %q, want GET %s labelled %q",
						i, exchange.Request.Method, exchange.Request.URL.Path, exchange.Endpoint, test.wantPaths[i], observe.EndpointIssuerKeyMaterial)
				}
			}
		})
	}
}
