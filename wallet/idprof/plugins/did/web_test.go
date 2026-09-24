package did

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

func TestWebDocumentURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		did  string
		want string
	}{
		{
			name: "a bare domain resolves to the well-known path",
			did:  "did:web:issuer.example.test",
			want: "https://issuer.example.test/.well-known/did.json",
		},
		{
			name: "a single extra part becomes a path segment",
			did:  "did:web:issuer.example.test:bank",
			want: "https://issuer.example.test/bank/did.json",
		},
		{
			name: "several extra parts become several path segments",
			did:  "did:web:issuer.example.test:a:b",
			want: "https://issuer.example.test/a/b/did.json",
		},
		{
			name: "a percent-encoded port reaches the authority",
			did:  "did:web:host%3A8443:a",
			want: "https://host:8443/a/did.json",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			documentURL, err := WebDocumentURL(test.did)
			if err != nil {
				t.Fatalf("WebDocumentURL(%q) failed: %v", test.did, err)
			}
			if got := documentURL.String(); got != test.want {
				t.Fatalf("WebDocumentURL(%q) = %q, want %q", test.did, got, test.want)
			}
		})
	}
}

func TestWebDocumentURLRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		did  string
	}{
		{name: "another method", did: "did:key:z6Mk"},
		{name: "an empty method-specific identifier", did: "did:web:"},
		{name: "an empty part", did: "did:web:issuer.example.test::bank"},
		{name: "an undecodable escape", did: "did:web:issuer.example.test:%zz"},
		{name: "a part carrying a path separator", did: "did:web:issuer.example.test:a%2Fb"},
		{name: "a part carrying a backslash", did: "did:web:issuer.example.test:a%5Cb"},
		{name: "userinfo in the domain part", did: "did:web:user@issuer.example.test"},
		{name: "a space in the domain part", did: "did:web:issuer%20example.test"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := WebDocumentURL(test.did); !errors.Is(err, ErrDIDWebIdentifierInvalid) {
				t.Fatalf("WebDocumentURL(%q) error = %v, want ErrDIDWebIdentifierInvalid", test.did, err)
			}
		})
	}
}

func TestDIDWebPluginResolve(t *testing.T) {
	t.Parallel()

	assertionKey := testPublicJWK(t)
	referencedKey := testPublicJWK(t)
	const identifier = "did:web:issuer.example.test:bank"

	var requestedPath, requestedAccept string
	plugin, _ := newDIDWebTestPlugin(t, func(writer http.ResponseWriter, request *http.Request) {
		requestedPath = request.URL.Path
		requestedAccept = request.Header.Get("Accept")
		writeDIDDocument(t, writer, map[string]any{
			"id": identifier,
			"assertionMethod": []any{
				verificationMethod(t, identifier+"#embedded", assertionKey),
				identifier + "#referenced",
				identifier + "#missing",
			},
			"verificationMethod": []any{
				verificationMethod(t, identifier+"#referenced", referencedKey),
				verificationMethod(t, identifier+"#unreferenced", testPublicJWK(t)),
			},
		})
	})

	profile, err := plugin.Resolve(identifier)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if requestedPath != "/bank/did.json" {
		t.Fatalf("requested path = %q, want %q", requestedPath, "/bank/did.json")
	}
	if !strings.Contains(requestedAccept, "application/did+json") {
		t.Fatalf("Accept header = %q, want it to ask for a DID document", requestedAccept)
	}
	if profile.ID != identifier || profile.TypeID != IDProfileTypeID {
		t.Fatalf("profile = {%q, %q}, want {%q, %q}", profile.ID, profile.TypeID, identifier, IDProfileTypeID)
	}
	if len(profile.Keys.Keys) != 2 {
		t.Fatalf("resolved %d keys, want 2", len(profile.Keys.Keys))
	}
	if got := profile.Keys.Keys[0].KeyID; got != identifier+"#embedded" {
		t.Fatalf("first key id = %q, want %q", got, identifier+"#embedded")
	}
	if got := profile.Keys.Keys[1].KeyID; got != identifier+"#referenced" {
		t.Fatalf("second key id = %q, want %q", got, identifier+"#referenced")
	}
}

func TestDIDWebPluginResolveRejects(t *testing.T) {
	t.Parallel()

	const identifier = "did:web:issuer.example.test"
	key := testPublicJWK(t)

	tests := []struct {
		name     string
		maxBytes int64
		handler  http.HandlerFunc
		want     error
	}{
		{
			name: "a not found status",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusNotFound)
			},
			want: ErrDIDWebDocumentFetchFailed,
		},
		{
			name: "a redirect",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Location", "https://elsewhere.example.test/did.json")
				writer.WriteHeader(http.StatusFound)
			},
			want: ErrDIDWebDocumentFetchFailed,
		},
		{
			name: "a body that is not labelled as a DID document",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "text/plain")
				_, _ = writer.Write([]byte(`{"id":"did:web:issuer.example.test"}`))
			},
			want: ErrDIDWebDocumentFetchFailed,
		},
		{
			name:     "a document larger than the cap",
			maxBytes: 16,
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/did+json")
				_, _ = writer.Write([]byte(`{"id":"did:web:issuer.example.test","padding":"aaaaaaaaaaaaaaaaaaaaaaaa"}`))
			},
			want: ErrDIDWebDocumentFetchFailed,
		},
		{
			name:     "a streamed document larger than the cap",
			maxBytes: 16,
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/did+json")
				writer.(http.Flusher).Flush()
				_, _ = writer.Write([]byte(`{"id":"did:web:issuer.example.test","padding":"aaaaaaaaaaaaaaaaaaaaaaaa"}`))
			},
			want: ErrDIDWebDocumentFetchFailed,
		},
		{
			name: "an empty body",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/did+json")
			},
			want: ErrDIDWebDocumentFetchFailed,
		},
		{
			name: "a body that is not a JSON object",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/did+json")
				_, _ = writer.Write([]byte(`["not an object"]`))
			},
			want: ErrDIDWebDocumentInvalid,
		},
		{
			name: "a media type that only contains a DID document type",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/jsonx")
				_, _ = writer.Write([]byte(`{"id":"did:web:issuer.example.test"}`))
			},
			want: ErrDIDWebDocumentFetchFailed,
		},
		{
			name: "a document without an id",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeDIDDocument(t, writer, map[string]any{"assertionMethod": []any{verificationMethod(t, identifier+"#sign", key)}})
			},
			want: ErrDIDWebDocumentInvalid,
		},
		{
			name: "a document whose id is not a string",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeDIDDocument(t, writer, map[string]any{"id": 7, "assertionMethod": []any{verificationMethod(t, identifier+"#sign", key)}})
			},
			want: ErrDIDWebDocumentInvalid,
		},
		{
			name: "a document that names another DID",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeDIDDocument(t, writer, map[string]any{"id": "did:web:other.example.test"})
			},
			want: ErrDIDWebDocumentInvalid,
		},
		{
			name: "a document with no assertionMethod",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeDIDDocument(t, writer, map[string]any{
					"id":                 identifier,
					"authentication":     []any{identifier + "#login"},
					"verificationMethod": []any{verificationMethod(t, identifier+"#login", key)},
				})
			},
			want: ErrDIDWebNoAssertionKey,
		},
		{
			name: "a document whose assertionMethod is empty",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeDIDDocument(t, writer, map[string]any{
					"id":                 identifier,
					"assertionMethod":    []any{},
					"verificationMethod": []any{verificationMethod(t, identifier+"#sign", key)},
				})
			},
			want: ErrDIDWebNoAssertionKey,
		},
		{
			name: "a verification method that belongs to another DID",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeDIDDocument(t, writer, map[string]any{
					"id":              identifier,
					"assertionMethod": []any{verificationMethod(t, "did:web:other.example.test#sign", key)},
				})
			},
			want: ErrDIDWebNoAssertionKey,
		},
		{
			name: "a verification method with no publicKeyJwk",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writeDIDDocument(t, writer, map[string]any{
					"id": identifier,
					"assertionMethod": []any{map[string]any{
						"id":                 identifier + "#sign",
						"type":               "Multikey",
						"publicKeyMultibase": "z6Mk",
					}},
				})
			},
			want: ErrDIDWebNoAssertionKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plugin, _ := newDIDWebTestPlugin(t, test.handler)
			plugin.MaxDocumentBytes = test.maxBytes

			_, err := plugin.Resolve(identifier)
			if !errors.Is(err, test.want) {
				t.Fatalf("Resolve error = %v, want %v", err, test.want)
			}
			wantCode, _ := common.CodeOf(test.want)
			if code, ok := common.CodeOf(err); !ok || code != wantCode {
				t.Fatalf("CodeOf(err) = %q, want %q", code, wantCode)
			}
		})
	}
}

func TestDIDWebPluginCreateAndUpdateAreUnsupported(t *testing.T) {
	t.Parallel()

	plugin := &DIDWebPlugin{}
	if _, err := plugin.Create(); !errors.Is(err, ErrDIDWebOperationUnsupported) {
		t.Fatalf("Create error = %v, want ErrDIDWebOperationUnsupported", err)
	}
	if _, err := plugin.Update(nil); !errors.Is(err, ErrDIDWebOperationUnsupported) {
		t.Fatalf("Update error = %v, want ErrDIDWebOperationUnsupported", err)
	}
}

func TestDIDWebPluginValidate(t *testing.T) {
	t.Parallel()

	key := testPublicJWK(t)
	key.KeyID = "did:web:issuer.example.test#sign"
	valid := &types.IdentityProfile{
		ID:     "did:web:issuer.example.test",
		TypeID: IDProfileTypeID,
		Keys:   &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}},
	}

	plugin := &DIDWebPlugin{}
	if err := plugin.Validate(valid); err != nil {
		t.Fatalf("Validate on a well-formed profile failed: %v", err)
	}
	if err := plugin.Validate(nil); err == nil {
		t.Fatal("Validate accepted a nil profile")
	}

	wrongType := *valid
	wrongType.TypeID = "jwks"
	if err := plugin.Validate(&wrongType); err == nil {
		t.Fatal("Validate accepted a profile of another type")
	}

	wrongID := *valid
	wrongID.ID = "did:key:z6Mk"
	if err := plugin.Validate(&wrongID); !errors.Is(err, ErrDIDWebIdentifierInvalid) {
		t.Fatalf("Validate error = %v, want ErrDIDWebIdentifierInvalid", err)
	}

	noKeys := *valid
	noKeys.Keys = &jose.JSONWebKeySet{}
	if err := plugin.Validate(&noKeys); err == nil {
		t.Fatal("Validate accepted a profile with no key")
	}
}

func TestNewDIDPluginRegistersOnlyOfflineMethods(t *testing.T) {
	t.Parallel()

	plugin := NewDIDPlugin()
	for _, method := range []string{"key", "jwk"} {
		if _, err := plugin.getMethodPlugin(method); err != nil {
			t.Fatalf("method %q is not registered: %v", method, err)
		}
	}
	if _, err := plugin.Resolve("did:web:issuer.example.test"); err == nil || !strings.Contains(err.Error(), "unsupported DID method") {
		t.Fatalf("did:web resolved by the default plugin: %v", err)
	}
	if _, err := NewDIDPluginWithWeb(nil).getMethodPlugin("web"); err != nil {
		t.Fatalf("NewDIDPluginWithWeb did not register did:web: %v", err)
	}
}

func TestDIDWebPluginResolvesRelativeVerificationMethodIDs(t *testing.T) {
	t.Parallel()

	embedded, referenced := testPublicJWK(t), testPublicJWK(t)
	const identifier = "did:web:issuer.example.test"
	plugin, _ := newDIDWebTestPlugin(t, func(writer http.ResponseWriter, _ *http.Request) {
		writeDIDDocument(t, writer, map[string]any{
			"id":                 identifier,
			"assertionMethod":    []any{verificationMethod(t, "#embedded", embedded), "#referenced", "relative/path"},
			"verificationMethod": []any{verificationMethod(t, "#referenced", referenced), verificationMethod(t, "#", testPublicJWK(t))},
		})
	})

	profile, err := plugin.Resolve(identifier)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	var ids []string
	for _, key := range profile.Keys.Keys {
		ids = append(ids, key.KeyID)
	}
	if want := []string{identifier + "#embedded", identifier + "#referenced"}; strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("key ids = %v, want %v", ids, want)
	}
}

func TestDIDPluginResolveContextPassesTheContextToDIDWeb(t *testing.T) {
	t.Parallel()

	web, _ := newDIDWebTestPlugin(t, func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewDIDPluginWithWeb(web).ResolveContext(ctx, "did:web:issuer.example.test")
	if !errors.Is(err, ErrDIDWebDocumentFetchFailed) {
		t.Fatalf("ResolveContext error = %v, want a fetch failure from the cancelled context", err)
	}
}

// newDIDWebTestPlugin returns a did:web plugin whose HTTP client reaches a TLS
// test server whatever host the document URL names, so that a did:web
// identifier can be resolved without a real network.
func newDIDWebTestPlugin(t *testing.T, handler http.HandlerFunc) (*DIDWebPlugin, *httptest.Server) {
	t.Helper()

	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	transport, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("test server client does not use an *http.Transport")
	}
	transport = transport.Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only client for a test server certificate
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	return &DIDWebPlugin{HTTPClient: &http.Client{Transport: transport}}, server
}

// testPublicJWK returns a freshly generated P-256 public key.
func testPublicJWK(t *testing.T) jose.JSONWebKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key failed: %v", err)
	}
	return jose.JSONWebKey{Key: &private.PublicKey}
}

// verificationMethod builds a DID document verification method that publishes
// key as a JWK.
func verificationMethod(t *testing.T, id string, key jose.JSONWebKey) map[string]any {
	t.Helper()
	raw, err := key.MarshalJSON()
	if err != nil {
		t.Fatalf("marshalling a key failed: %v", err)
	}
	var publicKeyJWK map[string]any
	if err := json.Unmarshal(raw, &publicKeyJWK); err != nil {
		t.Fatalf("decoding a key failed: %v", err)
	}
	return map[string]any{"id": id, "type": "JsonWebKey2020", "publicKeyJwk": publicKeyJWK}
}

// writeDIDDocument serves document as a DID document.
func writeDIDDocument(t *testing.T, writer http.ResponseWriter, document map[string]any) {
	t.Helper()
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshalling a DID document failed: %v", err)
	}
	writer.Header().Set("Content-Type", "application/did+json")
	_, _ = writer.Write(body)
}
