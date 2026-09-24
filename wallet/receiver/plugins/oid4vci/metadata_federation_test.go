package oid4vci

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
)

// federatedIssuer is a Credential Issuer that publishes its metadata only in
// its OpenID Federation Entity Configuration, below a Trust Anchor on the
// same TLS server.
type federatedIssuer struct {
	server     *httptest.Server
	issuerID   string
	anchor     federation.TrustAnchor
	mu         sync.Mutex
	wellKnown  map[string]any
	fetches    map[string]int
	statements map[string]string
}

func newFederatedIssuer(t *testing.T, metadata func(issuerID string) map[string]any) *federatedIssuer {
	t.Helper()
	f := &federatedIssuer{fetches: map[string]int{}, statements: map[string]string{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.fetches[r.URL.Path]++
		if r.URL.Path == wellKnownCredentialIssuer && f.wellKnown != nil {
			writeTestJSON(w, f.wellKnown)
			return
		}
		statement, ok := f.statements[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(statement))
	}))
	t.Cleanup(f.server.Close)
	f.issuerID = f.server.URL
	anchorID := f.server.URL + "/anchor"
	issuerKey, anchorKey := testutil.NewP256Key(t), testutil.NewP256Key(t)
	jwks := func(key *ecdsa.PrivateKey, kid string) jose.JSONWebKeySet {
		return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}}}
	}
	sign := func(key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("entity-statement+jwt"))
		require.NoError(t, err)
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)
		return token
	}
	iat, exp := time.Now().Add(-time.Minute).Unix(), time.Now().Add(10*time.Minute).Unix()
	f.statements["/.well-known/openid-federation"] = sign(issuerKey, "issuer", map[string]any{
		"iss": f.issuerID, "sub": f.issuerID, "iat": iat, "exp": exp, "jwks": jwks(issuerKey, "issuer"),
		"authority_hints": []string{anchorID},
		"metadata":        map[string]any{credentialIssuerEntityType: metadata(f.issuerID)},
	})
	f.statements["/anchor/.well-known/openid-federation"] = sign(anchorKey, "anchor", map[string]any{
		"iss": anchorID, "sub": anchorID, "iat": iat, "exp": exp, "jwks": jwks(anchorKey, "anchor"),
		"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": anchorID + "/fetch"}},
	})
	f.statements["/anchor/fetch"] = sign(anchorKey, "anchor", map[string]any{
		"iss": anchorID, "sub": f.issuerID, "iat": iat, "exp": exp, "jwks": jwks(issuerKey, "issuer"),
	})
	f.anchor = federation.TrustAnchor{EntityID: anchorID, JWKS: jwks(anchorKey, "anchor")}
	return f
}

func (f *federatedIssuer) endpoint(t *testing.T) common.URIField {
	t.Helper()
	parsed, err := url.Parse(f.issuerID)
	require.NoError(t, err)
	return common.URIField(*parsed)
}

func (f *federatedIssuer) fetched(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches[path]
}

func (f *federatedIssuer) receiver(anchors ...federation.TrustAnchor) *Oid4vciReceiver {
	return &Oid4vciReceiver{HTTPClient: f.server.Client(), IssuerMetadataFederation: &federation.Resolver{TrustAnchors: anchors}}
}

func writeTestJSON(w http.ResponseWriter, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func issuerMetadataFor(issuerID string) map[string]any {
	return map[string]any{
		"credential_issuer":   issuerID,
		"credential_endpoint": issuerID + "/credential",
		"credential_configurations_supported": map[string]any{
			"degree": map[string]any{"format": "jwt_vc_json"},
		},
	}
}

// An issuer whose metadata document is not found is resolved through a Trust
// Chain to a configured Trust Anchor.
func TestDiscoverCredentialIssuerFromOpenIDFederation(t *testing.T) {
	f := newFederatedIssuer(t, issuerMetadataFor)
	metadata, err := f.receiver(f.anchor).DiscoverCredentialIssuer(context.Background(), f.endpoint(t))
	require.NoError(t, err)
	require.Equal(t, f.issuerID, metadata.CredentialIssuer)
	require.Equal(t, f.issuerID+"/credential", metadata.CredentialEndpoint.String())
	require.Contains(t, metadata.CredentialConfigurationSupported, "degree")
	require.JSONEq(t, `{"credential_issuer":"`+f.issuerID+`","credential_endpoint":"`+f.issuerID+`/credential",`+
		`"credential_configurations_supported":{"degree":{"format":"jwt_vc_json"}}}`, string(metadata.RawDocument))
	require.Equal(t, 1, f.fetched(wellKnownCredentialIssuer))
}

func TestDiscoverCredentialIssuerFromOpenIDFederationFailsClosed(t *testing.T) {
	t.Run("a Trust Anchor with other keys", func(t *testing.T) {
		f := newFederatedIssuer(t, issuerMetadataFor)
		wrong := federation.TrustAnchor{EntityID: f.anchor.EntityID, JWKS: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &testutil.NewP256Key(t).PublicKey, KeyID: "anchor", Algorithm: string(jose.ES256), Use: "sig",
		}}}}
		_, err := f.receiver(wrong).DiscoverCredentialIssuer(context.Background(), f.endpoint(t))
		require.ErrorIs(t, err, federation.ErrTrustChainInvalid)
	})
	t.Run("no Trust Anchor", func(t *testing.T) {
		f := newFederatedIssuer(t, issuerMetadataFor)
		_, err := f.receiver().DiscoverCredentialIssuer(context.Background(), f.endpoint(t))
		require.Error(t, err)
	})
	t.Run("metadata naming another issuer", func(t *testing.T) {
		f := newFederatedIssuer(t, func(string) map[string]any { return issuerMetadataFor("https://other.example") })
		_, err := f.receiver(f.anchor).DiscoverCredentialIssuer(context.Background(), f.endpoint(t))
		require.ErrorIs(t, err, ErrIssuerIdentifierMismatch)
	})
	t.Run("no openid_credential_issuer metadata", func(t *testing.T) {
		f := newFederatedIssuer(t, func(string) map[string]any { return nil })
		_, err := f.receiver(f.anchor).DiscoverCredentialIssuer(context.Background(), f.endpoint(t))
		require.ErrorIs(t, err, federation.ErrMetadataDerivationFailed)
	})
}

// The well-known document wins; federation is only consulted after a 404,
// never when signed metadata is required, and not at all when unset.
func TestDiscoverCredentialIssuerConsultsOpenIDFederationOnlyAfterNotFound(t *testing.T) {
	t.Run("a published document", func(t *testing.T) {
		f := newFederatedIssuer(t, issuerMetadataFor)
		f.wellKnown = issuerMetadataFor(f.issuerID)
		f.wellKnown["credential_endpoint"] = f.issuerID + "/published"
		metadata, err := f.receiver(f.anchor).DiscoverCredentialIssuer(context.Background(), f.endpoint(t))
		require.NoError(t, err)
		require.Equal(t, f.issuerID+"/published", metadata.CredentialEndpoint.String())
		require.Zero(t, f.fetched("/.well-known/openid-federation"))
	})
	t.Run("signed metadata required", func(t *testing.T) {
		f := newFederatedIssuer(t, issuerMetadataFor)
		receiver := f.receiver(f.anchor)
		receiver.IssuerMetadataSigning = &IssuerMetadataSigningOptions{Require: true}
		_, err := receiver.DiscoverCredentialIssuer(context.Background(), f.endpoint(t))
		require.ErrorIs(t, err, ErrIssuerMetadataSignatureRequired)
		require.Zero(t, f.fetched("/.well-known/openid-federation"))
	})
	t.Run("not configured", func(t *testing.T) {
		f := newFederatedIssuer(t, issuerMetadataFor)
		receiver := &Oid4vciReceiver{HTTPClient: f.server.Client()}
		_, err := receiver.DiscoverCredentialIssuer(context.Background(), f.endpoint(t))
		require.True(t, isNotFound(err))
		require.Zero(t, f.fetched("/.well-known/openid-federation"))
	})
}
