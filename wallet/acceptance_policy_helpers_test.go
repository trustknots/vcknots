package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/idprof/issuerkeys"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
)

// testIssuerIdentifier is the iss the issuance fixtures sign under.
const testIssuerIdentifier = "https://issuer.example.test"

// acceptIssuerKeyPolicy authenticates credentials that testIssuerIdentifier
// signs with issuerKey through the mechanisms SD-JWT VC -19 §2.5 permits for
// an https iss: JWT VC Issuer Metadata (SD-JWT VC) and the jwks of an OpenID
// Federation Trust Chain (every format). Both are served without a network.
func acceptIssuerKeyPolicy(issuerKey *ecdsa.PrivateKey) *acceptance.Policy {
	return acceptIssuerPolicyFor(testIssuerIdentifier, issuerKey)
}

// acceptIssuerPolicyFor is acceptIssuerKeyPolicy for the https iss issuer.
func acceptIssuerPolicyFor(issuer string, issuerKey *ecdsa.PrivateKey) *acceptance.Policy {
	key := jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256", Use: "sig"}
	network := &issuerKeyNetwork{documents: map[string]any{
		issuer + "/.well-known/jwt-vc-issuer": map[string]any{"issuer": issuer, "jwks": jsonObject(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}})},
	}}
	return &acceptance.Policy{
		IssuerKeys: &issuerkeys.Resolver{HTTPClient: &http.Client{Transport: network}, Mechanisms: issuerkeys.Mechanisms{JWTVCIssuerMetadata: true}},
		Federation: federationIssuerKeys(issuer, key),
	}
}

// acceptDIDIssuerPolicy authenticates credentials that did issues with key
// under kid: every origin the wallet asks serves a DIF Well Known DID
// Configuration linking did to that origin (OpenID4VCI 1.0 §14.4), so the
// Credential Issuer of any fixture binds the DID.
func acceptDIDIssuerPolicy(did, kid string, algorithm jose.SignatureAlgorithm, key any) *acceptance.Policy {
	network := &issuerKeyNetwork{documents: map[string]any{}, linkedDID: func(origin string) any {
		return map[string]any{"linked_dids": []any{domainLinkageCredential(did, kid, origin, algorithm, key)}}
	}}
	return &acceptance.Policy{IssuerKeys: &issuerkeys.Resolver{
		HTTPClient: &http.Client{Transport: network},
		Mechanisms: issuerkeys.Mechanisms{DIDKey: true, DIDJWK: true, DIDConfiguration: true},
		// The issuance fixtures run their Credential Issuer on plain http.
		Experimental: experimental.Transport{AllowHTTP: true},
	}}
}

// domainLinkageCredential is a JWT Domain Linkage Credential in which did,
// signing with key under kid, links itself to origin.
func domainLinkageCredential(did, kid, origin string, algorithm jose.SignatureAlgorithm, key any) string {
	now := time.Now()
	claims := map[string]any{
		"iss": did, "sub": did,
		"nbf": now.Add(-time.Hour).Unix(), "exp": now.Add(time.Hour).Unix(),
		"vc": map[string]any{
			"@context":          []any{"https://www.w3.org/2018/credentials/v1", "https://identity.foundation/.well-known/did-configuration/v1"},
			"type":              []any{"VerifiableCredential", "DomainLinkageCredential"},
			"issuer":            did,
			"issuanceDate":      now.Add(-time.Hour).UTC().Format(time.RFC3339),
			"credentialSubject": map[string]any{"id": did, "origin": origin},
		},
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		panic(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		panic(err)
	}
	return token
}

// mockIssuerAcceptance authenticates the credentials the mockserver issuers
// sign: their x5c chain reaches mockserver.CredentialTrustAnchors, and the
// leaf names the loopback host the mock issuers run on over http
// (Experimental.AllowHTTP binds an http iss).
func mockIssuerAcceptance() *acceptance.Policy {
	return &acceptance.Policy{IssuerX509: &acceptance.IssuerX509TrustOptions{
		TrustAnchors:                mockserver.CredentialTrustAnchors(),
		AllowUnadvertisedRevocation: true,
		Experimental:                experimental.Transport{AllowHTTP: true},
	}}
}

// issuerKeyNetwork answers GET requests from canned JSON documents keyed by
// URL, a DID Configuration from linkedDID for any origin when it is set, and
// 404 for anything else.
type issuerKeyNetwork struct {
	mu        sync.Mutex
	documents map[string]any
	linkedDID func(origin string) any
}

func (n *issuerKeyNetwork) RoundTrip(request *http.Request) (*http.Response, error) {
	n.mu.Lock()
	document, ok := n.documents[request.URL.String()]
	n.mu.Unlock()
	if !ok && n.linkedDID != nil && request.URL.Path == "/.well-known/did-configuration.json" {
		document, ok = n.linkedDID(request.URL.Scheme+"://"+request.URL.Host), true
	}
	status := http.StatusOK
	body := []byte(`{}`)
	if ok {
		encoded, err := json.Marshal(document)
		if err != nil {
			return nil, err
		}
		body = encoded
	} else {
		status = http.StatusNotFound
	}
	return &http.Response{
		StatusCode:    status,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}, nil
}

// federationIssuerKeys are the keys of entityID's openid_credential_issuer
// metadata, from a two-level Trust Chain to a test Trust Anchor.
func federationIssuerKeys(entityID string, keys ...jose.JSONWebKey) *acceptance.FederationIssuerKeys {
	anchorKey := mustP256Key()
	entityKey := mustP256Key()
	const anchorID = "https://trust-anchor.example.test"
	anchorJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &anchorKey.PublicKey, KeyID: "anchor", Algorithm: "ES256", Use: "sig"}}}
	entityJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &entityKey.PublicKey, KeyID: "entity", Algorithm: "ES256", Use: "sig"}}}
	now := time.Now()
	statement := func(key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
		claims["iat"] = now.Add(-time.Minute).Unix()
		claims["exp"] = now.Add(24 * time.Hour).Unix()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("entity-statement+jwt").WithHeader("kid", kid))
		if err != nil {
			panic(err)
		}
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			panic(err)
		}
		return token
	}
	statements := []string{
		statement(entityKey, "entity", map[string]any{
			"iss": entityID, "sub": entityID, "jwks": jsonObject(entityJWKS), "authority_hints": []any{anchorID},
			"metadata": map[string]any{"openid_credential_issuer": map[string]any{
				"credential_issuer": entityID, "jwks": jsonObject(jose.JSONWebKeySet{Keys: keys}),
			}},
		}),
		statement(anchorKey, "anchor", map[string]any{"iss": anchorID, "sub": entityID, "jwks": jsonObject(entityJWKS)}),
		statement(anchorKey, "anchor", map[string]any{"iss": anchorID, "sub": anchorID, "jwks": jsonObject(anchorJWKS)}),
	}
	chain, err := federation.ValidateTrustChain(statements, entityID, []federation.TrustAnchor{{EntityID: anchorID, JWKS: anchorJWKS}}, now)
	if err != nil {
		panic(err)
	}
	issuerKeys, err := acceptance.NewFederationIssuerKeys(chain)
	if err != nil {
		panic(err)
	}
	return issuerKeys
}

// jsonObject is value as the generic JSON a JWT claim carries.
func jsonObject(value any) any {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		panic(err)
	}
	return decoded
}

func mustP256Key() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}
