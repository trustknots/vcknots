package acceptance

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/idprof/issuerkeys"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
	"github.com/trustknots/vcknots/wallet/profile"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

// x5cClaims is an SD-JWT VC signed by the chain's leaf with x5c, whose iss is
// issuer (omitted when nil).
func x5cClaims(t *testing.T, chain testIssuerChain, holder jose.JSONWebKey, issuer *string) []byte {
	t.Helper()
	claims := baseClaims(holder)
	delete(claims, "iss")
	if issuer != nil {
		claims["iss"] = *issuer
	}
	return []byte(signedClaims(t, chain.leafKey, "dc+sd-jwt", map[string]any{"x5c": chain.leafOnlyX5C()}, claims))
}

// A chain trusted for attacker.example must not make the credential speak for
// another issuer. SD-JWT VC -19 §2.5 makes the subject of the end-entity
// certificate the Issuer of an x5c credential, so an https iss beside it is
// bound to the leaf by default, under Final and HAIP alike, and a mismatch is
// refused rather than reported as Verification.Issuer.
func TestVerifyX5CBindsTheIssToTheLeafByDefault(t *testing.T) {
	chain := newTestIssuerChain(t, []string{"attacker.example"})
	holder := newHolderKey(t)
	for _, p := range []profile.Profile{profile.Final(), profile.HAIP()} {
		for name, issuer := range map[string]string{
			"https victim":        "https://victim.example",
			"did:web victim":      "did:web:victim.example",
			"did:web own host":    "did:web:attacker.example",
			"http victim":         "http://victim.example",
			"http own host":       "http://attacker.example",
			"https parent domain": "https://example",
			"https subdomain":     "https://www.attacker.example",
			"not a URL":           "attacker.example",
		} {
			t.Run(p.String()+" iss "+name, func(t *testing.T) {
				_, verification, err := newTestAcceptor(t, p).Verify(t.Context(), x5cClaims(t, chain, holder, &issuer), x509Trust(chain.anchors()), sdJWT(&holder))
				require.ErrorIs(t, err, ErrIssuerDNSBindingFailed)
				require.Nil(t, verification)
			})
		}

		t.Run(p.String()+" the leaf's own host is bound and the Issuer is the certificate subject", func(t *testing.T) {
			_, verification, err := newTestAcceptor(t, p).Verify(t.Context(), x5cClaims(t, chain, holder, ptr("https://attacker.example/issuer")), x509Trust(chain.anchors()), sdJWT(&holder))
			require.NoError(t, err)
			require.True(t, verification.IssuerDNSBound)
			require.Equal(t, "CN=Acceptance Test Issuer", verification.Issuer)
			require.Equal(t, "https://attacker.example/issuer", verification.ClaimedIssuer)
			require.Equal(t, issuerkeys.MechanismX5CTrustedChain, verification.Mechanism)
		})
	}

	t.Run("a URI subject alternative name of the same scheme binds the host", func(t *testing.T) {
		uriChain := newTestIssuerChainWithURIs(t, nil, []string{"https://issuer.example.test/credential-issuer"})
		_, verification, err := newTestAcceptor(t, profile.HAIP()).Verify(t.Context(), x5cClaims(t, uriChain, holder, ptr("https://issuer.example.test")), x509Trust(uriChain.anchors()), sdJWT(&holder))
		require.NoError(t, err)
		require.True(t, verification.IssuerDNSBound)

		otherScheme := newTestIssuerChainWithURIs(t, nil, []string{"http://issuer.example.test"})
		_, _, err = newTestAcceptor(t, profile.Final()).Verify(t.Context(), x5cClaims(t, otherScheme, holder, ptr("https://issuer.example.test")), x509Trust(otherScheme.anchors()), sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerDNSBindingFailed)
	})

	t.Run("a wildcard dNSName does not bind", func(t *testing.T) {
		wildcard := newTestIssuerChain(t, []string{"*.example.test"})
		_, _, err := newTestAcceptor(t, profile.Final()).Verify(t.Context(), x5cClaims(t, wildcard, holder, ptr("https://issuer.example.test")), x509Trust(wildcard.anchors()), sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerDNSBindingFailed)
	})

	t.Run("Experimental.AllowHTTP binds an http iss by its host, and HAIP refuses it", func(t *testing.T) {
		policy := x509Trust(chain.anchors())
		policy.IssuerX509.Experimental = experimental.Transport{AllowHTTP: true}
		_, verification, err := newTestAcceptor(t, profile.Final()).Verify(t.Context(), x5cClaims(t, chain, holder, ptr("http://attacker.example")), policy, sdJWT(&holder))
		require.NoError(t, err)
		require.True(t, verification.IssuerDNSBound)
		_, _, err = newTestAcceptor(t, profile.Final()).Verify(t.Context(), x5cClaims(t, chain, holder, ptr("http://victim.example")), policy, sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerDNSBindingFailed)
		_, _, err = newTestAcceptor(t, profile.Final()).Verify(t.Context(), x5cClaims(t, chain, holder, ptr("did:web:attacker.example")), policy, sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerDNSBindingFailed)
		_, _, err = newTestAcceptor(t, profile.HAIP()).Verify(t.Context(), x5cClaims(t, chain, holder, ptr("https://attacker.example")), policy, sdJWT(&holder))
		require.ErrorIs(t, err, common.ErrInvalidInput)
	})
}

// SD-JWT VC -19 §2.2.2.3 makes iss OPTIONAL and §2.5 makes the subject of the
// x5c end-entity certificate the Issuer when it is absent.
func TestVerifyX5CWithoutIssIsIssuedByTheCertificateSubject(t *testing.T) {
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	holder := newHolderKey(t)
	for _, p := range []profile.Profile{profile.Final(), profile.HAIP()} {
		t.Run(p.String(), func(t *testing.T) {
			_, verification, err := newTestAcceptor(t, p).Verify(t.Context(), x5cClaims(t, chain, holder, nil), x509Trust(chain.anchors()), sdJWT(&holder))
			require.NoError(t, err)
			require.Equal(t, "CN=Acceptance Test Issuer", verification.Issuer)
			require.Empty(t, verification.ClaimedIssuer)
			require.Equal(t, issuerkeys.MechanismX5CTrustedChain, verification.Mechanism)
			require.False(t, verification.IssuerDNSBound)
			require.Equal(t, []string{"issuer.example.test"}, verification.IssuerCertificateSubject.DNSNames)
		})
	}

	t.Run("without x5c a credential without iss names no mechanism", func(t *testing.T) {
		issuerKey := testutil.NewP256Key(t)
		claims := baseClaims(holder)
		delete(claims, "iss")
		raw := signedClaims(t, issuerKey, "dc+sd-jwt", nil, claims)
		_, _, err := newTestAcceptor(t, profile.Final()).Verify(t.Context(), []byte(raw), resolving(jose.JSONWebKey{Key: &issuerKey.PublicKey}), sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.ErrorContains(t, err, "names no issuer and carries no x5c")
	})
}

// An iss that is only in a Disclosure is not the issuer-signed iss. SD-JWT VC
// -19 §2.2.2.3 forbids disclosing it, so the credential is refused before any
// issuer check could read it.
func TestVerifyRefusesADisclosedIss(t *testing.T) {
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	holder := newHolderKey(t)
	disclosure := base64.RawURLEncoding.EncodeToString([]byte(`["salt","iss","https://victim.example"]`))
	digest := sha256.Sum256([]byte(disclosure))
	claims := baseClaims(holder)
	delete(claims, "iss")
	claims["_sd"] = []string{base64.RawURLEncoding.EncodeToString(digest[:])}
	claims["_sd_alg"] = "sha-256"
	raw := signedClaims(t, chain.leafKey, "dc+sd-jwt", map[string]any{"x5c": chain.leafOnlyX5C()}, claims) + disclosure + "~"

	_, _, err := newTestAcceptor(t, profile.Final()).Verify(t.Context(), []byte(raw), x509Trust(chain.anchors()), sdJWT(&holder))
	require.ErrorIs(t, err, ErrCredentialParse)
	require.ErrorIs(t, err, serializerTypes.ErrRegisteredClaimDisclosed)
}

// SD-JWT VC -19 §7.3: the verification process follows from iss and the
// policy only narrows it.
func TestVerifyMechanismFollowsTheIssuerIdentifier(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final())
	holder := newHolderKey(t)
	issuerKey := testutil.NewP256Key(t)
	issuerJWK := jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1"}
	withIssuer := func(issuer string) []byte {
		claims := baseClaims(holder)
		claims["iss"] = issuer
		return []byte(signedClaims(t, issuerKey, "dc+sd-jwt", map[string]any{"kid": "issuer-key-1"}, claims))
	}

	t.Run("an https iss without x5c is refused by an x5c-only policy", func(t *testing.T) {
		chain := newTestIssuerChain(t, []string{"issuer.example.test"})
		_, _, err := acceptor.Verify(t.Context(), withIssuer(testCredentialIssuer), x509Trust(chain.anchors()), sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
	})

	t.Run("JWT VC Issuer Metadata is defined for SD-JWT VC only", func(t *testing.T) {
		policy := resolving(issuerJWK)
		options := Options{Flavor: credential.JwtVc}
		raw := signedJWTVC(t, issuerKey, testCredentialIssuer)
		_, _, err := acceptor.Verify(t.Context(), raw, policy, options)
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
	})

	t.Run("an http iss is refused without the experimental transport", func(t *testing.T) {
		network := newKeyNetwork()
		network.publishIssuerMetadata("http://issuer.example.test", issuerJWK)
		policy := Policy{IssuerKeys: network.resolver(issuerkeys.Mechanisms{JWTVCIssuerMetadata: true})}
		_, _, err := acceptor.Verify(t.Context(), withIssuer("http://issuer.example.test"), policy, sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.Zero(t, network.requestCount())

		policy.IssuerKeys.Experimental = experimental.Transport{AllowHTTP: true}
		_, verification, err := acceptor.Verify(t.Context(), withIssuer("http://issuer.example.test"), policy, sdJWT(&holder))
		require.NoError(t, err)
		require.Equal(t, issuerkeys.MechanismJWTVCIssuerMetadata, verification.Mechanism)
	})

	t.Run("an iss that is neither https nor a DID names no mechanism", func(t *testing.T) {
		_, _, err := acceptor.Verify(t.Context(), withIssuer("urn:example:issuer"), resolving(issuerJWK), sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.ErrorContains(t, err, "neither an https URL nor a DID")
	})

	t.Run("a DID iss is refused without IssuerKeys", func(t *testing.T) {
		_, _, err := acceptor.Verify(t.Context(), withIssuer("did:jwk:abc"), Policy{}, sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.ErrorContains(t, err, "does not permit DID resolution")
	})

	t.Run("an unresolved issuer keeps the resolver diagnostics", func(t *testing.T) {
		_, _, err := acceptor.Verify(t.Context(), withIssuer("https://unknown.example.test"), resolving(issuerJWK), sdJWT(&holder))
		var unresolved *issuerkeys.UnresolvedError
		require.ErrorAs(t, err, &unresolved)
		require.NotEmpty(t, unresolved.Diagnostics)
		code, _ := common.CodeOf(err)
		require.Equal(t, "issuer_key_unresolved", code)
	})
}

// A DID iss is bound to the Credential Issuer by a DID Configuration only
// (OpenID4VCI 1.0 §14.4, mechanism 1). A DID that resolves is not enough, and
// the credential's own statements (the vc.issuer.credential_issuer member of
// mechanism 2, which the signer writes itself) are not consulted.
func TestVerifyJWTVCDIDIssuerNeedsADIDConfiguration(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final())
	signer := testutil.NewP256Key(t)
	public := jose.JSONWebKey{Key: &signer.PublicKey}
	encoded, err := public.MarshalJSON()
	require.NoError(t, err)
	did := "did:jwk:" + base64.RawURLEncoding.EncodeToString(encoded)
	raw := signedJWTVC(t, signer, did)
	options := Options{Flavor: credential.JwtVc, CredentialIssuer: testCredentialIssuer}

	t.Run("a resolving DID without a DID Configuration binds nothing", func(t *testing.T) {
		network := newKeyNetwork()
		policy := Policy{IssuerKeys: network.resolver(issuerkeys.Mechanisms{DIDJWK: true, DIDConfiguration: true})}
		_, _, err := acceptor.Verify(t.Context(), raw, policy, options)
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.ErrorIs(t, err, issuerkeys.ErrDIDOnlyTrustUnsupported)
	})

	t.Run("a DID Configuration of the Credential Issuer's origin binds the DID", func(t *testing.T) {
		network := newKeyNetwork()
		network.linkDID(t, testCredentialIssuer, did, did+"#0", jose.ES256, signer)
		policy := Policy{IssuerKeys: network.resolver(issuerkeys.Mechanisms{DIDJWK: true, DIDConfiguration: true})}
		_, verification, err := acceptor.Verify(t.Context(), raw, policy, options)
		require.NoError(t, err)
		require.Equal(t, issuerkeys.MechanismDIDConfigurationBinding, verification.Mechanism)
		require.Equal(t, did, verification.DID)
		require.Equal(t, did, verification.Issuer)
		require.Equal(t, did, verification.ClaimedIssuer)
	})
}

// HAIP 1.0 §4 and SD-JWT VC -19 §3: key material over TLS only.
func TestVerifyRefusesAnExperimentalResolverUnderForbidExperimental(t *testing.T) {
	holder := newHolderKey(t)
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	policy := x509Trust(chain.anchors())
	policy.IssuerKeys = newKeyNetwork().resolver(issuerkeys.Mechanisms{JWTVCIssuerMetadata: true})
	policy.IssuerKeys.Experimental = experimental.Transport{AllowHTTP: true}
	_, _, err := newTestAcceptor(t, profile.HAIP()).Verify(t.Context(), x5cClaims(t, chain, holder, ptr(testCredentialIssuer)), policy, sdJWT(&holder))
	require.ErrorIs(t, err, common.ErrInvalidInput)

	_, _, err = newTestAcceptor(t, profile.Final()).Verify(t.Context(), x5cClaims(t, chain, holder, ptr(testCredentialIssuer)), policy, sdJWT(&holder))
	require.NoError(t, err)
}

// signedJWTVC is a W3C JWT VC (jwt_vc_json) signed by key under iss.
func signedJWTVC(t *testing.T, key *ecdsa.PrivateKey, iss string) []byte {
	t.Helper()
	vc := map[string]any{
		"@context":          []any{"https://www.w3.org/2018/credentials/v1"},
		"id":                "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
		"type":              []any{"VerifiableCredential"},
		"issuer":            iss,
		"credentialSubject": map[string]any{"name": "Erika"},
	}
	claims := map[string]any{"iss": iss, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "vc": vc}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", iss+"#0"))
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return []byte(token)
}

// federationFixture is a two-level OpenID Federation: a Trust Anchor and a
// Credential Issuer Entity whose openid_credential_issuer metadata publishes
// the issuer's signing key.
type federationFixture struct {
	anchor    federation.TrustAnchor
	statement []string
	issuerKey *ecdsa.PrivateKey
}

const (
	federationEntityID = testCredentialIssuer
	federationAnchorID = "https://anchor.example.test"
)

func newFederationFixture(t *testing.T, metadata map[string]any) federationFixture {
	t.Helper()
	anchorKey := testutil.NewP256Key(t)
	entityKey := testutil.NewP256Key(t)
	issuerKey := testutil.NewP256Key(t)
	anchorJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &anchorKey.PublicKey, KeyID: "anchor", Algorithm: "ES256", Use: "sig"}}}
	entityJWKS := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &entityKey.PublicKey, KeyID: "entity", Algorithm: "ES256", Use: "sig"}}}
	if metadata == nil {
		metadata = map[string]any{"credential_issuer": federationEntityID, "jwks": jsonValue(t, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Use: "sig"}}})}
	}
	now := time.Now()
	statement := func(key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
		claims["iat"] = now.Add(-time.Minute).Unix()
		claims["exp"] = now.Add(time.Hour).Unix()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("entity-statement+jwt").WithHeader("kid", kid))
		require.NoError(t, err)
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)
		return token
	}
	leaf := statement(entityKey, "entity", map[string]any{
		"iss": federationEntityID, "sub": federationEntityID, "jwks": jsonValue(t, entityJWKS),
		"authority_hints": []any{federationAnchorID},
		"metadata":        map[string]any{"openid_credential_issuer": metadata},
	})
	subordinate := statement(anchorKey, "anchor", map[string]any{
		"iss": federationAnchorID, "sub": federationEntityID, "jwks": jsonValue(t, entityJWKS),
	})
	anchor := statement(anchorKey, "anchor", map[string]any{
		"iss": federationAnchorID, "sub": federationAnchorID, "jwks": jsonValue(t, anchorJWKS),
	})
	return federationFixture{
		anchor:    federation.TrustAnchor{EntityID: federationAnchorID, JWKS: anchorJWKS},
		statement: []string{leaf, subordinate, anchor},
		issuerKey: issuerKey,
	}
}

func (f federationFixture) chain(t *testing.T) *federation.TrustChain {
	t.Helper()
	chain, err := federation.ValidateTrustChain(f.statement, federationEntityID, []federation.TrustAnchor{f.anchor}, time.Now())
	require.NoError(t, err)
	return chain
}

func jsonValue(t *testing.T, value any) any {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	var decoded any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	return decoded
}

// OpenID Federation 1.0 §5.2.1 and §6.1.4: the jwks of the Entity Type
// metadata a Trust Chain derives authenticates an https iss equal to the
// Entity Identifier (SD-JWT VC -19 §2.5 "separate specifications").
func TestVerifyFederationIssuerKeys(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final())
	holder := newHolderKey(t)
	fixture := newFederationFixture(t, nil)
	keys, err := NewFederationIssuerKeys(fixture.chain(t))
	require.NoError(t, err)
	require.Equal(t, federationEntityID, keys.EntityID())
	require.Equal(t, federationAnchorID, keys.TrustAnchor())
	withIssuer := func(issuer string) []byte {
		claims := baseClaims(holder)
		claims["iss"] = issuer
		return []byte(signedClaims(t, fixture.issuerKey, "dc+sd-jwt", map[string]any{"kid": "issuer-key-1"}, claims))
	}

	t.Run("the Entity's key authenticates its iss", func(t *testing.T) {
		_, verification, err := acceptor.Verify(t.Context(), withIssuer(federationEntityID), Policy{Federation: keys}, sdJWT(&holder))
		require.NoError(t, err)
		require.Equal(t, issuerkeys.MechanismOpenIDFederation, verification.Mechanism)
		require.Equal(t, federationAnchorID, verification.FederationTrustAnchor)
		require.Equal(t, "issuer-key-1", verification.IssuerKeyID)
	})

	t.Run("a W3C JWT VC under the Entity's iss", func(t *testing.T) {
		raw := signedJWTVC(t, fixture.issuerKey, federationEntityID)
		_, verification, err := acceptor.Verify(t.Context(), raw, Policy{Federation: keys}, Options{Flavor: credential.JwtVc})
		require.NoError(t, err)
		require.Equal(t, issuerkeys.MechanismOpenIDFederation, verification.Mechanism)
	})

	t.Run("another iss is not the Entity", func(t *testing.T) {
		_, _, err := acceptor.Verify(t.Context(), withIssuer("https://other.example.test"), Policy{Federation: keys}, sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
	})

	t.Run("an expired Trust Chain authenticates nothing", func(t *testing.T) {
		policy := Policy{Federation: keys, Now: func() time.Time { return keys.ExpiresAt() }}
		_, _, err := acceptor.Verify(t.Context(), withIssuer(federationEntityID), policy, sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
	})

	t.Run("metadata without an inline jwks yields no keys", func(t *testing.T) {
		bare := newFederationFixture(t, map[string]any{"credential_issuer": federationEntityID})
		_, err := NewFederationIssuerKeys(bare.chain(t))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.True(t, strings.Contains(err.Error(), "carries no jwks"))
		_, err = NewFederationIssuerKeys(nil)
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
	})
}
