package wallet

import (
	"crypto/ecdsa"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
)

// publishIssuerFederation makes the fixture's credential issuer (its base URL)
// a subordinate of a Trust Anchor at baseURL/anchor, and returns that anchor.
func publishIssuerFederation(t *testing.T, fixture sdjwtPresentationFixture) federation.TrustAnchor {
	t.Helper()
	issuerID, anchorID := fixture.baseURL, fixture.baseURL+"/anchor"
	issuerKey, anchorKey := testutil.NewP256Key(t), testutil.NewP256Key(t)
	jwks := func(key *ecdsa.PrivateKey, kid string) jose.JSONWebKeySet {
		return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}}}
	}
	sign := func(key *ecdsa.PrivateKey, kid string, claims map[string]any) []byte {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("entity-statement+jwt"))
		require.NoError(t, err)
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)
		return []byte(token)
	}
	iat, exp := time.Now().Add(-time.Minute).Unix(), time.Now().Add(10*time.Minute).Unix()
	statements := map[string][]byte{
		"/.well-known/openid-federation": sign(issuerKey, "issuer", map[string]any{
			"iss": issuerID, "sub": issuerID, "iat": iat, "exp": exp, "jwks": jwks(issuerKey, "issuer"),
			"authority_hints": []string{anchorID},
			"metadata":        map[string]any{"openid_credential_issuer": map[string]any{"credential_issuer": issuerID}},
		}),
		"/anchor/.well-known/openid-federation": sign(anchorKey, "anchor", map[string]any{
			"iss": anchorID, "sub": anchorID, "iat": iat, "exp": exp, "jwks": jwks(anchorKey, "anchor"),
			"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": anchorID + "/fetch"}},
		}),
		"/anchor/fetch": sign(anchorKey, "anchor", map[string]any{
			"iss": anchorID, "sub": issuerID, "iat": iat, "exp": exp, "jwks": jwks(issuerKey, "issuer"),
		}),
	}
	for path, statement := range statements {
		fixture.mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			_, _ = w.Write(statement)
		})
	}
	return federation.TrustAnchor{EntityID: anchorID, JWKS: jwks(anchorKey, "anchor")}
}

// SelectCredentials and SubmitPresentation evaluate an openid_federation
// trusted_authorities query (OID4VP 1.0 Section 6.1.1.3) against the Trust
// Anchors of the presenter's federation configuration.
func TestWallet_DCQLOpenIDFederationTrustedAuthorities(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	anchor := publishIssuerFederation(t, fixture)
	fixturePresenter(t, fixture.wallet).RequestObjectValidation = &oid4vp.RequestObjectValidationOptions{
		Federation: &oid4vp.FederationTrustOptions{TrustAnchors: []federation.TrustAnchor{anchor}},
	}
	query := func(value string) string {
		return `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},` +
			`"trusted_authorities":[{"type":"openid_federation","values":["` + value + `"]}],"claims":[{"path":["given_name"]}]}]}`
	}

	request := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query(anchor.EntityID)))
	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	require.Len(t, selections, 1)
	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.NoError(t, err)
	require.Len(t, postedVPToken(t, fixture)["pid"], 1)

	other := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query("https://other-anchor.example")))
	_, err = fixture.wallet.SelectCredentials(t.Context(), other)
	var refusal *oid4vp.AuthorizationRequestError
	require.ErrorAs(t, err, &refusal)
	require.Equal(t, oid4vp.AccessDeniedError, refusal.Code)
	_, err = presentSelections(t, fixture.wallet, other, fixture.key, selections)
	require.ErrorIs(t, err, oid4vp.ErrDCQLSelectionUnsatisfied)
}
