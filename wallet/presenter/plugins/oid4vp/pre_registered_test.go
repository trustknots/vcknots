package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

func preRegisteredQuery(clientID, responseURI string) string {
	return finalQueryURI(url.Values{
		"client_id":     {clientID},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {responseURI},
		"nonce":         {"n"},
		"dcql_query":    {finalDcqlParam},
	})
}

func bankRegistration() PreRegisteredClient {
	return PreRegisteredClient{Metadata: &VerifierMetadata{
		ClientName:   "Real Bank",
		RedirectURIs: []string{"https://bank.example/cb"},
	}}
}

// A pre-registered Client Identifier authenticates nothing by itself, so the
// response endpoint must be one the registration names (OID4VP 1.0 §5.1,
// §5.9.2; RFC 6749 §3.1.2.3). Otherwise anyone could send a request in the
// registered Verifier's name and receive the presentation.
func TestPreRegisteredClientResponseEndpointMustBeRegistered(t *testing.T) {
	p := &Oid4vpPresenter{PreRegisteredClients: map[string]PreRegisteredClient{
		"bank":      bankRegistration(),
		"no-uris":   {Metadata: &VerifierMetadata{ClientName: "No URIs"}},
		"no-record": {},
	}}

	req, err := p.ParsePresentationRequest(preRegisteredQuery("bank", "https://bank.example/cb"))
	require.NoError(t, err)
	require.Equal(t, "Real Bank", req.ClientMetadata.ClientName)

	for name, uri := range map[string]string{
		"foreign response_uri":     preRegisteredQuery("bank", "https://attacker.example/steal"),
		"prefix of a registration": preRegisteredQuery("bank", "https://bank.example/cb/extra"),
		"no registered uris":       preRegisteredQuery("no-uris", "https://bank.example/cb"),
		"no metadata":              preRegisteredQuery("no-record", "https://bank.example/cb"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := p.ParsePresentationRequest(uri)
			require.ErrorIs(t, err, ErrPreRegisteredClientEndpointUnregistered)
			assertAuthzErrorCode(t, err, InvalidRequestError)
		})
	}

	t.Run("redirect_uri of a non-direct_post request", func(t *testing.T) {
		query := func(redirectURI string) string {
			return finalQueryURI(url.Values{
				"client_id": {"bank"}, "redirect_uri": {redirectURI}, "response_type": {"vp_token"},
				"response_mode": {"fragment"}, "nonce": {"n"}, "dcql_query": {finalDcqlParam},
			})
		}
		_, err := p.ParsePresentationRequest(query("https://bank.example/cb"))
		require.NoError(t, err)
		_, err = p.ParsePresentationRequest(query("https://attacker.example/cb"))
		require.ErrorIs(t, err, ErrPreRegisteredClientEndpointUnregistered)
	})
}

// OID4VP 1.0 §8.5 invalid_client: "Verifier's pre-registered metadata has been
// found based on the Client Identifier, but client_metadata parameter is also
// present."
func TestPreRegisteredClientRefusesClientMetadataParameter(t *testing.T) {
	p := &Oid4vpPresenter{PreRegisteredClients: map[string]PreRegisteredClient{"bank": bankRegistration()}}
	uri := preRegisteredQuery("bank", "https://bank.example/cb") + "&client_metadata=" + url.QueryEscape(`{"client_name":"Fake"}`)
	_, err := p.ParsePresentationRequest(uri)
	assertAuthzErrorCode(t, err, InvalidClientError)
}

type preRegisteredSigner struct {
	key  *ecdsa.PrivateKey
	jwks *jose.JSONWebKeySet
}

func newPreRegisteredSigner(t *testing.T) preRegisteredSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return preRegisteredSigner{key: key, jwks: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &key.PublicKey, KeyID: "bank-1", Use: "sig", Algorithm: string(jose.ES256),
	}}}}
}

func (s preRegisteredSigner) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key},
		(&jose.SignerOptions{}).WithType("oauth-authz-req+jwt").WithHeader("kid", "bank-1"))
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func preRegisteredClaims() map[string]any {
	return map[string]any{
		"aud": "https://self-issued.me/v2", "client_id": "bank", "response_type": "vp_token",
		"response_mode": "direct_post", "response_uri": "https://bank.example/cb", "nonce": "n",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "cred", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:test"}},
		}}},
	}
}

// A pre-registered client's Request Object is authenticated with the keys the
// registration holds; client_metadata keys are never request-signing keys.
func TestPreRegisteredClientSignedRequestObject(t *testing.T) {
	signer := newPreRegisteredSigner(t)
	registration := bankRegistration()
	registration.JWKS = signer.jwks
	p := &Oid4vpPresenter{PreRegisteredClients: map[string]PreRegisteredClient{"bank": registration}}
	parse := func(p *Oid4vpPresenter, token string) (*CredentialPresentationRequest, error) {
		return p.ParsePresentationRequest("openid4vp://authorize?" + url.Values{"client_id": {"bank"}, "request": {token}}.Encode())
	}

	req, err := parse(p, signer.sign(t, preRegisteredClaims()))
	require.NoError(t, err)
	require.NotNil(t, req.RequestObjectVerification)
	require.Equal(t, "bank", req.RequestObjectVerification.ClientID)

	other := newPreRegisteredSigner(t)
	_, err = parse(p, other.sign(t, preRegisteredClaims()))
	require.ErrorIs(t, err, ErrRequestObjectSignatureInvalid)

	claims := preRegisteredClaims()
	claims["response_uri"] = "https://attacker.example/steal"
	_, err = parse(p, signer.sign(t, claims))
	require.ErrorIs(t, err, ErrPreRegisteredClientEndpointUnregistered)

	unkeyed := &Oid4vpPresenter{PreRegisteredClients: map[string]PreRegisteredClient{"bank": bankRegistration()}}
	_, err = parse(unkeyed, signer.sign(t, preRegisteredClaims()))
	require.ErrorIs(t, err, ErrRequestObjectClientAuthUnsupported)
}

// A registration that requires signed Request Objects refuses the unsigned
// query form.
func TestPreRegisteredClientRequireSignedRequestObject(t *testing.T) {
	signer := newPreRegisteredSigner(t)
	registration := bankRegistration()
	registration.JWKS = signer.jwks
	registration.RequireSignedRequestObject = true
	p := &Oid4vpPresenter{PreRegisteredClients: map[string]PreRegisteredClient{"bank": registration}}

	_, err := p.ParsePresentationRequest(preRegisteredQuery("bank", "https://bank.example/cb"))
	require.True(t, errors.Is(err, ErrRequestObjectSignatureRequired), "got %v", err)

	_, err = p.ParsePresentationRequest("openid4vp://authorize?" + url.Values{
		"client_id": {"bank"}, "request": {signer.sign(t, preRegisteredClaims())},
	}.Encode())
	require.NoError(t, err)
}
