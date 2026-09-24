package wallet

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// clientAuthTestVerifyAssertion parses a private_key_jwt client_assertion and
// checks its signature, issuer, subject, audience and expiry.
func clientAuthTestVerifyAssertion(t *testing.T, assertion string, publicKey jose.JSONWebKey, expectedAudience, expectedClientID string) map[string]any {
	t.Helper()
	signature, err := jose.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	payload, err := signature.Verify(publicKey)
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Equal(t, expectedClientID, claims["iss"])
	require.Equal(t, expectedClientID, claims["sub"])
	require.Equal(t, expectedAudience, claims["aud"])
	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	require.Greater(t, int64(exp), time.Now().Unix())
	return claims
}

// clientAuthTestPrivateKeyJWT configures private_key_jwt with a fresh client
// key and has the authorization server advertise methods, with ES256 as the
// signing algorithm. It returns the key's public JWK.
func clientAuthTestPrivateKeyJWT(t *testing.T, methods ...receiverTypes.TokenEndpointAuthMethod) (func(*finalIssuanceFixture), jose.JSONWebKey) {
	t.Helper()
	keyEntry, publicJWK := newClientAuthKeyEntry(t, "client-auth-key-1")
	return func(f *finalIssuanceFixture) {
		f.clientAuthKey = keyEntry
		f.authMethodsSupported = methods
		f.authSigningAlgsSupported = []jose.SignatureAlgorithm{jose.ES256}
	}, publicJWK
}

// RFC 7523 private_key_jwt authenticates the client at the PAR and token
// endpoints, each with its own assertion whose aud is the authorization server.
func TestIssuancePrivateKeyJWTClientAssertion(t *testing.T) {
	option, publicJWK := clientAuthTestPrivateKeyJWT(t, receiverTypes.PrivateKeyJwt)
	fixture := newFinalIssuanceFixture(t, option)

	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)

	parForm := fixture.parForm
	require.Equal(t, receiverTypes.ClientAssertionTypeJWTBearer, parForm.Get("client_assertion_type"))
	parClaims := clientAuthTestVerifyAssertion(t, parForm.Get("client_assertion"), publicJWK, fixture.server.URL, "client-1")

	require.Len(t, fixture.tokenForms, 1)
	tokenForm := fixture.tokenForms[0]
	require.Equal(t, receiverTypes.ClientAssertionTypeJWTBearer, tokenForm.Get("client_assertion_type"))
	tokenClaims := clientAuthTestVerifyAssertion(t, tokenForm.Get("client_assertion"), publicJWK, fixture.server.URL, "client-1")

	require.NotEqual(t, parClaims["jti"], tokenClaims["jti"])
}

// A configured private_key_jwt that the authorization server does not
// advertise is refused before the PAR request.
func TestIssuancePrivateKeyJWTNotAdvertisedFailsBeforePAR(t *testing.T) {
	option, _ := clientAuthTestPrivateKeyJWT(t, receiverTypes.ClientSecretBasic)
	fixture := newFinalIssuanceFixture(t, option)

	_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
	require.ErrorContains(t, err, "private_key_jwt")
	require.Equal(t, 0, fixture.parCalls)
}

// RFC 7523 Section 3 requires a unique jti, so the use_dpop_nonce retry of the
// token request carries a freshly signed assertion.
func TestIssuancePrivateKeyJWTTokenRetryRefreshesAssertion(t *testing.T) {
	option, publicJWK := clientAuthTestPrivateKeyJWT(t, receiverTypes.PrivateKeyJwt)
	fixture := newFinalIssuanceFixture(t, option, func(f *finalIssuanceFixture) {
		f.tokenHandler = func(w http.ResponseWriter, r *http.Request) {
			if f.tokenCalls == 1 {
				w.Header().Set("DPoP-Nonce", "nonce-1")
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "use_dpop_nonce"})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"access_token": "access-1", "token_type": "DPoP", "expires_in": 3600})
		}
	})

	_, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Equal(t, 2, fixture.tokenCalls)
	require.Len(t, fixture.tokenForms, 2)

	first := fixture.tokenForms[0].Get("client_assertion")
	second := fixture.tokenForms[1].Get("client_assertion")
	firstClaims := clientAuthTestVerifyAssertion(t, first, publicJWK, fixture.server.URL, "client-1")
	secondClaims := clientAuthTestVerifyAssertion(t, second, publicJWK, fixture.server.URL, "client-1")
	require.NotEqual(t, first, second)
	require.NotEqual(t, firstClaims["jti"], secondClaims["jti"])
}

// Without a configured client authentication no assertion is sent.
func TestIssuanceWithoutClientAuthenticationSendsNoAssertion(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)

	_, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("client_assertion"))
	require.Empty(t, fixture.parForm.Get("client_assertion_type"))
	require.Len(t, fixture.tokenForms, 1)
	require.Empty(t, fixture.tokenForms[0].Get("client_assertion"))
	require.Empty(t, fixture.tokenForms[0].Get("client_assertion_type"))
}

// A client attestation takes precedence over a configured private_key_jwt: no
// client_assertion is sent and the authorization server does not have to
// advertise private_key_jwt.
func TestIssuanceClientAttestationSupersedesPrivateKeyJWT(t *testing.T) {
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-1")
	option, _ := clientAuthTestPrivateKeyJWT(t, receiverTypes.ClientSecretBasic)
	fixture := newFinalIssuanceFixture(t, option, func(f *finalIssuanceFixture) {
		f.clientAttestation = &attestation.StaticClientAttester{Key: testKeyEntry(t, attesterKey), Issuer: "https://attester.example"}
	})

	_, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("client_assertion"))
	require.NotEmpty(t, fixture.parHeaders.Get("OAuth-Client-Attestation"))
	require.Len(t, fixture.tokenForms, 1)
	require.Empty(t, fixture.tokenForms[0].Get("client_assertion"))
	require.NotEmpty(t, fixture.tokenHeaders.Get("OAuth-Client-Attestation"))
}

// HAIP Section 4.4.1 applies to wallet-initiated issuance too: without a
// client authentication mechanism nothing is sent to the issuer.
func TestIssuanceWalletInitiatedHAIPRequiresClientAuthentication(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.clientAuthKey = nil
	})

	_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.walletInitiatedRequest())
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "HAIP requires an OAuth2 client authentication mechanism")
	require.Equal(t, 0, fixture.issuerMetadataCalls)
}
