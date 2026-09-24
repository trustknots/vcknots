package wallet

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// tokenTestKeyAttestation signs an Appendix D key attestation the way an
// out-of-process attester would: over the public holder keys, with the nonce
// and audience it was asked for.
func tokenTestKeyAttestation(t *testing.T, attesterKey jose.JSONWebKey, keys []jose.JSONWebKey, nonce, audience string) *attestation.KeyAttestation {
	t.Helper()
	signed, err := (&attestation.StaticKeyAttester{Key: testKeyEntry(t, attesterKey), Issuer: "https://key-attester.example"}).KeyAttestation(
		context.Background(),
		attestation.KeyRequest{Keys: keys, Nonce: nonce, Audience: audience},
	)
	require.NoError(t, err)
	return signed
}

// tokenTestAttesterTrust authenticates an attestation minted outside the
// wallet by the attester's public key, since a static attester ships no x5c.
func tokenTestAttesterTrust(attesterKey jose.JSONWebKey) attestation.TrustPolicy {
	return attestation.TrustPolicy{ResolveKey: func(attestation.JOSEHeader) (any, error) {
		return attesterKey.Public().Key, nil
	}}
}

// tokenTestKeyAttestationsRequired makes the "pid" configuration list
// key_attestations_required.
func tokenTestKeyAttestationsRequired(f *finalIssuanceFixture) {
	f.keyAttestationsRequired = true
}

// tokenTestBearer makes the token endpoint answer with a Bearer token
// (OpenID4VCI 1.0 Section 6.1).
func tokenTestBearer(f *finalIssuanceFixture) {
	f.tokenResponse = map[string]any{"access_token": "access-1", "token_type": "Bearer", "expires_in": 3600}
}

// tokenTestUnknownTokenType makes the token endpoint answer with a scheme the
// wallet cannot present.
func tokenTestUnknownTokenType(f *finalIssuanceFixture) {
	f.tokenResponse = map[string]any{"access_token": "access-1", "token_type": "Mac", "expires_in": 3600}
}

// tokenTestAnonymous builds the wallet without a DPoP key; the test clears
// Config.ClientAuth on the wallet it gets back.
func tokenTestAnonymous(f *finalIssuanceFixture) {
	f.noDPoPKey = true
}

// tokenTestPreAuthorizedRequest is a Pre-Authorized Code offer for "pid" from the
// fixture issuer, with txCode as the grant's tx_code object.
func (f *finalIssuanceFixture) tokenTestPreAuthorizedRequest(txCode *TxCode) PreAuthorizedIssuanceRequest {
	issuerURL, err := url.Parse(f.server.URL)
	require.NoError(f.t, err)
	return PreAuthorizedIssuanceRequest{CredentialOffer: &CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{"pid"},
		Grants: map[string]*CredentialOfferGrant{
			string(receiverTypes.PreAuthorizedCode): {PreAuthorizedCode: "pre-auth-code-1", TxCode: txCode},
		},
	}}
}

// tokenTestPreAuthorize runs AuthorizePreAuthorizedIssuance on the fixture
// wallet.
func (f *finalIssuanceFixture) tokenTestPreAuthorize(req PreAuthorizedIssuanceRequest) (*IssuanceGrant, error) {
	return f.wallet.AuthorizePreAuthorizedIssuance(context.Background(), req)
}

// tokenTestVerifyJWT verifies a compact ES256 JWS with key and returns its
// claims.
func tokenTestVerifyJWT(t *testing.T, token string, key jose.JSONWebKey) map[string]any {
	t.Helper()
	signature, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	payload, err := signature.Verify(key.Public())
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// tokenTestVerifyClientAttestationHeaders authenticates the Appendix E headers
// as an authorization server does: the attestation is signed by the attester
// and binds the instance key to client_id, the PoP is signed by that key and
// addressed to the authorization server.
func tokenTestVerifyClientAttestationHeaders(
	t *testing.T,
	headers http.Header,
	attesterKey jose.JSONWebKey,
	clientKey jose.JSONWebKey,
	clientID string,
	authorizationServer string,
) (attestationClaims map[string]any, popClaims map[string]any) {
	t.Helper()
	signedAttestation := headers.Get("OAuth-Client-Attestation")
	require.NotEmpty(t, signedAttestation)
	pop := headers.Get("OAuth-Client-Attestation-PoP")
	require.NotEmpty(t, pop)

	attestationClaims = tokenTestVerifyJWT(t, signedAttestation, attesterKey)
	require.Equal(t, clientID, attestationClaims["sub"])
	cnf, ok := attestationClaims["cnf"].(map[string]any)
	require.True(t, ok)
	require.NotNil(t, cnf["jwk"])

	popClaims = tokenTestVerifyJWT(t, pop, clientKey)
	require.Equal(t, clientID, popClaims["iss"])
	require.Equal(t, authorizationServer, popClaims["aud"])
	require.NotEmpty(t, popClaims["jti"])
	return attestationClaims, popClaims
}

// tokenTestHAIPAttestationFixture is a HAIP issuer whose wallet authenticates
// with a Client Attestation only (no private_key_jwt).
func tokenTestHAIPAttestationFixture(t *testing.T, opts ...func(*finalIssuanceFixture)) (*finalIssuanceFixture, jose.JSONWebKey) {
	t.Helper()
	attesterKey := newPrivateJWKForFinalVCITest(t, "client-attester-1")
	// HAIP Section 4.4.1: x5c with a leaf that is not self-signed.
	attesterKey.Certificates = []*x509.Certificate{testLeafCertificate(t, attesterKey, false)}
	withAttestation := append([]func(*finalIssuanceFixture){func(f *finalIssuanceFixture) {
		f.clientAuthKey = nil
		f.clientAttestation = &attestation.StaticClientAttester{
			Key: testKeyEntry(t, attesterKey), Chain: attesterKey.Certificates, Issuer: "https://attester.example",
		}
	}}, opts...)
	return newHAIPIssuanceFixture(t, withAttestation...), attesterKey
}

// Each stage runs in another wallet with only JSON carried across: the token
// stage stops before the credential request with the c_nonce, and the grant
// holds what the credential stage needs.
func TestIssuanceTwoStageAuthorizationSurvivesJSONRoundTrip(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	ctx := context.Background()
	authorization, err := fixture.wallet.BeginIssuance(ctx, fixture.issuanceRequest())
	require.NoError(t, err)
	var restoredAuthorization IssuanceAuthorization
	requireJSONRoundTrip(t, authorization, &restoredAuthorization)
	location, err := fixture.followAuthorization(&restoredAuthorization)
	require.NoError(t, err)

	grant, err := fixture.newWallet(t).AuthorizeIssuance(ctx, &restoredAuthorization, location)
	require.NoError(t, err)
	require.Equal(t, 1, fixture.tokenCalls)
	require.Equal(t, 1, fixture.nonceCalls)
	require.Equal(t, 0, fixture.credentialCalls)
	require.Equal(t, "credential-nonce-1", grant.CNonce)
	require.False(t, grant.KeyAttestationRequired)

	var restoredGrant IssuanceGrant
	requireJSONRoundTrip(t, grant, &restoredGrant)
	require.Equal(t, IssuanceVersionFinal, restoredGrant.Version)
	require.NotNil(t, restoredGrant.AccessToken)
	require.Equal(t, "pid", restoredGrant.CredentialConfigurationID)
	require.Equal(t, fixture.server.URL, restoredGrant.CredentialIssuer)
	require.Equal(t, fixture.server.URL, restoredGrant.AuthorizationServer)
	// RFC 9449 Section 5: the grant records the key the token is bound to.
	require.NotEmpty(t, restoredGrant.DPoPKeyThumbprint)

	result, err := fixture.newWallet(t).RequestCredential(ctx, &restoredGrant, fixture.credentialRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, 1, fixture.credentialCalls)
	require.Equal(t, 1, fixture.nonceCalls, "the grant's c_nonce is used, not fetched again")
}

// A DPoP-bound access token is presented only with the key it was issued to.
func TestRequestCredentialRejectsForeignDPoPKey(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)

	fixture.dpopEntry = fixture.keyEntry(newPrivateJWKForFinalVCITest(t, "someone-elses-dpop-key"))
	_, err = fixture.newWallet(t).RequestCredential(context.Background(), grant, fixture.credentialRequest())
	require.ErrorIs(t, err, ErrDPoPKeyMismatch)
	require.Equal(t, 0, fixture.credentialCalls)
}

// The interruption names what an Appendix D attestation must be signed over:
// the public holder keys, the c_nonce and the Credential Issuer.
func TestRequestCredentialKeyAttestationRequiredCarriesTheSigningInput(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, tokenTestKeyAttestationsRequired)
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)
	require.True(t, grant.KeyAttestationRequired)
	require.Equal(t, "credential-nonce-1", grant.CNonce)

	_, err = fixture.wallet.RequestCredential(context.Background(), grant, fixture.credentialRequest())
	var required *KeyAttestationRequiredError
	require.ErrorAs(t, err, &required)
	require.Equal(t, "credential-nonce-1", required.CNonce)
	require.Equal(t, fixture.server.URL, required.Audience)
	require.Len(t, required.HolderKeys, 1)
	require.NoError(t, requireJWKThumbprint(fixture.holderKey, required.HolderKeys[0]))
	// Only the public half is handed to whatever process signs.
	require.True(t, required.HolderKeys[0].IsPublic())
	require.Same(t, grant, required.Grant)
}

// A wallet without a key attestation source stops before the credential
// request, and completes the issuance with an attestation signed elsewhere.
func TestRequestCredentialRequiresThenAcceptsAKeyAttestation(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, tokenTestKeyAttestationsRequired)
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)

	fixture.attestationTrust = tokenTestAttesterTrust(attesterKey)
	credentialWallet := fixture.newWallet(t)
	_, err = credentialWallet.RequestCredential(context.Background(), grant, fixture.credentialRequest())
	var required *KeyAttestationRequiredError
	require.ErrorAs(t, err, &required)
	require.ErrorIs(t, err, ErrKeyAttestationRequired)
	require.True(t, required.IssuerRequired)
	require.False(t, required.NonceRejected)
	require.Equal(t, "credential-nonce-1", required.CNonce)
	require.Equal(t, fixture.server.URL, required.Audience)
	require.Len(t, required.HolderKeys, 1)
	require.Equal(t, 0, fixture.credentialCalls, "nothing was sent")

	signed := fixture.credentialRequest()
	signed.KeyAttestation = tokenTestKeyAttestation(t, attesterKey, required.HolderKeys, required.CNonce, required.Audience)
	result, err := credentialWallet.RequestCredential(context.Background(), required.Grant, signed)
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, 1, fixture.credentialCalls)

	header := finalProofHeader(t, fixture.proofJWTs(t)[0])
	attestationJWT, ok := header["key_attestation"].(string)
	require.True(t, ok, "proof header is missing key_attestation: %#v", header)
	require.Equal(t, signed.KeyAttestation.JWT, attestationJWT)
}

// Appendix F: an attestation minted for another c_nonce never reaches the
// wire.
func TestRequestCredentialRejectsForeignNonceAttestation(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, tokenTestKeyAttestationsRequired)
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)

	fixture.attestationTrust = tokenTestAttesterTrust(attesterKey)
	stale := fixture.credentialRequest()
	stale.KeyAttestation = tokenTestKeyAttestation(t, attesterKey,
		[]jose.JSONWebKey{fixture.holderKey.Public()}, "some-other-nonce", fixture.server.URL)
	_, err = fixture.newWallet(t).RequestCredential(context.Background(), grant, stale)
	var required *KeyAttestationRequiredError
	require.ErrorAs(t, err, &required)
	require.ErrorIs(t, err, ErrKeyAttestationNonceRejected)
	require.True(t, required.NonceRejected)
	require.Equal(t, "credential-nonce-1", required.Grant.CNonce)
	require.Equal(t, 0, fixture.credentialCalls)
}

// Section 8.3.1.2: invalid_nonce spends the attestation, and the caller gets
// the fresh c_nonce to sign a new one for.
func TestRequestCredentialReSignsAfterInvalidNonce(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, tokenTestKeyAttestationsRequired, func(f *finalIssuanceFixture) {
		f.nonceHandler = func(w http.ResponseWriter, _ *http.Request) {
			if f.nonceCalls == 1 {
				mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "credential-nonce-1"})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "credential-nonce-2"})
		}
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			if f.credentialCalls == 1 {
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_nonce"})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credentials": []any{map[string]any{"credential": f.issuedCredential}}})
		}
	})
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	fixture.attestationTrust = tokenTestAttesterTrust(attesterKey)
	fixture.wallet = fixture.newWallet(t)
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Equal(t, "credential-nonce-1", grant.CNonce)
	holderKeys := []jose.JSONWebKey{fixture.holderKey.Public()}

	first := fixture.credentialRequest()
	first.KeyAttestation = tokenTestKeyAttestation(t, attesterKey, holderKeys, grant.CNonce, fixture.server.URL)
	_, err = fixture.wallet.RequestCredential(context.Background(), grant, first)
	var required *KeyAttestationRequiredError
	require.ErrorAs(t, err, &required)
	require.ErrorIs(t, err, ErrKeyAttestationNonceRejected)
	require.Equal(t, "credential-nonce-2", required.CNonce)
	require.Equal(t, "credential-nonce-2", required.Grant.CNonce)
	require.Equal(t, 1, fixture.credentialCalls)
	require.Equal(t, 2, fixture.nonceCalls)

	second := fixture.credentialRequest()
	second.KeyAttestation = tokenTestKeyAttestation(t, attesterKey, required.HolderKeys, required.CNonce, required.Audience)
	result, err := fixture.wallet.RequestCredential(context.Background(), required.Grant, second)
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, 2, fixture.credentialCalls)
	require.Equal(t, "credential-nonce-2", finalProofClaims(t, fixture.proofJWTs(t)[0])["nonce"])
}

// HAIP Section 4.5.1: an issuer that requires key attestations advertises a
// nonce_endpoint.
func TestAuthorizeIssuanceRequiresNonceEndpointUnderHAIP(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, tokenTestKeyAttestationsRequired, func(f *finalIssuanceFixture) {
		f.includeNonceEndpoint = false
	})
	_, err := fixture.authorize(fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrNonceEndpointRequired)
	require.Equal(t, 0, fixture.credentialCalls)
}

// A Key Attestation's ExpiresAt ends its use even when its exp claim is later.
func TestKeyAttestationExpiresAtBindsTheAttestersLifetime(t *testing.T) {
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-expiry")
	holderKey := newPrivateJWKForFinalVCITest(t, "holder-expiry")
	attester := &attestation.StaticKeyAttester{Key: testKeyEntry(t, attesterKey), Issuer: "https://key-attester.example", Lifetime: time.Hour}
	request := attestation.KeyRequest{Keys: []jose.JSONWebKey{holderKey.Public()}, Audience: "https://issuer.example"}
	signed, err := attester.KeyAttestation(t.Context(), request)
	require.NoError(t, err)

	policy := tokenTestAttesterTrust(attesterKey)
	require.NoError(t, attestation.ValidateKeyAttestation(t.Context(), signed, request, policy))

	signed.ExpiresAt = time.Now().Add(-time.Minute)
	err = attestation.ValidateKeyAttestation(t.Context(), signed, request, policy)
	require.ErrorIs(t, err, attestation.ErrKeyAttestationInvalid)
	require.ErrorContains(t, err, "expired")
}

// A wallet with no DPoP key and no client authentication is the anonymous
// Section 6.1 client: no client_id, no DPoP, no attestation headers, and the
// Bearer token is presented as one.
func TestAuthorizePreAuthorizedIssuanceAcceptsAnonymousBearer(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, tokenTestBearer, tokenTestAnonymous)
	fixture.wallet.clientAuth = ClientAuthConfig{}
	grant, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
	require.NoError(t, err)
	require.Empty(t, grant.DPoPKeyThumbprint)
	result, err := fixture.wallet.RequestCredential(context.Background(), grant, fixture.credentialRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)

	require.Len(t, fixture.tokenForms, 1)
	form := fixture.tokenForms[0]
	require.Equal(t, string(receiverTypes.PreAuthorizedCode), form.Get("grant_type"))
	require.Equal(t, "pre-auth-code-1", form.Get("pre-authorized_code"))
	require.Empty(t, form.Get("client_id"))
	require.Empty(t, form.Get("tx_code"))
	require.Empty(t, form.Get("client_assertion"))
	require.Empty(t, fixture.tokenHeaders.Get("DPoP"))
	require.Empty(t, fixture.tokenHeaders.Get("OAuth-Client-Attestation"))
	require.Empty(t, fixture.tokenHeaders.Get("OAuth-Client-Attestation-PoP"))
	require.Equal(t, 1, fixture.credentialCalls)
	require.Equal(t, "pid", fixture.lastCredentialBody["credential_configuration_id"])
	require.Equal(t, "Bearer access-1", fixture.credentialHeaders.Get("Authorization"))
	require.Empty(t, fixture.credentialHeaders.Get("DPoP"))
}

// With a DPoP key the token is bound to it and presented with the RFC 9449
// Section 7.1 scheme.
func TestAuthorizePreAuthorizedIssuanceAcceptsDPoP(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	grant, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
	require.NoError(t, err)
	require.NotEmpty(t, grant.DPoPKeyThumbprint)
	require.Equal(t, "client-1", fixture.tokenForms[0].Get("client_id"))
	require.NotEmpty(t, fixture.tokenHeaders.Get("DPoP"))

	result, err := fixture.wallet.RequestCredential(context.Background(), grant, fixture.credentialRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, "DPoP access-1", fixture.credentialHeaders.Get("Authorization"))
	require.NotEmpty(t, fixture.credentialHeaders.Get("DPoP"))
}

// Section 6.1: tx_code "MUST be present if a tx_code object was present in the
// Credential Offer (including if the object was empty)".
func TestAuthorizePreAuthorizedIssuanceSendsTransactionCode(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, tokenTestBearer)
	req := fixture.tokenTestPreAuthorizedRequest(&TxCode{InputMode: "numeric", Length: 6})
	req.TxCode = "493536"
	_, err := fixture.tokenTestPreAuthorize(req)
	require.NoError(t, err)
	require.Equal(t, "493536", fixture.tokenForms[0].Get("tx_code"))
}

// A missing Transaction Code is caught before the single-use pre-authorized
// code is spent, and one the offer did not ask for is not sent.
func TestAuthorizePreAuthorizedIssuanceChecksTransactionCode(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, tokenTestBearer)
	_, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(&TxCode{}))
	require.ErrorIs(t, err, ErrTransactionCodeRequired)

	unasked := fixture.tokenTestPreAuthorizedRequest(nil)
	unasked.TxCode = "493536"
	_, err = fixture.tokenTestPreAuthorize(unasked)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.Equal(t, 0, fixture.tokenCalls)
	require.Equal(t, 0, fixture.issuerMetadataCalls)
}

// An offer without the Pre-Authorized Code grant is refused before any
// request.
func TestAuthorizePreAuthorizedIssuanceRequiresTheGrant(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.tokenTestPreAuthorizedRequest(nil)
	req.CredentialOffer.Grants = map[string]*CredentialOfferGrant{
		"authorization_code": {IssuerState: "issuer-state-1"},
	}
	_, err := fixture.tokenTestPreAuthorize(req)
	require.ErrorIs(t, err, ErrPreAuthorizedGrantMissing)
	require.Equal(t, 0, fixture.issuerMetadataCalls)
}

// HAIP Section 4 requires a sender-constrained token, so a Bearer token_type
// is refused where it arrives, on both grants.
func TestTokenStageRejectsBearerUnderHAIP(t *testing.T) {
	t.Run("pre-authorized code", func(t *testing.T) {
		fixture := newHAIPIssuanceFixture(t, tokenTestBearer)
		_, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
		require.ErrorIs(t, err, oid4vci.ErrDPoPRequired)
		require.Equal(t, 1, fixture.tokenCalls)
		require.Equal(t, 0, fixture.credentialCalls)
	})
	t.Run("authorization code", func(t *testing.T) {
		fixture := newHAIPIssuanceFixture(t, tokenTestBearer)
		_, err := fixture.authorize(fixture.issuanceRequest())
		require.ErrorIs(t, err, oid4vci.ErrDPoPRequired)
		require.Equal(t, 1, fixture.tokenCalls)
		require.Equal(t, 0, fixture.credentialCalls)
	})
}

// Section 6.1 makes token_type REQUIRED and the wallet presents only Bearer
// and DPoP, so another scheme is refused rather than presented as Bearer.
func TestTokenStageRejectsUnknownTokenType(t *testing.T) {
	t.Run("pre-authorized code", func(t *testing.T) {
		fixture := newFinalIssuanceFixture(t, tokenTestUnknownTokenType)
		_, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
		require.ErrorIs(t, err, ErrTokenTypeUnsupported)
		require.Equal(t, 0, fixture.credentialCalls)
	})
	t.Run("authorization code", func(t *testing.T) {
		fixture := newFinalIssuanceFixture(t, tokenTestUnknownTokenType)
		_, err := fixture.authorize(fixture.issuanceRequest())
		require.ErrorIs(t, err, ErrTokenTypeUnsupported)
		require.Equal(t, 0, fixture.credentialCalls)
	})
}

// A wallet without a DPoP key cannot present a DPoP-bound token, so it is
// refused rather than downgraded to Bearer use.
func TestAuthorizePreAuthorizedIssuanceRejectsDPoPWithoutKey(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, tokenTestAnonymous)
	_, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
	require.ErrorIs(t, err, oid4vci.ErrDPoPRequired)
	require.Equal(t, 0, fixture.credentialCalls)
}

// Under HAIP the DPoP-bound token is accepted and the client authenticates
// with private_key_jwt (HAIP Section 4.4.1).
func TestAuthorizePreAuthorizedIssuanceAcceptsDPoPUnderHAIP(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t)
	grant, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
	require.NoError(t, err)
	require.Equal(t, "DPoP", grant.AccessToken.TokenType)
	require.NotEmpty(t, grant.DPoPKeyThumbprint)
	require.Equal(t, "credential-nonce-1", grant.CNonce)
	require.NotEmpty(t, fixture.tokenHeaders.Get("DPoP"))
	require.Equal(t, string(receiverTypes.PreAuthorizedCode), fixture.tokenForms[0].Get("grant_type"))
	require.Equal(t, "client-1", fixture.tokenForms[0].Get("client_id"))
	require.NotEmpty(t, fixture.tokenForms[0].Get("client_assertion"))
	require.Equal(t, receiverTypes.ClientAssertionTypeJWTBearer, fixture.tokenForms[0].Get("client_assertion_type"))
}

// HAIP has no anonymous clients (HAIP Section 4.4.1).
func TestAuthorizePreAuthorizedIssuanceRejectsAnonymousUnderHAIP(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, func(f *finalIssuanceFixture) { f.clientAuthKey = nil })
	_, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "HAIP requires an OAuth2 client authentication mechanism")
	require.Equal(t, 0, fixture.tokenCalls)

	fixture.wallet.attestationConfig.Client = &attestation.StaticClientAttester{Key: testKeyEntry(t, fixture.attesterKey)}
	fixture.wallet.clientAuth = ClientAuthConfig{}
	_, err = fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "client_id")
	require.Equal(t, 0, fixture.tokenCalls)
}

// The Pre-Authorized Code grant stops at the same key attestation
// interruption, and an attestation minted elsewhere completes it in another
// wallet.
func TestAuthorizePreAuthorizedIssuanceCrossesTheKeyAttestationBoundary(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, tokenTestBearer, tokenTestKeyAttestationsRequired)
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-1")
	grant, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
	require.NoError(t, err)
	require.True(t, grant.KeyAttestationRequired)
	require.Equal(t, "credential-nonce-1", grant.CNonce)
	require.Equal(t, 0, fixture.credentialCalls)

	var restoredGrant IssuanceGrant
	requireJSONRoundTrip(t, grant, &restoredGrant)
	fixture.attestationTrust = tokenTestAttesterTrust(attesterKey)
	credentialWallet := fixture.newWallet(t)
	_, err = credentialWallet.RequestCredential(context.Background(), &restoredGrant, fixture.credentialRequest())
	var required *KeyAttestationRequiredError
	require.ErrorAs(t, err, &required)

	signed := fixture.credentialRequest()
	signed.KeyAttestation = tokenTestKeyAttestation(t, attesterKey, required.HolderKeys, required.CNonce, required.Audience)
	result, err := credentialWallet.RequestCredential(context.Background(), required.Grant, signed)
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
}

// OpenID4VCI 1.0 Appendix E satisfies HAIP Section 4.4.1 on the Pre-Authorized
// Code token request: the headers carry the Client Attestation and its PoP,
// and the form carries no client_assertion.
func TestAuthorizePreAuthorizedIssuanceCarriesClientAttestationUnderHAIP(t *testing.T) {
	fixture, attesterKey := tokenTestHAIPAttestationFixture(t)
	grant, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
	require.NoError(t, err)
	require.Equal(t, "DPoP", grant.AccessToken.TokenType)
	require.Equal(t, 1, fixture.tokenCalls)
	require.Equal(t, string(receiverTypes.PreAuthorizedCode), fixture.tokenForms[0].Get("grant_type"))
	require.NotEmpty(t, fixture.tokenHeaders.Get("DPoP"))

	tokenTestVerifyClientAttestationHeaders(t, fixture.tokenHeaders, attesterKey, fixture.clientKey, "client-1", fixture.server.URL)
	require.Empty(t, fixture.tokenForms[0].Get("client_assertion"))
	require.Empty(t, fixture.tokenForms[0].Get("client_assertion_type"))
}

// RFC 9449 Section 8: the use_dpop_nonce retry re-signs the DPoP proof with
// the nonce, and mints a new Client Attestation PoP with its own jti.
func TestAuthorizePreAuthorizedIssuanceRefreshesAttestationOnDPoPNonceRetry(t *testing.T) {
	fixture, attesterKey := tokenTestHAIPAttestationFixture(t, func(f *finalIssuanceFixture) {
		f.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
			if f.tokenCalls == 1 {
				w.Header().Set("DPoP-Nonce", "token-nonce-1")
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "use_dpop_nonce"})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, f.tokenResponseValue())
		}
	})
	grant, err := fixture.tokenTestPreAuthorize(fixture.tokenTestPreAuthorizedRequest(nil))
	require.NoError(t, err)
	require.Equal(t, "DPoP", grant.AccessToken.TokenType)
	require.Equal(t, 2, fixture.tokenCalls)
	require.Len(t, fixture.tokenHeaderList, 2)

	_, firstPop := tokenTestVerifyClientAttestationHeaders(t, fixture.tokenHeaderList[0], attesterKey, fixture.clientKey, "client-1", fixture.server.URL)
	_, secondPop := tokenTestVerifyClientAttestationHeaders(t, fixture.tokenHeaderList[1], attesterKey, fixture.clientKey, "client-1", fixture.server.URL)
	require.NotEqual(t, firstPop["jti"], secondPop["jti"])

	firstProof := tokenTestVerifyJWT(t, fixture.tokenHeaderList[0].Get("DPoP"), fixture.clientKey)
	secondProof := tokenTestVerifyJWT(t, fixture.tokenHeaderList[1].Get("DPoP"), fixture.clientKey)
	require.Empty(t, firstProof["nonce"])
	require.Equal(t, "token-nonce-1", secondProof["nonce"])
	require.NotEqual(t, firstProof["jti"], secondProof["jti"])
}

// A resumed authorization state is checked against the Config and the
// metadata the issuer publishes now; nothing in it can point the token request
// elsewhere.
func TestAuthorizeIssuanceRefusesAStateThatDoesNotFit(t *testing.T) {
	for name, tc := range map[string]struct {
		tamper func(f *finalIssuanceFixture, other *finalIssuanceFixture, a *IssuanceAuthorization, w *Wallet)
		want   error
	}{
		"credential issuer that does not delegate to the recorded server": {
			tamper: func(_ *finalIssuanceFixture, other *finalIssuanceFixture, a *IssuanceAuthorization, _ *Wallet) {
				a.CredentialIssuer = other.server.URL
			},
			want: ErrIssuanceStateMismatch,
		},
		"undelegated authorization server": {
			tamper: func(_ *finalIssuanceFixture, other *finalIssuanceFixture, a *IssuanceAuthorization, _ *Wallet) {
				a.AuthorizationServer = other.server.URL
			},
			want: ErrIssuanceStateMismatch,
		},
		"unknown configuration": {
			tamper: func(_ *finalIssuanceFixture, _ *finalIssuanceFixture, a *IssuanceAuthorization, _ *Wallet) {
				a.CredentialConfigurationID = "other"
			},
			want: ErrUnknownCredentialConfiguration,
		},
		"missing code_verifier": {
			tamper: func(_ *finalIssuanceFixture, _ *finalIssuanceFixture, a *IssuanceAuthorization, _ *Wallet) {
				a.CodeVerifier = ""
			},
			want: ErrIssuanceStateMismatch,
		},
		"state names another client_id": {
			tamper: func(_ *finalIssuanceFixture, _ *finalIssuanceFixture, a *IssuanceAuthorization, _ *Wallet) {
				a.ClientID = "client-2"
			},
			want: ErrIssuanceStateMismatch,
		},
		"state names another redirect_uri": {
			tamper: func(_ *finalIssuanceFixture, _ *finalIssuanceFixture, a *IssuanceAuthorization, _ *Wallet) {
				a.RedirectURI = "https://wallet.example/cb"
			},
			want: ErrIssuanceStateMismatch,
		},
		"Config names another client_id": {
			tamper: func(_ *finalIssuanceFixture, _ *finalIssuanceFixture, _ *IssuanceAuthorization, w *Wallet) {
				w.clientAuth.ClientID = "client-2"
			},
			want: ErrIssuanceStateMismatch,
		},
		"Config names another redirect_uri": {
			tamper: func(_ *finalIssuanceFixture, _ *finalIssuanceFixture, _ *IssuanceAuthorization, w *Wallet) {
				w.issuance.RedirectURI = "https://wallet.example/cb"
			},
			want: ErrIssuanceStateMismatch,
		},
		"another version": {
			tamper: func(_ *finalIssuanceFixture, _ *finalIssuanceFixture, a *IssuanceAuthorization, _ *Wallet) {
				a.Version = IssuanceVersionDraft13
			},
			want: ErrIssuanceVersionMismatch,
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFinalIssuanceFixture(t)
			other := newFinalIssuanceFixture(t)
			authorization, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
			require.NoError(t, err)
			location, err := fixture.followAuthorization(authorization)
			require.NoError(t, err)
			var restored IssuanceAuthorization
			requireJSONRoundTrip(t, authorization, &restored)
			resumed := fixture.newWallet(t)
			tc.tamper(fixture, other, &restored, resumed)

			_, err = resumed.AuthorizeIssuance(context.Background(), &restored, location)
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, 0, fixture.tokenCalls)
			require.Equal(t, 0, other.tokenCalls)
		})
	}
}

// A resumed state reads the metadata the issuer publishes now, not a copy.
func TestAuthorizeIssuanceRefetchesTheMetadata(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	authorization, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.NoError(t, err)
	require.Equal(t, 1, fixture.issuerMetadataCalls)
	location, err := fixture.followAuthorization(authorization)
	require.NoError(t, err)

	var restored IssuanceAuthorization
	requireJSONRoundTrip(t, authorization, &restored)
	_, err = fixture.wallet.AuthorizeIssuance(context.Background(), &restored, location)
	require.NoError(t, err)
	require.Equal(t, 2, fixture.issuerMetadataCalls)
}

// A grant names its Credential Issuer and authorization server; a grant
// rewritten to another issuer does not get the access token sent anywhere.
func TestRequestCredentialRefusesGrantOfAnotherIssuer(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	other := newFinalIssuanceFixture(t)
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)

	var restored IssuanceGrant
	requireJSONRoundTrip(t, grant, &restored)
	restored.CredentialIssuer = other.server.URL
	_, err = fixture.wallet.RequestCredential(context.Background(), &restored, fixture.credentialRequest())
	require.ErrorIs(t, err, ErrIssuanceStateMismatch)
	require.Equal(t, 0, fixture.credentialCalls)
	require.Equal(t, 0, other.credentialCalls)
}

// HAIP Section 4.4.1 applies to the token request of a resumed authorization,
// not only to the PAR request BeginIssuance sent.
func TestAuthorizeIssuanceRequiresHAIPClientAuthenticationOnResume(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t)
	authorization, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.NoError(t, err)
	location, err := fixture.followAuthorization(authorization)
	require.NoError(t, err)

	fixture.clientAuthKey = nil
	_, err = fixture.newWallet(t).AuthorizeIssuance(context.Background(), authorization, location)
	require.ErrorContains(t, err, "HAIP requires an OAuth2 client authentication mechanism")
	require.Equal(t, 0, fixture.tokenCalls)
}

// HAIP Section 4 requires a DPoP-bound access token; one read back from a
// grant or a deferred issuance is held to that as well.
func TestHAIPResumedAccessTokenMustBeDPoPBound(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
	})
	bearer := &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "Bearer"}

	_, err := fixture.wallet.RequestCredential(context.Background(), &IssuanceGrant{
		Version:                   IssuanceVersionFinal,
		CredentialIssuer:          fixture.server.URL,
		CredentialConfigurationID: "pid",
		AuthorizationServer:       fixture.server.URL,
		AccessToken:               bearer,
	}, fixture.credentialRequest())
	require.ErrorIs(t, err, ErrDPoPRequired)

	_, err = fixture.wallet.RequestDeferredCredential(context.Background(), &DeferredIssuance{
		Version:                   IssuanceVersionFinal,
		CredentialIssuer:          fixture.server.URL,
		CredentialConfigurationID: "pid",
		TransactionID:             "tx-1",
		AccessToken:               bearer,
		HolderKeys:                []jose.JSONWebKey{fixture.holderKey.Public()},
	})
	require.ErrorIs(t, err, ErrDPoPRequired)
	require.Equal(t, 0, fixture.credentialCalls)
	require.Equal(t, 0, fixture.deferredCalls)
}
