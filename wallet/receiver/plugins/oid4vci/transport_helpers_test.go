package oid4vci

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// dpopAccessToken is a DPoP-bound Token Response carrying accessToken.
func dpopAccessToken(accessToken string) types.CredentialIssuanceAccessToken {
	return types.CredentialIssuanceAccessToken{Token: accessToken, TokenType: dpopAuthorizationScheme}
}

// fixedProof returns the same DPoP proof for every attempt.
func fixedProof(proof string) types.DPoPProofFactory {
	return func(string) (string, error) { return proof, nil }
}

// fixedAttestationHeaders returns the same client attestation headers for every attempt.
func fixedAttestationHeaders(headers types.OAuthClientAttestationHeaders) types.OAuthClientAttestationHeadersFactory {
	return func() (types.OAuthClientAttestationHeaders, error) { return headers, nil }
}

// postCredentialBody posts a pre-encoded body to a protected endpoint with a
// DPoP-bound access token and no c_nonce refresh.
func postCredentialBody(ctx context.Context, receiver *Oid4vciReceiver, endpoint common.URIField, accessToken string, body []byte, contentType string, proof types.DPoPProofFactory) (*types.CredentialEndpointHTTPResponse, error) {
	return receiver.RequestDeferredCredential(ctx, endpoint, dpopAccessToken(accessToken), body, contentType, proof)
}

// signDPoP builds an RFC 9449 DPoP proof with key, as a wallet's factory does.
func signDPoP(key jose.JSONWebKey, method, rawURL, nonce, accessToken string) (string, error) {
	entry, err := keystore.NewKeyEntryFromJWK(key)
	if err != nil {
		return "", err
	}
	return jwtproof.DPoP(context.Background(), entry, jwtproof.DPoPOptions{Method: method, URL: rawURL, Nonce: nonce, AccessToken: accessToken})
}

// signClientAttestation self-issues a Client Attestation for clientKey.
func signClientAttestation(clientKey, attesterKey jose.JSONWebKey, attesterIssuer, clientID string) (string, error) {
	entry, err := keystore.NewKeyEntryFromJWK(attesterKey)
	if err != nil {
		return "", err
	}
	return jwtproof.ClientAttestation(context.Background(), entry, jwtproof.ClientAttestationOptions{Issuer: attesterIssuer, ClientID: clientID, ClientKey: clientKey})
}

// signClientAttestationPoP builds the Client Attestation PoP for clientKey.
func signClientAttestationPoP(clientKey jose.JSONWebKey, clientID, audience, challenge string) (string, error) {
	entry, err := keystore.NewKeyEntryFromJWK(clientKey)
	if err != nil {
		return "", err
	}
	return jwtproof.ClientAttestationPoP(context.Background(), entry, jwtproof.ClientAttestationPoPOptions{ClientID: clientID, Audience: audience, Challenge: challenge})
}

// requestCredentialJSON posts payload as JSON to a Credential or Deferred
// Credential Endpoint and decodes the plaintext response.
func requestCredentialJSON(ctx context.Context, receiver *Oid4vciReceiver, endpoint common.URIField, accessToken string, payload any, proof types.DPoPProofFactory) (*types.CredentialResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	response, err := postCredentialBody(ctx, receiver, endpoint, accessToken, body, "application/json", proof)
	if err != nil {
		return nil, err
	}
	return receiver.DecodeCredentialResponse(response.Body, response.ContentType, nil, false)
}

// useDPoPNonceTokenChallenge answers as an RFC 9449 Section 8 authorization
// server that requires a nonce. The caller sets the DPoP-Nonce header first.
func useDPoPNonceTokenChallenge(w http.ResponseWriter) {
	_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "use_dpop_nonce"})
}

// useDPoPNonceResourceChallenge answers as an RFC 9449 Section 9 resource
// server that requires a nonce. The caller sets the DPoP-Nonce header first.
func useDPoPNonceResourceChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"`)
	w.WriteHeader(http.StatusUnauthorized)
}
