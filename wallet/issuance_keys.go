package wallet

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// dpopTokenType is the RFC 9449 Section 7.1 token_type; token_type is compared
// case-insensitively (RFC 6749 Section 7.1).
const dpopTokenType = "DPoP"

// clientAssertionLifetime bounds the exp of a private_key_jwt assertion.
const clientAssertionLifetime = 5 * time.Minute

// clientAttestationPoPLifetime bounds the exp of a Client Attestation PoP.
const clientAttestationPoPLifetime = 5 * time.Minute

// dpopProofFactory returns the RFC 9449 proof factory for one request, or nil
// when key is nil.
func dpopProofFactory(ctx context.Context, key IKeyEntry, method, endpoint, accessToken string) receiverTypes.DPoPProofFactory {
	if key == nil {
		return nil
	}
	return func(nonce string) (string, error) {
		return jwtproof.DPoP(ctx, key, jwtproof.DPoPOptions{Method: method, URL: endpoint, AccessToken: accessToken, Nonce: nonce})
	}
}

// generateDPoPProof builds one DPoP proof; a nil or empty nonce omits the
// claim.
func (w *Wallet) generateDPoPProof(key IKeyEntry, method, targetURL, accessToken string, nonce *string) (string, error) {
	if key == nil {
		return "", fmt.Errorf("dpop key is required")
	}
	options := jwtproof.DPoPOptions{Method: method, URL: targetURL, AccessToken: accessToken}
	if nonce != nil {
		options.Nonce = *nonce
	}
	proof, err := jwtproof.DPoP(context.Background(), key, options)
	if err != nil {
		return "", fmt.Errorf("failed to serialize dpop proof: %w", err)
	}
	return proof, nil
}

// generateClientAssertion builds an RFC 7523 private_key_jwt client assertion
// (iss and sub are clientID) signed with alg, one of ES256, ES384 or ES512.
func (w *Wallet) generateClientAssertion(key IKeyEntry, clientID, audience string, alg jose.SignatureAlgorithm) (string, error) {
	return clientAssertion(context.Background(), key, clientID, audience, alg)
}

func clientAssertion(ctx context.Context, key IKeyEntry, clientID, audience string, alg jose.SignatureAlgorithm) (string, error) {
	if key == nil {
		return "", fmt.Errorf("client auth key is required")
	}
	if strings.TrimSpace(clientID) == "" {
		return "", fmt.Errorf("clientID is required for client assertion")
	}
	if strings.TrimSpace(audience) == "" {
		return "", fmt.Errorf("audience is required for client assertion aud")
	}
	if _, err := curveForSignatureAlgorithm(alg); err != nil {
		return "", err
	}
	return jwtproof.ClientAssertion(ctx, key, jwtproof.ClientAssertionOptions{
		ClientID:  clientID,
		Audience:  audience,
		Algorithm: alg,
		Lifetime:  clientAssertionLifetime,
	})
}

// errNoUsableClientAuthMethod reports that neither anonymous access nor the
// configured method can be used at the token endpoint.
var errNoUsableClientAuthMethod = common.NewCodedError("client_authentication_unavailable",
	"no usable client authentication method for the authorization server token endpoint; "+
		"the authorization server declares pre-authorized_grant_anonymous_access_supported as false, "+
		"or it does not support the configured client authentication method")

// resolveClientAuthMethod reports the configured method (None when empty) and
// whether the authorization server accepts it.
func resolveClientAuthMethod(clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata) (receiverTypes.TokenEndpointAuthMethod, bool) {
	method := clientAuth.Method
	if method == "" {
		method = receiverTypes.None
	}
	return method, clientAuthMethodAvailable(method, clientAuth, authMetadata)
}

// clientAuthMethodAvailable reports whether method can be used against the
// authorization server.
func clientAuthMethodAvailable(method receiverTypes.TokenEndpointAuthMethod, clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata) bool {
	switch method {
	case receiverTypes.None:
		// pre-authorized_grant_anonymous_access_supported is OPTIONAL, so only
		// an explicit false refuses anonymous access.
		if authMetadata == nil {
			return false
		}
		anonymousAccess := authMetadata.PreAuthorizedGrantAnonymousAccessSupported
		return anonymousAccess == nil || *anonymousAccess
	case receiverTypes.PrivateKeyJwt:
		if strings.TrimSpace(clientAuth.ClientID) == "" || clientAuth.Key == nil {
			return false
		}
		if !asMetadataSupportsAuthMethod(authMetadata, receiverTypes.PrivateKeyJwt) {
			return false
		}
		return asMetadataSupportsSigningAlg(authMetadata, clientAuth.signatureAlgorithm())
	}
	return false
}

func asMetadataSupportsAuthMethod(authMetadata *receiverTypes.AuthorizationServerMetadata, method receiverTypes.TokenEndpointAuthMethod) bool {
	if authMetadata == nil || authMetadata.TokenEndpointAuthMethodsSupported == nil {
		return false
	}
	for _, m := range *authMetadata.TokenEndpointAuthMethodsSupported {
		if m == method {
			return true
		}
	}
	return false
}

// asMetadataSupportsSigningAlg reports whether alg is advertised; RFC 8414
// defines no default.
func asMetadataSupportsSigningAlg(authMetadata *receiverTypes.AuthorizationServerMetadata, alg jose.SignatureAlgorithm) bool {
	if authMetadata == nil || authMetadata.TokenEndpointAuthSigningAlgValuesSupported == nil {
		return false
	}
	for _, a := range *authMetadata.TokenEndpointAuthSigningAlgValuesSupported {
		if a == alg {
			return true
		}
	}
	return false
}

// resolveClientAssertionAudience returns the aud of a client assertion:
// ClientAuthConfig.AssertionAudience, else the authorization server issuer,
// else the token endpoint.
func resolveClientAssertionAudience(clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata, tokenEndpointURL string) string {
	if audience := strings.TrimSpace(clientAuth.AssertionAudience); audience != "" {
		return audience
	}
	if authMetadata != nil {
		issuerURL := url.URL(authMetadata.Issuer)
		if issuer := strings.TrimSpace(issuerURL.String()); issuer != "" {
			return issuer
		}
	}
	return tokenEndpointURL
}

// privateKeyJWTFactory returns the client_assertion factory for the token and
// PAR endpoints of asMetadata; each attempt signs a fresh assertion (RFC 7523
// Section 3 unique jti).
func (w *Wallet) privateKeyJWTFactory(ctx context.Context, asMetadata *receiverTypes.AuthorizationServerMetadata) receiverTypes.ClientAssertionFactory {
	tokenEndpoint := ""
	if asMetadata.TokenEndpoint != nil {
		tokenEndpoint = asMetadata.TokenEndpoint.String()
	}
	audience := resolveClientAssertionAudience(w.clientAuth, asMetadata, tokenEndpoint)
	return func() (string, error) {
		return clientAssertion(ctx, w.clientAuth.Key, w.clientAuth.ClientID, audience, w.clientAuth.signatureAlgorithm())
	}
}

// isDPoPAccessToken reports whether the token is DPoP-bound.
func isDPoPAccessToken(token *receiverTypes.CredentialIssuanceAccessToken) bool {
	return token != nil && strings.EqualFold(strings.TrimSpace(token.TokenType), dpopTokenType)
}

// jwkThumbprint is the base64url RFC 7638 SHA-256 thumbprint of key.
func jwkThumbprint(key jose.JSONWebKey) (string, error) {
	if key.Key == nil {
		return "", fmt.Errorf("missing key")
	}
	public := key.Public()
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// keyThumbprint is jwkThumbprint of key's public JWK; "" for a nil key.
func keyThumbprint(key IKeyEntry) (string, error) {
	if key == nil {
		return "", nil
	}
	return jwkThumbprint(key.PublicKey())
}

// requireDPoPKey returns Config.DPoP.Key when the state recorded a DPoP-bound
// token, after checking it is the key the token is bound to.
func (w *Wallet) requireDPoPKey(recordedThumbprint string, token *receiverTypes.CredentialIssuanceAccessToken, missing error) (IKeyEntry, error) {
	if !isDPoPAccessToken(token) {
		return nil, nil
	}
	if w.dpop.Key == nil {
		return nil, missing
	}
	if recordedThumbprint == "" {
		return w.dpop.Key, nil
	}
	thumbprint, err := keyThumbprint(w.dpop.Key)
	if err != nil {
		return nil, fmt.Errorf("DPoP key: %w", err)
	}
	if thumbprint != recordedThumbprint {
		return nil, ErrDPoPKeyMismatch
	}
	return w.dpop.Key, nil
}

// publicKeys returns the public JWKs of keys.
func publicKeys(keys []IKeyEntry) []jose.JSONWebKey {
	public := make([]jose.JSONWebKey, 0, len(keys))
	for _, key := range keys {
		jwk := key.PublicKey()
		public = append(public, jwk.Public())
	}
	return public
}

// jwsHeader decodes the protected header of a compact JWS without verifying
// it.
func jwsHeader(token string) (map[string]any, error) {
	encoded, _, found := strings.Cut(token, ".")
	if !found {
		return nil, fmt.Errorf("not a compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid JWS header encoding: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("invalid JWS header JSON: %w", err)
	}
	return header, nil
}

// jwsClaims decodes the payload of a compact JWS without verifying it.
func jwsClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected a compact JWS with three parts")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWS payload encoding: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("invalid JWS payload JSON: %w", err)
	}
	return claims, nil
}
