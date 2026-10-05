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

// dpopProofFactory returns the RFC 9449 prover for one request, or the zero
// prover when key is nil. The key thumbprint scopes the server nonces the
// receiver keeps to this key.
func dpopProofFactory(ctx context.Context, key IKeyEntry, method, endpoint, accessToken string) receiverTypes.DPoPProver {
	if key == nil {
		return receiverTypes.DPoPProver{}
	}
	thumbprint, _ := keyThumbprint(key)
	return receiverTypes.DPoPProver{
		KeyThumbprint: thumbprint,
		Proof: func(nonce string) (string, error) {
			return jwtproof.DPoP(ctx, key, jwtproof.DPoPOptions{Method: method, URL: endpoint, AccessToken: accessToken, Nonce: nonce})
		},
	}
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

// errNoUsableClientAuthMethod is wrapped by every client authentication
// negotiation failure at the token endpoint.
var errNoUsableClientAuthMethod = common.NewCodedError("client_authentication_unavailable",
	"no usable client authentication method for the authorization server token endpoint")

// tokenEndpointAuth is the negotiation outcome. SendClientID is separate because
// Method None does not imply an anonymous request; OpenID4VCI 1.0 Section 12.3
// decides that.
type tokenEndpointAuth struct {
	Method       receiverTypes.TokenEndpointAuthMethod
	SendClientID bool
}

// resolveClientAuthMethod negotiates how a pre-authorized_code token request
// authenticates. token_endpoint_auth_methods_supported filters the configured
// method and never picks or downgrades one;
// pre-authorized_grant_anonymous_access_supported decides whether client_id
// may be omitted, and, when the server publishes no method list, stands on
// its own for an anonymous request. Do not rearrange the steps below.
func resolveClientAuthMethod(clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata) (tokenEndpointAuth, error) {
	if authMetadata == nil {
		return tokenEndpointAuth{}, fmt.Errorf(
			"authorization server metadata is required to select a client authentication method")
	}

	configured := clientAuth.Method
	if configured == "" {
		configured = receiverTypes.None
	}
	if configured != receiverTypes.None && configured != receiverTypes.PrivateKeyJwt {
		return tokenEndpointAuth{}, unimplementedAuthMethodError(configured)
	}

	// OpenID4VCI 1.0 Section 6.1: "For the Pre-Authorized Code Grant Type,
	// authentication of the Client is OPTIONAL ... and, consequently, the
	// client_id parameter is only needed when a form of Client Authentication
	// that relies on this parameter is used". Section 12.3 defines
	// pre-authorized_grant_anonymous_access_supported as "whether the
	// Credential Issuer accepts a Token Request with a Pre-Authorized Code but
	// without a client_id". A server that declares it and publishes no
	// token_endpoint_auth_methods_supported takes the anonymous request:
	// RFC 8414 Section 2's default for the absent list, client_secret_basic,
	// names how a confidential client authenticates, and an anonymous request
	// authenticates no client. A published list still decides (below).
	if configured == receiverTypes.None && authMetadata.TokenEndpointAuthMethodsSupported == nil &&
		anonymousPreAuthorizedAccessSupported(authMetadata) {
		return tokenEndpointAuth{Method: receiverTypes.None}, nil
	}

	switch methods := authMetadata.TokenEndpointAuthMethodsSupported; {
	case methods == nil:
		return tokenEndpointAuth{}, fmt.Errorf(
			"%w: token_endpoint_auth_methods_supported is absent, so RFC 8414 section 2 makes the token "+
				"endpoint default to client_secret_basic, which this wallet does not implement (supported: %q, %q)",
			errNoUsableClientAuthMethod, receiverTypes.None, receiverTypes.PrivateKeyJwt)
	case len(*methods) == 0:
		return tokenEndpointAuth{}, fmt.Errorf(
			"%w: token_endpoint_auth_methods_supported is an empty array, so the token endpoint "+
				"advertises no client authentication method",
			errNoUsableClientAuthMethod)
	}

	if err := clientAuthMethodUsable(configured, clientAuth, authMetadata); err != nil {
		return tokenEndpointAuth{}, err
	}

	if configured == receiverTypes.PrivateKeyJwt {
		return tokenEndpointAuth{Method: receiverTypes.PrivateKeyJwt, SendClientID: true}, nil
	}

	if anonymousPreAuthorizedAccessSupported(authMetadata) {
		return tokenEndpointAuth{Method: receiverTypes.None}, nil
	}

	if strings.TrimSpace(clientAuth.ClientID) == "" {
		anonState := "absent"
		if authMetadata.PreAuthorizedGrantAnonymousAccessSupported != nil {
			anonState = "false"
		}
		return tokenEndpointAuth{}, fmt.Errorf(
			"%w: the token endpoint accepts %q, but pre-authorized_grant_anonymous_access_supported is %s "+
				"and OID4VCI 1.0 section 12.3 defines its default as false, so the token request must carry "+
				"a client_id and none is configured",
			errNoUsableClientAuthMethod, receiverTypes.None, anonState)
	}
	return tokenEndpointAuth{Method: receiverTypes.None, SendClientID: true}, nil
}

// clientAuthMethodUsable reports whether method can be used against
// authMetadata. It must never read
// pre-authorized_grant_anonymous_access_supported, which resolveClientAuthMethod
// applies itself.
func clientAuthMethodUsable(method receiverTypes.TokenEndpointAuthMethod, clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata) error {
	switch method {
	case receiverTypes.None:
		if !asMetadataSupportsAuthMethod(authMetadata, receiverTypes.None) {
			return methodNotAdvertisedError(method, authMetadata)
		}
		return nil

	case receiverTypes.PrivateKeyJwt:
		if strings.TrimSpace(clientAuth.ClientID) == "" || clientAuth.Key == nil {
			return fmt.Errorf(
				"%w: private_key_jwt requires both a client_id and a client authentication key",
				errNoUsableClientAuthMethod)
		}
		if !asMetadataSupportsAuthMethod(authMetadata, receiverTypes.PrivateKeyJwt) {
			return methodNotAdvertisedError(method, authMetadata)
		}
		if authMetadata.TokenEndpointAuthSigningAlgValuesSupported == nil ||
			len(*authMetadata.TokenEndpointAuthSigningAlgValuesSupported) == 0 {
			return fmt.Errorf(
				"%w: the authorization server advertises private_key_jwt but omits "+
					"token_endpoint_auth_signing_alg_values_supported, which RFC 8414 section 2 requires when "+
					"JWT client authentication is supported and for which it defines no default",
				errNoUsableClientAuthMethod)
		}
		if !asMetadataSupportsSigningAlg(authMetadata, clientAuth.signatureAlgorithm()) {
			return fmt.Errorf(
				"%w: the authorization server does not advertise %s in "+
					"token_endpoint_auth_signing_alg_values_supported %v",
				errNoUsableClientAuthMethod, clientAuth.signatureAlgorithm(),
				*authMetadata.TokenEndpointAuthSigningAlgValuesSupported)
		}
		return nil
	}
	return unimplementedAuthMethodError(method)
}

func unimplementedAuthMethodError(method receiverTypes.TokenEndpointAuthMethod) error {
	return fmt.Errorf(
		"%w: token_endpoint_auth_method %q is configured, but this wallet implements only %q and %q",
		errNoUsableClientAuthMethod, method, receiverTypes.None, receiverTypes.PrivateKeyJwt)
}

// methodNotAdvertisedError quotes back the list the server does advertise. Only
// resolveClientAuthMethod reaches this, past its own nil and empty-list guards.
func methodNotAdvertisedError(method receiverTypes.TokenEndpointAuthMethod, authMetadata *receiverTypes.AuthorizationServerMetadata) error {
	// Not being advertised is None's only failure mode, so an operator who set
	// anonymous access needs telling here why it was not enough.
	anonNote := ""
	if method == receiverTypes.None && anonymousPreAuthorizedAccessSupported(authMetadata) {
		anonNote = " (pre-authorized_grant_anonymous_access_supported is true, but a published" +
			" token_endpoint_auth_methods_supported without none decides only whether client_id may be" +
			" omitted, not whether the token endpoint serves an unauthenticated client)"
	}
	return fmt.Errorf(
		"%w: the wallet is configured for %q, but token_endpoint_auth_methods_supported is %v%s",
		errNoUsableClientAuthMethod, method, *authMetadata.TokenEndpointAuthMethodsSupported, anonNote)
}

// anonymousPreAuthorizedAccessSupported applies
// pre-authorized_grant_anonymous_access_supported (OpenID4VCI 1.0 Section
// 12.3, Draft 13 Section 11.3): a Token Request with a Pre-Authorized Code and
// without a client_id is accepted only when the authorization server sets it
// to true. "The default is false", so an absent value refuses.
func anonymousPreAuthorizedAccessSupported(authMetadata *receiverTypes.AuthorizationServerMetadata) bool {
	if authMetadata == nil || authMetadata.PreAuthorizedGrantAnonymousAccessSupported == nil {
		return false
	}
	return *authMetadata.PreAuthorizedGrantAnonymousAccessSupported
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
