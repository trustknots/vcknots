package oid4vp

import (
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4/jwt"
)

// lookupPreRegisteredClient resolves a pre-registered Client Identifier against
// the wallet's registry: the in-memory map first, then the caller's resolver.
// OID4VP 1.0 §5.9.2: "the Client Identifier needs to be known to the Wallet in
// advance of the Authorization Request", so an unresolved identifier is an
// error rather than an unauthenticated Verifier.
func (b *requestBuilder) lookupPreRegisteredClient(clientID string) (*PreRegisteredClient, error) {
	if registered, exists := b.settings().preRegisteredClients[clientID]; exists {
		return preRegisteredClientWithID(&registered, clientID), nil
	}
	if b.settings().resolvePreRegisteredClient != nil {
		resolved, err := b.settings().resolvePreRegisteredClient(clientID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve pre-registered client_id %q: %w", clientID, err)
		}
		if resolved != nil {
			copied := *resolved
			return preRegisteredClientWithID(&copied, clientID), nil
		}
	}
	return nil, fmt.Errorf("pre-registered client_id %q is not known to this wallet: %w", clientID, ErrPreRegisteredClientUnknown)
}

// preRegisteredClientWithID fills in the registration's ClientID from the
// request when a map registration left it empty, so consumers never have to
// consult the map key.
func preRegisteredClientWithID(client *PreRegisteredClient, clientID string) *PreRegisteredClient {
	if client.ClientID == "" {
		client.ClientID = clientID
	}
	return client
}

// authenticatePreRegisteredRequestObject verifies a pre-registered client's
// Request Object with the keys registered for it.
func (b *requestBuilder) authenticatePreRegisteredRequestObject(parsed *jwt.JSONWebToken, options RequestObjectValidationOptions) error {
	client := b.preRegisteredClient
	if client == nil || client.JWKS == nil || len(client.JWKS.Keys) == 0 {
		return fmt.Errorf("%w: pre-registered client %q has no registered request signing key", ErrRequestObjectClientAuthUnsupported, b.req.ClientID)
	}
	verified, err := verifyRequestObjectWithKeySet(parsed, *client.JWKS)
	if err != nil {
		return err
	}
	if err := b.requireWalletNonceEcho(verified); err != nil {
		return err
	}
	if err := validateRequestObjectClaims(verified, b.resolveClaimPolicy(options, requestObjectNow(options))); err != nil {
		return fmt.Errorf("JWT standard claims validation failed: %w", err)
	}
	b.req.RequestObjectVerification = &RequestObjectVerification{
		ClientID:    b.req.ClientID,
		WalletNonce: b.sentWalletNonce,
		ExpiresAt:   requestObjectExpiry(verified),
	}
	return nil
}

// checkPreRegisteredClient holds a pre-registered client's request to its
// registration: the response endpoint must be a registered redirect_uri,
// compared exactly (OID4VP 1.0 §5.1 response_uri, RFC 6749 §3.1.2.3), and a
// registration that requires signed requests refuses an unsigned one.
func (b *requestBuilder) checkPreRegisteredClient() error {
	client := b.preRegisteredClient
	if client == nil {
		return nil
	}
	if client.RequireSignedRequestObject && b.req.RequestObjectVerification == nil {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrRequestObjectSignatureRequired)
	}
	var registered []string
	if client.Metadata != nil {
		registered = client.Metadata.RedirectURIs
	}
	endpoint := b.req.responseEndpoint()
	if endpoint == "" || !slices.Contains(registered, endpoint) {
		return newAuthorizationRequestError(InvalidRequestError, "%w: %q", ErrPreRegisteredClientEndpointUnregistered, endpoint)
	}
	return nil
}
