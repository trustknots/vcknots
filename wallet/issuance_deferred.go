package wallet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// RequestDeferredCredential sends one OpenID4VCI 1.0 Deferred Credential
// Request (Section 9) for d. While the issuer has not issued the credentials,
// the result's Deferred is d with the interval the issuer asked for; the
// library does not wait or retry. Issued credentials are accepted as in
// RequestCredential.
func (w *Wallet) RequestDeferredCredential(ctx context.Context, d *DeferredIssuance) (*IssuanceResult, error) {
	result, err := w.requestDeferredCredential(ctx, d)
	return result, classify(err)
}

func (w *Wallet) requestDeferredCredential(ctx context.Context, d *DeferredIssuance) (*IssuanceResult, error) {
	if err := checkDeferred(d, IssuanceVersionFinal); err != nil {
		return nil, err
	}
	if err := w.requireFinalIssuance(ctx); err != nil {
		return nil, err
	}
	if err := w.checkGrantToken(d.AccessToken); err != nil {
		return nil, err
	}
	dpopKey, err := w.requireDPoPKey(d.DPoPKeyThumbprint, d.AccessToken, fmt.Errorf("the access token is DPoP-bound but no DPoP key is configured: %w", ErrDPoPKeyMismatch))
	if err != nil {
		return nil, err
	}
	transport, err := w.oid4vciTransport()
	if err != nil {
		return nil, err
	}
	discovery, err := w.discoverIssuance(ctx, transport, d.cache, d.CredentialIssuer, offeredAuthorizationServer(""), false)
	if err != nil {
		return nil, err
	}
	md := discovery.issuerMetadata
	if _, err := credentialConfiguration(md, d.CredentialConfigurationID); err != nil {
		return nil, err
	}
	if md.DeferredCredentialEndpoint == nil {
		return nil, invalidMetadata("deferred credential endpoint is missing on credential issuer")
	}
	// Section 9.1: response encryption is used only when the request repeats
	// credential_response_encryption, so the stored key is sent again.
	// EncodeCredentialRequest then encrypts the request (Section 8.1).
	request := map[string]any{"transaction_id": d.TransactionID}
	if d.ResponseDecryptionKey != nil {
		encryption, err := receiverOid4vci.CredentialResponseEncryptionParameters(md, d.ResponseDecryptionKey)
		if err != nil {
			return nil, fmt.Errorf("credential response encryption: %w", withCode(receiverTypes.ErrInvalidMetadata, err))
		}
		request["credential_response_encryption"] = encryption
	}
	body, contentType, err := transport.EncodeCredentialRequest(request, md)
	if err != nil {
		return nil, fmt.Errorf("failed to encode deferred credential request: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	endpoint := *md.DeferredCredentialEndpoint
	raw, err := transport.RequestDeferredCredential(ctx, endpoint, *d.AccessToken, body, contentType,
		dpopProofFactory(ctx, dpopKey, http.MethodPost, endpoint.String(), d.AccessToken.Token))
	if err != nil {
		var endpointError *receiverTypes.CredentialEndpointError
		if errors.Is(err, receiverTypes.ErrIssuancePending) && errors.As(err, &endpointError) {
			return pendingDeferred(d, w, discovery, endpointError.Interval), nil
		}
		return nil, fmt.Errorf("failed to receive deferred credential: %w", err)
	}
	response, err := decodeCredentialResponse(transport, raw, d.ResponseDecryptionKey, len(d.HolderKeys))
	if err != nil {
		return nil, err
	}
	if len(response.Credentials) == 0 {
		// A response that defers again repeats the transaction_id.
		if response.TransactionID != d.TransactionID {
			return nil, fmt.Errorf("%w: deferred credential response named transaction_id %q, not %q", ErrCredentialResponseShape, response.TransactionID, d.TransactionID)
		}
		result := pendingDeferred(d, w, discovery, response.Interval)
		result.CredentialResponse = response
		return result, nil
	}
	return w.acceptCredentialResponse(ctx, md, d.CredentialConfigurationID, d.AccessToken, d.DPoPKeyThumbprint, response, d.HolderKeys)
}

// pendingDeferred returns d, still pending, with the interval the issuer
// named.
func pendingDeferred(d *DeferredIssuance, w *Wallet, discovery *issuanceDiscovery, intervalSeconds int) *IssuanceResult {
	pending := *d
	pending.Interval = intervalDuration(intervalSeconds)
	pending.cache = w.newIssuanceMetadataCache(discovery)
	return &IssuanceResult{Deferred: &pending}
}

// checkDeferred checks that d is a complete state of version.
func checkDeferred(d *DeferredIssuance, version IssuanceVersion) error {
	if d == nil {
		return invalidArgument("deferred issuance is required")
	}
	if d.Version != version {
		return fmt.Errorf("deferred issuance has version %q: %w", d.Version, ErrIssuanceVersionMismatch)
	}
	if d.CredentialIssuer == "" || d.CredentialConfigurationID == "" || strings.TrimSpace(d.TransactionID) == "" {
		return fmt.Errorf("deferred issuance does not name its credential issuer, configuration and transaction: %w", ErrIssuanceStateMismatch)
	}
	return nil
}
