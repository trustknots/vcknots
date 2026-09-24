package wallet

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// AuthorizePreAuthorizedIssuance runs the OpenID4VCI 1.0 Pre-Authorized Code
// Flow token request (Sections 4.1.1 and 6.1) and fetches the c_nonce. The
// client is anonymous unless Config.Attestation.Client or private_key_jwt
// authenticates it; HAIP requires one of them. A DPoP proof is sent whenever
// Config.DPoP.Key is set.
func (w *Wallet) AuthorizePreAuthorizedIssuance(ctx context.Context, req PreAuthorizedIssuanceRequest) (*IssuanceGrant, error) {
	grant, err := w.authorizePreAuthorizedIssuance(ctx, req)
	return grant, classify(err)
}

func (w *Wallet) authorizePreAuthorizedIssuance(ctx context.Context, req PreAuthorizedIssuanceRequest) (*IssuanceGrant, error) {
	if err := w.requireFinalAuthorizationStage(ctx); err != nil {
		return nil, err
	}
	if req.CredentialOffer == nil {
		return nil, invalidArgument("credential offer is required")
	}
	offered, err := fromOffer(req.CredentialOffer, req.CredentialConfigurationID, string(receiverTypes.PreAuthorizedCode), ErrPreAuthorizedGrantMissing)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(offered.grant.PreAuthorizedCode) == "" {
		return nil, ErrPreAuthorizedGrantMissing
	}
	if err := checkTxCode(offered.grant, req.TxCode); err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(w.clientAuth.ClientID)
	if w.profile.IsHAIP() && clientID == "" {
		return nil, invalidArgument("HAIP requires a client_id on the pre-authorized_code token request")
	}
	hint := strings.TrimSpace(req.AuthorizationServer)
	if hint == "" {
		hint = strings.TrimSpace(offered.grant.AuthorizationServer)
	}

	transport, err := w.oid4vciTransport()
	if err != nil {
		return nil, err
	}
	discovery, err := w.discoverIssuance(ctx, transport, nil, offered.issuer, offeredAuthorizationServer(hint), true)
	if err != nil {
		return nil, err
	}
	as := discovery.asMetadata
	if as.TokenEndpoint == nil {
		return nil, invalidMetadata("token endpoint is missing on authorization server")
	}
	config, err := w.finalCredentialConfiguration(transport, discovery.issuerMetadata, offered.configurationID)
	if err != nil {
		return nil, err
	}
	if err := w.issuance.CredentialEncryption.validate(discovery.issuerMetadata); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	auth, err := w.clientAuthentication(ctx, transport, discovery, true)
	if err != nil {
		return nil, err
	}
	// RFC 9449 Section 5: a server that does not implement DPoP ignores the
	// header, and HAIP requires the sender-constrained token it enables.
	auth.DPoP = dpopProofFactory(ctx, w.dpop.Key, http.MethodPost, as.TokenEndpoint.String(), "")
	token, err := transport.RequestToken(ctx, *as.TokenEndpoint, receiverTypes.TokenRequest{
		GrantType:         receiverTypes.PreAuthorizedCode,
		PreAuthorizedCode: offered.grant.PreAuthorizedCode,
		TxCode:            req.TxCode,
		ClientID:          clientID,
	}, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange the pre-authorized code: %w", err)
	}
	// The request sent neither scope nor authorization_details, so the Token
	// Response's authorization_details are optional (Section 6.2).
	return w.newFinalGrant(ctx, transport, discovery, offered.configurationID, config, token, authorizationDetailsOptional)
}

// checkTxCode applies Section 6.1: tx_code "MUST be present if a tx_code
// object was present in the Credential Offer", and is only sent then.
func checkTxCode(grant *CredentialOfferGrant, txCode string) error {
	switch {
	case grant.TxCode != nil && strings.TrimSpace(txCode) == "":
		return ErrTransactionCodeRequired
	case grant.TxCode == nil && txCode != "":
		return invalidArgument("the credential offer declares no tx_code, so none may be sent")
	}
	return nil
}

// newFinalGrant checks the Token Response and collects what RequestCredential
// needs: the credential_identifiers (Section 6.2) and the c_nonce (Section 7),
// fetched now so a key attestation can be signed for it in between.
func (w *Wallet) newFinalGrant(
	ctx context.Context,
	transport receiverTypes.OID4VCITransport,
	discovery *issuanceDiscovery,
	configurationID string,
	config receiverTypes.CredentialConfiguration,
	token *receiverTypes.CredentialIssuanceAccessToken,
	mode authorizationDetailsMode,
) (*IssuanceGrant, error) {
	if err := w.checkTokenType(token); err != nil {
		return nil, err
	}
	identifiers, err := credentialIdentifiersFor(token, configurationID, mode)
	if err != nil {
		return nil, err
	}
	md := discovery.issuerMetadata
	required := issuerRequiresKeyAttestation(config)
	// HAIP Section 4.5.1: an issuer that requires key binding advertises a
	// nonce_endpoint.
	if required && md.NonceEndpoint == nil && w.profile.IsHAIP() {
		return nil, fmt.Errorf("the credential configuration %q requires a key attestation: %w", configurationID, ErrNonceEndpointRequired)
	}
	cNonce := ""
	if md.NonceEndpoint != nil {
		nonce, err := transport.RequestNonce(ctx, *md.NonceEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch credential nonce: %w", err)
		}
		cNonce = nonce.CNonce
	}
	grant := &IssuanceGrant{
		Version:                   IssuanceVersionFinal,
		CredentialIssuer:          md.CredentialIssuer,
		CredentialConfigurationID: configurationID,
		AuthorizationServer:       discovery.authorizationServer,
		AccessToken:               token,
		CredentialIdentifiers:     identifiers,
		CNonce:                    cNonce,
		KeyAttestationRequired:    required,
		cache:                     w.newIssuanceMetadataCache(discovery),
	}
	if isDPoPAccessToken(token) {
		if grant.DPoPKeyThumbprint, err = keyThumbprint(w.dpop.Key); err != nil {
			return nil, fmt.Errorf("failed to compute the DPoP key thumbprint: %w", err)
		}
	}
	return grant, nil
}

// checkTokenType applies the Section 6.1 token_type rule: with a DPoP key the
// token is Bearer or DPoP; without one it must be Bearer, since a DPoP-bound
// token could not be presented.
func (w *Wallet) checkTokenType(token *receiverTypes.CredentialIssuanceAccessToken) error {
	if token == nil || strings.TrimSpace(token.Token) == "" {
		return fmt.Errorf("%w: token response did not contain an access token", receiverTypes.ErrInvalidTokenResponse)
	}
	bearer := strings.EqualFold(strings.TrimSpace(token.TokenType), "Bearer")
	switch {
	case bearer:
		return nil
	case isDPoPAccessToken(token) && w.dpop.Key != nil:
		return nil
	case isDPoPAccessToken(token):
		return fmt.Errorf("token endpoint issued a DPoP-bound access token and no DPoP key is configured: %w", ErrDPoPRequired)
	}
	return fmt.Errorf("token response returned token_type %q: %w", token.TokenType, ErrTokenTypeUnsupported)
}

// checkGrantToken validates the access token of a state read back from the
// caller: present, and DPoP-bound under HAIP (HAIP Section 4).
func (w *Wallet) checkGrantToken(token *receiverTypes.CredentialIssuanceAccessToken) error {
	if token == nil || strings.TrimSpace(token.Token) == "" {
		return fmt.Errorf("the state carries no access token: %w", ErrIssuanceStateMismatch)
	}
	if w.profile.IsHAIP() && !isDPoPAccessToken(token) {
		return fmt.Errorf("HAIP requires a DPoP-bound access token, the token has token_type %q: %w", token.TokenType, ErrDPoPRequired)
	}
	return nil
}
