package wallet

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/env"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// FetchCredentialIssuerMetadata fetches credential issuer metadata from the given endpoint.
func (w *Wallet) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error) {
	if endpoint == nil {
		return nil, invalidArgument("issuer metadata endpoint is required")
	}
	uriField, err := common.ParseURIField(endpoint.String())
	if err != nil {
		return nil, keepMessage(ErrInvalidArgument, fmt.Errorf("failed to parse URI field: %w", err))
	}
	metadata, err := w.receiver.FetchIssuerMetadata(*uriField, receivingType)
	return metadata, classifyKeepingMessage(err)
}

// ReceiveCredential runs a Pre-Authorized Code issuance through the receiver
// plugin's Receiver methods and stores the credential. Without
// Config.CredentialAcceptance the credential is parsed but its issuer is not
// authenticated. It returns ErrProfileForbidsDraft under HAIP; new code uses
// AuthorizePreAuthorizedIssuance and RequestCredential.
func (w *Wallet) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error) {
	saved, err := w.receiveCredential(req)
	return saved, classifyKeepingMessage(err)
}

func (w *Wallet) receiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error) {
	if w.profile.IsHAIP() {
		return nil, ErrProfileForbidsDraft
	}
	preAuthCode, err := w.validateCredentialOffer(req.CredentialOffer)
	if err != nil {
		return nil, keepMessage(ErrInvalidArgument, err)
	}

	issuerMetadata, authMetadata, err := w.fetchCredentialMetadata(req)
	if err != nil {
		return nil, err
	}

	credentialConfigurationID, credentialConfiguration, serializationFlavor, err := w.selectCredentialConfiguration(req, issuerMetadata)
	if err != nil {
		return nil, err
	}

	accessToken, err := w.obtainAccessToken(req.Type, authMetadata, preAuthCode, req.TxCode)

	if err != nil {
		return nil, err
	}

	credentialJWT, err := w.requestCredential(req, issuerMetadata, accessToken, credentialConfigurationID, credentialConfiguration)
	if err != nil {
		return nil, err
	}

	var holderKey *jose.JSONWebKey
	if req.Key != nil {
		publicKey := req.Key.PublicKey()
		holderKey = &publicKey
	}

	return w.storeAndParseCredential(context.Background(), credentialJWT, serializationFlavor, holderKey, false)
}

// validateCredentialOffer validates the credential offer and extracts pre-authorization code.
func (w *Wallet) validateCredentialOffer(offer *CredentialOffer) (string, error) {
	if offer == nil {
		return "", fmt.Errorf("credential offer is required")
	}

	if err := validateCredentialIssuerIdentifier(offer.CredentialIssuer, env.IsHTTPAllowed()); err != nil {
		return "", err
	}

	preAuthGrant := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	if preAuthGrant == nil {
		return "", fmt.Errorf("pre-authorization code is not included in the offer")
	}

	if len(offer.CredentialConfigurationIDs) == 0 {
		return "", fmt.Errorf("credential configuration IDs are empty")
	}
	seen := make(map[string]struct{}, len(offer.CredentialConfigurationIDs))
	for _, id := range offer.CredentialConfigurationIDs {
		if _, dup := seen[id]; dup {
			return "", fmt.Errorf("credential configuration IDs must be unique: %q is duplicated", id)
		}
		seen[id] = struct{}{}
	}

	preAuthCode := preAuthGrant.PreAuthorizedCode
	if preAuthCode == "" {
		return "", fmt.Errorf("pre-authorization code is not included in the offer")
	}

	return preAuthCode, nil
}
func (w *Wallet) selectCredentialConfiguration(
	req ReceiveCredentialRequest,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
) (string, *receiverTypes.CredentialConfiguration, credential.SupportedSerializationFlavor, error) {
	if req.CredentialOffer == nil || len(req.CredentialOffer.CredentialConfigurationIDs) == 0 {
		return "", nil, "", fmt.Errorf("credential configuration IDs are empty")
	}

	defaultConfigurationID := req.CredentialOffer.CredentialConfigurationIDs[0]
	defaultFlavor := credential.JwtVc

	if req.RequestedFormat != "" {
		if req.RequestedFormat != credential.JwtVc && req.RequestedFormat != credential.SDJwtVC {
			return "", nil, "", fmt.Errorf("unsupported requested serialization format: %s", req.RequestedFormat)
		}

		if issuerMetadata == nil || issuerMetadata.CredentialConfigurationSupported == nil {
			return "", nil, "", fmt.Errorf("credential configuration metadata is required when requested format is specified")
		}

		for _, configID := range req.CredentialOffer.CredentialConfigurationIDs {
			config, ok := issuerMetadata.CredentialConfigurationSupported[configID]
			if !ok {
				continue
			}

			flavor, err := receiverOid4vci.OID4VCICredentialFormatToSerializationFlavor(config.Format)
			if err != nil {
				continue
			}
			if flavor == req.RequestedFormat {
				configCopy := config
				return configID, &configCopy, flavor, nil
			}
		}

		return "", nil, "", fmt.Errorf("no credential configuration matches requested format: %s", req.RequestedFormat)
	}

	if issuerMetadata == nil || issuerMetadata.CredentialConfigurationSupported == nil {
		return defaultConfigurationID, nil, defaultFlavor, nil
	}

	config, ok := issuerMetadata.CredentialConfigurationSupported[defaultConfigurationID]
	if !ok {
		return defaultConfigurationID, nil, defaultFlavor, nil
	}

	configCopy := config
	flavor, err := receiverOid4vci.OID4VCICredentialFormatToSerializationFlavor(config.Format)
	if err != nil {
		return "", nil, "", fmt.Errorf("unsupported credential format for configuration %q: %w", defaultConfigurationID, err)
	}

	return defaultConfigurationID, &configCopy, flavor, nil
}
func shouldAttachCredentialRequestProof(req ReceiveCredentialRequest, credentialConfiguration *receiverTypes.CredentialConfiguration) bool {
	if credentialConfiguration != nil {
		if credentialConfiguration.ProofTypesSupported != nil {
			return true
		}
		if credentialConfiguration.CryptographicBindingMethodsSupported != nil &&
			len(*credentialConfiguration.CryptographicBindingMethodsSupported) > 0 {
			return true
		}
	}

	// Keep backward-compatible behavior for existing callers that do not specify format.
	return req.RequestedFormat == ""
}
func ensureJWTProofSupported(credentialConfiguration *receiverTypes.CredentialConfiguration) error {
	if credentialConfiguration == nil || credentialConfiguration.ProofTypesSupported == nil {
		return nil
	}

	proofTypes := *credentialConfiguration.ProofTypesSupported
	if len(proofTypes) == 0 {
		return fmt.Errorf("proof_types_supported must not be empty")
	}

	for proofType := range proofTypes {
		if strings.EqualFold(strings.TrimSpace(proofType), "jwt") {
			return nil
		}
	}

	return fmt.Errorf("unsupported proof type: jwt proof is required")
}
func (w *Wallet) validateCredentialConfigurationIDs(offer *CredentialOffer, issuerMetadata *receiverTypes.CredentialIssuerMetadata) error {
	return validateOfferedConfigurations(offer, issuerMetadata)
}

// fetchCredentialMetadata fetches issuer and authorization server metadata.
func (w *Wallet) fetchCredentialMetadata(req ReceiveCredentialRequest) (*receiverTypes.CredentialIssuerMetadata, *receiverTypes.AuthorizationServerMetadata, error) {
	var issuerMetadata *receiverTypes.CredentialIssuerMetadata
	var err error

	if req.CachedIssuerMetadata != nil {
		issuerMetadata = req.CachedIssuerMetadata
	} else {
		issuerMetadata, err = w.FetchCredentialIssuerMetadata(req.CredentialOffer.CredentialIssuer, req.Type)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
		}
	}

	if err := w.validateCredentialConfigurationIDs(req.CredentialOffer, issuerMetadata); err != nil {
		return nil, nil, err
	}

	authorizationServers := issuerMetadata.AuthorizationServers
	if authorizationServers == nil {
		issuerAuthorizationServer, err := common.ParseURIField(req.CredentialOffer.CredentialIssuer.String())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to use credential issuer as authorization server: %w", err)
		}
		authorizationServers = []common.URIField{*issuerAuthorizationServer}
	} else if len(authorizationServers) == 0 {
		return nil, nil, fmt.Errorf("authorization_servers must not be an empty array")
	}

	authMetadata, err := w.receiver.FetchAuthorizationServerMetadata(authorizationServers[0], req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}

	if authMetadata == nil {
		return nil, nil, fmt.Errorf("authorization server metadata is nil")
	}

	if authMetadata.TokenEndpoint == nil {
		return nil, nil, fmt.Errorf("token endpoint is missing on authorization server")
	}

	if _, ok := resolveClientAuthMethod(w.clientAuth, authMetadata); !ok {
		return nil, nil, errNoUsableClientAuthMethod
	}

	return issuerMetadata, authMetadata, nil
}

// obtainAccessToken obtains an access token using pre-authorization code.
func (w *Wallet) obtainAccessToken(receivingType receiverTypes.SupportedReceivingTypes, authMetadata *receiverTypes.AuthorizationServerMetadata, preAuthCode string, txCode string) (*receiverTypes.CredentialIssuanceAccessToken, error) {
	if authMetadata == nil || authMetadata.TokenEndpoint == nil {
		return nil, fmt.Errorf("token endpoint is missing on authorization server")
	}

	tokenEndpoint := *authMetadata.TokenEndpoint
	tokenEndpointURL := tokenEndpoint.String()
	clientAssertionAudience := resolveClientAssertionAudience(w.clientAuth, authMetadata, tokenEndpointURL)

	authMethod, ok := resolveClientAuthMethod(w.clientAuth, authMetadata)
	if !ok {
		return nil, errNoUsableClientAuthMethod
	}

	fetchAccessToken := func(dpopNonce *string) (*receiverTypes.CredentialIssuanceAccessToken, error) {
		var tokenReqOptions []receiverTypes.TokenRequestOption
		switch authMethod {
		case receiverTypes.PrivateKeyJwt:
			assertion, err := w.generateClientAssertion(
				w.clientAuth.Key,
				w.clientAuth.ClientID,
				clientAssertionAudience,
				w.clientAuth.signatureAlgorithm(),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to generate client assertion: %w", err)
			}
			tokenReqOptions = append(tokenReqOptions, receiverTypes.WithClientAssertion(w.clientAuth.ClientID, assertion))

		case receiverTypes.None:
			// client_id is OPTIONAL for the pre-authorized code grant, but an
			// authorization server that never advertised
			// pre-authorized_grant_anonymous_access_supported has told us nothing
			// about whether it serves anonymous clients. Naming the client when
			// one is configured is what lets such a server accept the request.
			if strings.TrimSpace(w.clientAuth.ClientID) != "" {
				tokenReqOptions = append(tokenReqOptions, receiverTypes.WithClientID(w.clientAuth.ClientID))
			}
		}
		if w.dpop.Enabled {
			proof, err := w.generateDPoPProof(
				w.dpop.Key,
				http.MethodPost,
				tokenEndpointURL,
				"",
				dpopNonce,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to generate DPoP proof: %w", err)
			}
			tokenReqOptions = append(tokenReqOptions, receiverTypes.WithDPoPProof(proof))
		}

		return w.receiver.FetchAccessToken(receivingType, tokenEndpoint, preAuthCode, txCode, tokenReqOptions...)
	}

	accessToken, err := fetchAccessToken(nil)
	if err != nil && w.dpop.Enabled {
		if dpopNonce, ok := receiverTypes.DPoPNonceFromError(err); ok && dpopNonce != "" {
			accessToken, err = fetchAccessToken(&dpopNonce)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch access token: %w", err)
	}
	return accessToken, nil
}
func accessTokenNonce(accessToken *receiverTypes.CredentialIssuanceAccessToken) *string {
	if accessToken == nil || accessToken.CNonce == nil || *accessToken.CNonce == "" {
		return nil
	}
	return accessToken.CNonce
}
func accessTokenCredentialIdentifier(accessToken *receiverTypes.CredentialIssuanceAccessToken) *string {
	if accessToken == nil {
		return nil
	}

	for _, authorizationDetail := range accessToken.AuthorizationDetails {
		if authorizationDetail.Type != receiverTypes.AuthorizationDetailTypeOpenIDCredential {
			continue
		}
		for _, identifier := range authorizationDetail.CredentialIdentifiers {
			if identifier == "" {
				continue
			}
			identifierCopy := identifier
			return &identifierCopy
		}
	}

	return nil
}

// fetchCredentialNonce retrieves nonce used for proof generation from nonce endpoint,
// and falls back to c_nonce in the access token when nonce endpoint is not available.
func (w *Wallet) fetchCredentialNonce(
	receivingType receiverTypes.SupportedReceivingTypes,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	accessToken *receiverTypes.CredentialIssuanceAccessToken,
) (*string, error) {
	fallbackNonce := accessTokenNonce(accessToken)

	if issuerMetadata.NonceEndpoint == nil {
		return fallbackNonce, nil
	}

	nonce, err := w.receiver.FetchNonce(receivingType, *issuerMetadata.NonceEndpoint)
	if err != nil {
		if fallbackNonce != nil {
			return fallbackNonce, nil
		}
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}

	if nonce != nil && *nonce != "" {
		return nonce, nil
	}

	if fallbackNonce != nil {
		return fallbackNonce, nil
	}

	return nil, fmt.Errorf("nonce response does not contain c_nonce or nonce")
}

// requestCredential requests the credential from the issuer with JWT proof.
func (w *Wallet) requestCredential(
	req ReceiveCredentialRequest,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	accessToken *receiverTypes.CredentialIssuanceAccessToken,
	credentialConfigurationID string,
	credentialConfiguration *receiverTypes.CredentialConfiguration,
) (*string, error) {
	credentialIdentifier := accessTokenCredentialIdentifier(accessToken)
	if credentialIdentifier != nil {
		credentialConfigurationID = ""
	}

	var proof *string
	attachProof := shouldAttachCredentialRequestProof(req, credentialConfiguration)
	if attachProof {
		if req.Key == nil {
			return nil, fmt.Errorf("key entry is required")
		}

		if err := ensureJWTProofSupported(credentialConfiguration); err != nil {
			return nil, err
		}

		proofBindingMethod := resolveCredentialRequestProofBindingMethod(credentialConfiguration)

		var did *idprofTypes.IdentityProfile
		if proofBindingMethod == credentialRequestProofBindingMethodKID {
			didGenerated, err := w.GenerateDID(DIDCreateOptions{
				TypeID:    "did:key",
				PublicKey: req.Key.PublicKey(),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to generate DID: %w", err)
			}
			did = didGenerated
		}

		nonce, err := w.fetchCredentialNonce(req.Type, issuerMetadata, accessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch nonce for credential proof: %w", err)
		}

		proofValue, err := w.generateJWTProof(
			req.Key,
			did,
			nonce,
			issuerMetadata.CredentialIssuer,
			nil,
			proofBindingMethod,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT proof: %w", err)
		}

		proof = &proofValue
	}

	var credentialDefinition *receiverTypes.CredentialDefinition
	if credentialConfiguration != nil {
		credentialDefinition = credentialConfiguration.CredentialDefinition
	}

	receiveCredential := func(dpopNonce *string) (*string, error) {
		var options *receiverTypes.CredentialRequestOptions
		if strings.EqualFold(accessToken.TokenType, "DPoP") {
			if w.dpop.Key == nil {
				return nil, fmt.Errorf("dpop key is required for DPoP access token")
			}
			dpopProof, err := w.generateDPoPProof(w.dpop.Key, http.MethodPost, issuerMetadata.CredentialEndpoint.String(), accessToken.Token, dpopNonce)
			if err != nil {
				return nil, fmt.Errorf("failed to generate DPoP proof: %w", err)
			}
			options = &receiverTypes.CredentialRequestOptions{
				DPoPProofJWT: &dpopProof,
			}
		}

		return w.receiver.ReceiveCredential(
			req.Type,
			issuerMetadata.CredentialEndpoint,
			credentialConfigurationID,
			credentialIdentifier,
			*accessToken,
			credentialDefinition,
			proof,
			options,
		)
	}

	credentialJWT, err := receiveCredential(nil)
	if err != nil && strings.EqualFold(accessToken.TokenType, "DPoP") {
		// RFC9449 section 9 binds the retry to the resource server's challenge.
		// The VCI c_nonce endpoint is a different protocol and cannot replace it.
		if dpopNonce, ok := receiverTypes.DPoPNonceFromError(err); ok && dpopNonce != "" {
			credentialJWT, err = receiveCredential(&dpopNonce)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to receive credential: %w", err)
	}

	return credentialJWT, nil
}

// storeAndParseCredential verifies the credential for acceptance, stores it and
// parses it for return. Nothing is stored when verification fails.
// requirePolicy makes Config.CredentialAcceptance mandatory for this call.
func (w *Wallet) storeAndParseCredential(ctx context.Context, credentialJWT *string, serializationFlavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey, requirePolicy bool) (*SavedCredential, error) {
	if serializationFlavor == "" {
		serializationFlavor = credential.JwtVc
	}

	parsedCredential, verification, verificationErr := w.verifyCredentialForAcceptanceContext(ctx, []byte(*credentialJWT), serializationFlavor, holderKey, requirePolicy)
	if verificationErr != nil {
		return nil, fmt.Errorf("failed to verify credential: %w", verificationErr)
	}

	credentialEntry := types.CredentialEntry{
		Id:         uuid.New().String(),
		ReceivedAt: time.Now(),
		Raw:        []byte(*credentialJWT),
		MimeType:   string(serializationFlavor),
	}

	if w.credStore == nil {
		return nil, ErrNoCredentialStore
	}
	if err := w.credStore.SaveCredentialEntry(credentialEntry, types.SupportedCredStoreTypes(0)); err != nil {
		return nil, fmt.Errorf("failed to save credential entry: %w", err)
	}

	return &SavedCredential{
		Credential:   parsedCredential,
		Entry:        &credentialEntry,
		Verification: verification,
	}, nil
}
