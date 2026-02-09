package wallet

import (
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credstore/types"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// FetchCredentialIssuerMetadata fetches credential issuer metadata from the given endpoint.
func (c *Controller) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error) {
	uriField, err := common.ParseURIField(endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI field: %w", err)
	}

	return c.receiver.FetchIssuerMetadata(*uriField, receivingType)
}

// ReceiveCredential orchestrates the credential receiving flow.
func (c *Controller) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error) {
	preAuthCode, err := c.validateCredentialOffer(req.CredentialOffer)
	if err != nil {
		return nil, err
	}

	issuerMetadata, authMetadata, err := c.fetchCredentialMetadata(req)
	if err != nil {
		return nil, err
	}

	accessToken, err := c.obtainAccessToken(req.Type, authMetadata, preAuthCode)
	if err != nil {
		return nil, err
	}

	credentialJWT, err := c.requestCredential(req, issuerMetadata, accessToken)
	if err != nil {
		return nil, err
	}

	return c.storeAndParseCredential(credentialJWT)
}

// validateCredentialOffer validates the credential offer and extracts pre-authorization code.
func (c *Controller) validateCredentialOffer(offer *CredentialOffer) (string, error) {
	if offer == nil {
		return "", fmt.Errorf("credential offer is required")
	}

	preAuthGrant := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	if preAuthGrant == nil {
		return "", fmt.Errorf("pre-authorization code is not included in the offer")
	}

	if len(offer.CredentialConfigurationIDs) == 0 {
		return "", fmt.Errorf("credential configuration IDs are empty")
	}

	preAuthCode := preAuthGrant.PreAuthorizedCode
	if preAuthCode == "" {
		return "", fmt.Errorf("pre-authorization code is not included in the offer")
	}

	return preAuthCode, nil
}

// fetchCredentialMetadata fetches issuer and authorization server metadata.
func (c *Controller) fetchCredentialMetadata(req ReceiveCredentialRequest) (*receiverTypes.CredentialIssuerMetadata, *receiverTypes.AuthorizationServerMetadata, error) {
	var issuerMetadata *receiverTypes.CredentialIssuerMetadata
	var err error

	if req.CachedIssuerMetadata != nil {
		issuerMetadata = req.CachedIssuerMetadata
	} else {
		issuerMetadata, err = c.FetchCredentialIssuerMetadata(req.CredentialOffer.CredentialIssuer, req.Type)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
		}
	}

	if len(issuerMetadata.AuthorizationServers) == 0 {
		return nil, nil, fmt.Errorf("no authorization servers found in issuer metadata")
	}

	authMetadata, err := c.receiver.FetchAuthorizationServerMetadata(issuerMetadata.AuthorizationServers[0], req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}

	if authMetadata == nil {
		return nil, nil, fmt.Errorf("authorization server metadata is nil")
	}

	if authMetadata.PreAuthorizedGrantAnonymousAccessSupported == nil || !*authMetadata.PreAuthorizedGrantAnonymousAccessSupported {
		return nil, nil, fmt.Errorf(
			"anonymous access support is missing on authorization server that the credential issuer relies on; PreAuthorizedGrantAnonymousAccessSupported: %v",
			authMetadata.PreAuthorizedGrantAnonymousAccessSupported,
		)
	}

	if authMetadata.TokenEndpoint == nil {
		return nil, nil, fmt.Errorf("token endpoint is missing on authorization server")
	}

	return issuerMetadata, authMetadata, nil
}

// obtainAccessToken obtains an access token using pre-authorization code.
func (c *Controller) obtainAccessToken(receivingType receiverTypes.SupportedReceivingTypes, authMetadata *receiverTypes.AuthorizationServerMetadata, preAuthCode string) (*receiverTypes.CredentialIssuanceAccessToken, error) {
	accessToken, err := c.receiver.FetchAccessToken(receivingType, *authMetadata.TokenEndpoint, preAuthCode)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch access token: %w", err)
	}
	return accessToken, nil
}

// requestCredential requests the credential from the issuer with JWT proof.
func (c *Controller) requestCredential(req ReceiveCredentialRequest, issuerMetadata *receiverTypes.CredentialIssuerMetadata, accessToken *receiverTypes.CredentialIssuanceAccessToken) (*string, error) {
	did, err := c.GenerateDID(DIDCreateOptions{
		TypeID:    "did:key",
		PublicKey: req.Key.PublicKey(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID: %w", err)
	}

	proof, err := c.generateJWTProof(req.Key, did, accessToken.CNonce, issuerMetadata.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT proof: %w", err)
	}

	credentialJWT, err := c.receiver.ReceiveCredential(
		req.Type,
		issuerMetadata.CredentialEndpoint,
		"jwt_vc_json",
		*accessToken,
		&receiverTypes.CredentialDefinition{
			Type: append(req.CredentialOffer.CredentialConfigurationIDs, "VerifiableCredential"),
		},
		&proof,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to receive credential: %w", err)
	}

	return credentialJWT, nil
}

// storeAndParseCredential stores the credential and parses it for return.
func (c *Controller) storeAndParseCredential(credentialJWT *string) (*SavedCredential, error) {
	credentialEntry := types.CredentialEntry{
		Id:         uuid.New().String(),
		ReceivedAt: time.Now(),
		Raw:        []byte(*credentialJWT),
		MimeType:   "application/vc+jwt",
	}

	if err := c.credStore.SaveCredentialEntry(credentialEntry, types.SupportedCredStoreTypes(0)); err != nil {
		return nil, fmt.Errorf("failed to save credential entry: %w", err)
	}

	f, err := credentialEntry.SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	credential, err := c.serializer.DeserializeCredential(f, credentialEntry.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return &SavedCredential{
		Credential: credential,
		Entry:      &credentialEntry,
	}, nil
}
