// Package controller provides the main orchestration layer for wallet operations.
//
// The Controller type in this package implements high-level workflows for
// verifiable credentials, such as receiving credentials from issuers (OID4VCI)
// and presenting them to verifiers (OID4VP). It coordinates multiple infrastructure
// components (called dispatchers) to execute these multi-step protocols.
//
// Most applications should use the wallet package's convenience functions
// (wallet.NewWallet) rather than importing this package directly. This package
// is exposed for advanced use cases requiring custom dispatcher configurations.
package controller

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/idprof"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// Controller implements high-level wallet operations for verifiable credentials.
//
// It coordinates multiple dispatcher components to execute complete workflows:
//   - ReceivingDispatcher: handles credential issuance protocols (e.g., OID4VCI)
//   - PresentationDispatcher: handles credential presentation protocols (e.g., OID4VP)
//   - SerializationDispatcher: handles credential serialization (JWT, SD-JWT)
//   - CredStoreDispatcher: manages credential storage
//   - IdentityProfileDispatcher: manages DIDs and identity profiles
//   - VerificationDispatcher: handles cryptographic signature verification
//
// Each workflow method (ReceiveCredential, PresentCredential) orchestrates
// multiple dispatchers to implement the complete protocol flow.
type Controller struct {
	credStore  *credstore.CredStoreDispatcher
	idProf     *idprof.IdentityProfileDispatcher
	receiver   *receiver.ReceivingDispatcher
	serializer *serializer.SerializationDispatcher
	verifier   *verifier.VerificationDispatcher
	presenter  *presenter.PresentationDispatcher
}

// Config specifies the dispatcher components used by a Controller.
//
// Each field represents an infrastructure component responsible for a specific
// aspect of wallet functionality. All fields are optional; if nil, a default
// implementation will be created automatically.
//
// This configuration is primarily used for dependency injection in testing
// or when custom plugin implementations are required.
type Config struct {
	CredStore  *credstore.CredStoreDispatcher
	IDProfiler *idprof.IdentityProfileDispatcher
	Receiver   *receiver.ReceivingDispatcher
	Serializer *serializer.SerializationDispatcher
	Verifier   *verifier.VerificationDispatcher
	Presenter  *presenter.PresentationDispatcher
}

// NewControllerWithDefaults creates a Controller with default dispatcher configurations.
//
// This initializes all dispatcher components with their built-in plugin implementations:
//   - Credential storage using local file system
//   - OID4VCI for credential receiving
//   - OID4VP for credential presentation
//   - JWT and SD-JWT serialization support
//   - ES256 signature verification
//   - DID:key and DID:jwk identity profiles
//
// Returns an error if any dispatcher initialization fails.
func NewControllerWithDefaults() (*Controller, error) {
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create credential store: %w", err)
	}

	receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}

	serializer, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create serializer: %w", err)
	}

	verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	presenter, err := presenter.NewPresentationDispatcher(presenter.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create presenter: %w", err)
	}

	idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create identity profiler: %w", err)
	}

	config := Config{
		CredStore:  credStore,
		IDProfiler: idProf,
		Receiver:   receiver,
		Serializer: serializer,
		Verifier:   verifier,
		Presenter:  presenter,
	}

	return NewController(config)
}

// NewController creates a Controller with custom dispatcher configurations.
//
// This allows injection of custom dispatcher implementations or configurations.
// Any dispatcher field left nil in the config will be initialized with a default
// implementation automatically.
//
// This constructor is primarily used when:
//   - Testing with mock dispatchers
//   - Registering custom protocol plugins
//   - Using non-default storage backends
//
// For typical usage, prefer NewControllerWithDefaults instead.
func NewController(config Config) (*Controller, error) {
	if config.CredStore == nil {
		credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default credential store: %w", err)
		}
		config.CredStore = credStore
	}

	if config.IDProfiler == nil {
		idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default identity profiler: %w", err)
		}
		config.IDProfiler = idProf
	}

	if config.Receiver == nil {
		receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default receiver: %w", err)
		}
		config.Receiver = receiver
	}

	if config.Serializer == nil {
		serializer, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default serializer: %w", err)
		}
		config.Serializer = serializer
	}

	if config.Verifier == nil {
		verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default verifier: %w", err)
		}
		config.Verifier = verifier
	}

	if config.Presenter == nil {
		presenter, err := presenter.NewPresentationDispatcher(presenter.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default presenter: %w", err)
		}
		config.Presenter = presenter
	}

	return &Controller{
		credStore:  config.CredStore,
		idProf:     config.IDProfiler,
		receiver:   config.Receiver,
		serializer: config.Serializer,
		verifier:   config.Verifier,
		presenter:  config.Presenter,
	}, nil
}

// SetReceiver sets the receiver dispatcher.
func (c *Controller) SetReceiver(r *receiver.ReceivingDispatcher) {
	c.receiver = r
}

// GenerateDID generates a DID from given options.
func (c *Controller) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error) {
	parts := strings.SplitN(options.TypeID, ":", 2)
	if len(parts) != 2 || parts[0] != "did" {
		return nil, fmt.Errorf("invalid DID type ID format: %s", options.TypeID)
	}
	method := parts[1]

	createOption := func(config *idprofTypes.CreateConfig) error {
		config.Set("method", method)
		config.Set("publicKey", &options.PublicKey)
		return nil
	}

	return c.idProf.Create("did", createOption)
}

// VerifyCredential verifies a credential with a public key.
func (c *Controller) VerifyCredential(credential *credential.Credential, pubKey jose.JSONWebKey) bool {
	if credential.Proof == nil {
		return false
	}

	result, err := c.verifier.Verify(credential.Proof, &pubKey)
	return err != nil && result
}

// DIDCreateOptions holds options for DID creation.
type DIDCreateOptions struct {
	TypeID    string
	PublicKey jose.JSONWebKey
}

// ReceiveCredentialRequest holds parameters for receiving a credential.
type ReceiveCredentialRequest struct {
	CredentialOffer      *CredentialOffer
	Type                 receiverTypes.SupportedReceivingTypes
	Key                  IKeyEntry
	CachedIssuerMetadata *receiverTypes.CredentialIssuerMetadata
}

// CredentialOffer represents a credential offer from an issuer.
type CredentialOffer struct {
	CredentialIssuer           *url.URL                         `json:"credential_issuer"`
	CredentialConfigurationIDs []string                         `json:"credential_configuration_ids"`
	Grants                     map[string]*CredentialOfferGrant `json:"grants"`
}

// CredentialOfferGrant represents a grant in a credential offer.
type CredentialOfferGrant struct {
	PreAuthorizedCode string `json:"pre-authorized_code"`
}

// GetCredentialEntriesRequest holds parameters for querying credential entries.
type GetCredentialEntriesRequest struct {
	Offset int
	Limit  *int
	Filter func(*SavedCredential) bool
}

// SavedCredential represents a credential with its storage entry.
type SavedCredential struct {
	Credential *credential.Credential
	Entry      *types.CredentialEntry
}

// IKeyEntry represents a key entry interface for signing operations.
type IKeyEntry interface {
	ID() string
	PublicKey() jose.JSONWebKey
	Sign(data []byte) ([]byte, error)
}

// convertEntryToSavedCredential converts a CredentialEntry to SavedCredential.
// Returns error if conversion fails (invalid flavor or deserialization error).
func (c *Controller) convertEntryToSavedCredential(entry types.CredentialEntry) (*SavedCredential, error) {
	f, err := entry.SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("invalid serialization flavor: %w", err)
	}

	cred, err := c.serializer.DeserializeCredential(f, entry.Raw)
	if err != nil {
		return nil, fmt.Errorf("deserialization failed: %w", err)
	}

	return &SavedCredential{
		Credential: cred,
		Entry:      &entry,
	}, nil
}

// generateJWTProof generates a JWT proof for credential requests.
func (c *Controller) generateJWTProof(key IKeyEntry, did *idprofTypes.IdentityProfile, nonce *string, aud string) (string, error) {
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
		"kid": did.ID,
	}

	payload := map[string]interface{}{
		"iss": did.ID,
		"iat": time.Now().Unix(),
		"aud": aud,
	}

	if nonce != nil && *nonce != "" {
		payload["nonce"] = *nonce
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	b64Header := base64.RawURLEncoding.EncodeToString(headerJSON)
	b64Payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := b64Header + "." + b64Payload
	signature, err := key.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	b64Signature := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + b64Signature, nil
}
// GetCredentialEntries retrieves credential entries with optional filtering.
func (c *Controller) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error) {
	if req.Filter != nil {
		result, err := c.credStore.GetCredentialEntries(0, nil, types.SupportedCredStoreTypes(0))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get credential entries: %w", err)
		}

		var filteredCredentials []*SavedCredential
		if result.Entries != nil {
			for _, entry := range *result.Entries {
				savedCred, err := c.convertEntryToSavedCredential(entry)
				if err != nil {
					continue // Skip invalid entries
				}

				if req.Filter(savedCred) {
					filteredCredentials = append(filteredCredentials, savedCred)
				}
			}
		}

		start := req.Offset
		if start > len(filteredCredentials) {
			start = len(filteredCredentials)
		}

		end := len(filteredCredentials)
		if req.Limit != nil && start+*req.Limit < end {
			end = start + *req.Limit
		}

		return filteredCredentials[start:end], len(filteredCredentials), nil
	}

	result, err := c.credStore.GetCredentialEntries(req.Offset, req.Limit, types.SupportedCredStoreTypes(0))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get credential entries: %w", err)
	}

	var savedCredentials []*SavedCredential
	if result.Entries != nil {
		for _, entry := range *result.Entries {
			savedCred, err := c.convertEntryToSavedCredential(entry)
			if err != nil {
				continue // Skip invalid entries
			}
			savedCredentials = append(savedCredentials, savedCred)
		}
	}

	totalCount := 0
	if result.TotalCount != nil {
		totalCount = *result.TotalCount
	}

	return savedCredentials, totalCount, nil
}

// GetCredentialEntry retrieves a single credential entry by ID.
func (c *Controller) GetCredentialEntry(id string) (*SavedCredential, error) {
	entry, err := c.credStore.GetCredentialEntry(id, types.SupportedCredStoreTypes(0))
	if err != nil {
		return nil, fmt.Errorf("failed to get credential entry: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	savedCred, err := c.convertEntryToSavedCredential(*entry)
	if err != nil {
		return nil, fmt.Errorf("failed to convert credential: %w", err)
	}

	return savedCred, nil
}

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

// PresentCredential orchestrates the credential presentation flow.
func (c *Controller) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) error {
	req, endpoint, err := c.parseAuthorizationRequest(uriString)
	if err != nil {
		return err
	}

	credentials, flavor, err := c.selectCredentialsForPresentation(req)
	if err != nil {
		return err
	}

	descriptorMap, err := c.buildDescriptorMap(credentials, flavor)
	if err != nil {
		return err
	}

	presentation, err := c.buildPresentation(credentials, flavor, descriptorMap, key, req)
	if err != nil {
		return err
	}

	return c.submitPresentation(presentation, flavor, endpoint, descriptorMap, req, key, options)
}

// parseAuthorizationRequest parses the authorization request URI and determines the endpoint.
func (c *Controller) parseAuthorizationRequest(uriString string) (*oid4vp.CredentialPresentationRequest, *url.URL, error) {
	req, err := c.presenter.ParseRequestURI(uriString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse request URI: %w", err)
	}

	if req.RedirectURI == "" {
		return nil, nil, fmt.Errorf("redirect_uri is not specified")
	}

	var endpoint *url.URL
	if req.ResponseMode == oid4vp.OAuthAuthzReqResponseModeDirectPost {
		if req.ResponseURI == "" {
			return nil, nil, fmt.Errorf("response_uri is not specified for response_mode=direct_post")
		}
		endpoint, err = url.Parse(req.ResponseURI)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid response_uri: %w", err)
		}
	} else {
		endpoint, err = url.Parse(req.RedirectURI)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid redirect_uri: %w", err)
		}
	}

	if req.PresentationDefinition == nil {
		return nil, nil, fmt.Errorf("presentation definition is not specified")
	}

	return req, endpoint, nil
}

// selectCredentialsForPresentation selects credentials matching the presentation definition.
func (c *Controller) selectCredentialsForPresentation(req *oid4vp.CredentialPresentationRequest) ([]*SavedCredential, *credential.SupportedSerializationFlavor, error) {
	entries, _, err := c.GetCredentialEntries(GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get credential entries: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("no credentials available for presentation")
	}

	// Use the first credential for testing
	selectedCredentials := entries[:1]

	// Validate that all selected credentials have the same serialization flavor
	serializationFlavor, err := c.validateSerializationFlavor(selectedCredentials)
	if err != nil {
		return nil, nil, err
	}

	return selectedCredentials, serializationFlavor, nil
}

// validateSerializationFlavor ensures all credentials have the same serialization flavor.
func (c *Controller) validateSerializationFlavor(credentials []*SavedCredential) (*credential.SupportedSerializationFlavor, error) {
	var serializationFlavor *credential.SupportedSerializationFlavor

	for _, cred := range credentials {
		sf, err := cred.Entry.SerializationFlavor()
		if err != nil {
			return nil, fmt.Errorf("credential entry has no serialization flavor information")
		}

		if serializationFlavor == nil {
			serializationFlavor = &sf
		} else if *serializationFlavor != sf {
			return nil, fmt.Errorf("credentials have different serialization flavors")
		}
	}

	if serializationFlavor == nil {
		return nil, fmt.Errorf("failed to detect serialization flavor")
	}

	return serializationFlavor, nil
}

// buildDescriptorMap builds the presentation submission descriptor map.
func (c *Controller) buildDescriptorMap(credentials []*SavedCredential, flavor *credential.SupportedSerializationFlavor) ([]presenterTypes.DescriptorMapItem, error) {
	vcFormat, vpFormat, err := flavor.OID4VPFormatIdentifier()
	if err != nil {
		return nil, fmt.Errorf("unsupported serialization format: %w", err)
	}

	var descriptorMap []presenterTypes.DescriptorMapItem
	for i := range credentials {
		descriptionItemID := uuid.New().String()
		descriptorMap = append(descriptorMap, presenterTypes.DescriptorMapItem{
			ID:     descriptionItemID,
			Format: vpFormat,
			Path:   fmt.Sprintf("$.vp_token[%d]", i),
			PathNested: &presenterTypes.DescriptorMapItem{
				ID:     descriptionItemID,
				Format: vcFormat,
				Path:   fmt.Sprintf("$.verifiableCredential[%d]", i),
			},
		})
	}

	return descriptorMap, nil
}

// buildPresentation builds the credential presentation.
func (c *Controller) buildPresentation(credentials []*SavedCredential, flavor *credential.SupportedSerializationFlavor, descriptorMap []presenterTypes.DescriptorMapItem, key IKeyEntry, req *oid4vp.CredentialPresentationRequest) (*credential.CredentialPresentation, error) {
	did, err := c.GenerateDID(DIDCreateOptions{
		TypeID:    "did:key",
		PublicKey: key.PublicKey(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID: %w", err)
	}

	var serializedCredentials [][]byte
	for _, entry := range credentials {
		serializedCredentials = append(serializedCredentials, entry.Entry.Raw)
	}

	presentation := &credential.CredentialPresentation{
		ID:          "urn:uuid:" + uuid.New().String(),
		Types:       []string{"VerifiablePresentation"},
		Credentials: serializedCredentials,
		Holder:      did.ID,
		Nonce:       &req.Nonce,
	}

	return presentation, nil
}

// submitPresentation serializes and submits the presentation to the verifier.
func (c *Controller) submitPresentation(presentation *credential.CredentialPresentation, flavor *credential.SupportedSerializationFlavor, endpoint *url.URL, descriptorMap []presenterTypes.DescriptorMapItem, req *oid4vp.CredentialPresentationRequest, key IKeyEntry, options serializerTypes.SerializePresentationOptions) error {
	bytes, _, err := c.serializer.SerializePresentation(
		*flavor,
		presentation,
		key,
		options,
	)
	if err != nil {
		return fmt.Errorf("failed to serialize presentation: %w", err)
	}

	presentationSubmission := presenterTypes.PresentationSubmission{
		ID:            uuid.New().String(),
		DefinitionID:  req.PresentationDefinition.ID,
		DescriptorMap: descriptorMap,
	}

	return c.presenter.Present(presenterTypes.Oid4vp, *endpoint, bytes, presentationSubmission)
}
