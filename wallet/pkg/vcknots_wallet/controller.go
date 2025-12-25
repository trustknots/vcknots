package vcknots_wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/internal/common"
	"github.com/trustknots/vcknots/wallet/internal/credential"
	"github.com/trustknots/vcknots/wallet/internal/credstore"
	"github.com/trustknots/vcknots/wallet/internal/credstore/types"
	"github.com/trustknots/vcknots/wallet/internal/idprof"
	idprofTypes "github.com/trustknots/vcknots/wallet/internal/idprof/types"
	"github.com/trustknots/vcknots/wallet/internal/presenter"
	"github.com/trustknots/vcknots/wallet/internal/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/internal/presenter/types"
	"github.com/trustknots/vcknots/wallet/internal/receiver"
	receiverTypes "github.com/trustknots/vcknots/wallet/internal/receiver/types"
	"github.com/trustknots/vcknots/wallet/internal/serializer"
	"github.com/trustknots/vcknots/wallet/internal/verifier"
)

type Controller struct {
	credStore  *credstore.CredStoreDispatcher
	idProf     *idprof.IdentityProfileDispatcher
	receiver   *receiver.ReceivingDispatcher
	serializer *serializer.SerializationDispatcher
	verifier   *verifier.VerificationDispatcher
	presenter  *presenter.PresentationDispatcher
}

type ControllerConfig struct {
	CredStore  *credstore.CredStoreDispatcher
	IDProfiler *idprof.IdentityProfileDispatcher
	Receiver   *receiver.ReceivingDispatcher
	Serializer *serializer.SerializationDispatcher
	Verifier   *verifier.VerificationDispatcher
	Presenter  *presenter.PresentationDispatcher
}

// NewControllerWithDefaults creates a new controller with default plugin configurations
func NewControllerWithDefaults() (*Controller, error) {
	// Create credential store with default config
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create credential store: %w", err)
	}

	// Create receiver with default config
	receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}

	serializer, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create serializer: %w", err)
	}

	// Create verifier with default config
	verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	// Create presenter with default config
	presenter, err := presenter.NewPresentationDispatcher(presenter.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create presenter: %w", err)
	}

	// Create identity profiler dispatcher with default config
	idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create identity profiler: %w", err)
	}

	config := ControllerConfig{
		CredStore:  credStore,
		IDProfiler: idProf,
		Receiver:   receiver,
		Serializer: serializer,
		Verifier:   verifier,
		Presenter:  presenter,
	}

	return NewController(config)
}

// NewController creates a new controller with provided dependencies
func NewController(config ControllerConfig) (*Controller, error) {
	// If config has nil components, use defaults
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

func (c *Controller) SetReceiver(r *receiver.ReceivingDispatcher) {
	c.receiver = r
}

type DIDCreateOptions struct {
	TypeID    string
	PublicKey jose.JSONWebKey
}

type ReceiveCredentialRequest struct {
	CredentialOffer      *CredentialOffer
	Type                 receiverTypes.SupportedReceivingTypes
	Key                  IKeyEntry
	CachedIssuerMetadata *receiverTypes.CredentialIssuerMetadata
}

type CredentialOffer struct {
	CredentialIssuer           *url.URL                         `json:"credential_issuer"`
	CredentialConfigurationIDs []string                         `json:"credential_configuration_ids"`
	Grants                     map[string]*CredentialOfferGrant `json:"grants"`
}

func (c *CredentialOffer) MarshalJSON() ([]byte, error) {
	type Alias CredentialOffer
	return json.Marshal(&struct {
		CredentialIssuer string `json:"credential_issuer"`
		*Alias
	}{
		CredentialIssuer: c.CredentialIssuer.String(),
		Alias:            (*Alias)(c),
	})
}

func (c *CredentialOffer) UnmarshalJSON(data []byte) error {
	type Alias CredentialOffer
	aux := &struct {
		CredentialIssuer string `json:"credential_issuer"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	parsedURL, err := url.Parse(aux.CredentialIssuer)
	if err != nil {
		return fmt.Errorf("invalid credential_issuer URL: %w", err)
	}
	c.CredentialIssuer = parsedURL
	return nil
}

type CredentialOfferGrant struct {
	PreAuthorizedCode string `json:"pre-authorized_code"`
}

type GetCredentialEntriesRequest struct {
	Offset int
	Limit  *int
	Filter func(*SavedCredential) bool
}

type SavedCredential struct {
	Credential *credential.Credential
	Entry      *types.CredentialEntry
}

type IKeyEntry interface {
	ID() string
	PublicKey() jose.JSONWebKey
	Sign(data []byte) ([]byte, error)
}

func (c *Controller) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error) {
	// Extract method from did:method format (e.g., "did:key" -> "key")
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

func (c *Controller) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error) {
	uriField, err := common.ParseURIField(endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI field: %w", err)
	}

	return c.receiver.FetchIssuerMetadata(*uriField, receivingType)
}

func (c *Controller) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error) {
	if req.CredentialOffer == nil {
		return nil, fmt.Errorf("credential offer is required")
	}

	preAuthGrant := req.CredentialOffer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	if preAuthGrant == nil {
		return nil, fmt.Errorf("pre-authorization code is not included in the offer")
	}

	if len(req.CredentialOffer.CredentialConfigurationIDs) == 0 {
		return nil, fmt.Errorf("credential configuration IDs are empty")
	}

	preAuthCode := preAuthGrant.PreAuthorizedCode
	if preAuthCode == "" {
		return nil, fmt.Errorf("pre-authorization code is not included in the offer")
	}

	var issuerMetadata *receiverTypes.CredentialIssuerMetadata
	var err error
	if req.CachedIssuerMetadata != nil {
		issuerMetadata = req.CachedIssuerMetadata
	} else {
		issuerMetadata, err = c.FetchCredentialIssuerMetadata(req.CredentialOffer.CredentialIssuer, req.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
		}
	}

	if len(issuerMetadata.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("no authorization servers found in issuer metadata")
	}

	authMetadata, err := c.receiver.FetchAuthorizationServerMetadata(issuerMetadata.AuthorizationServers[0], req.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}

	if authMetadata == nil {
		return nil, fmt.Errorf("authorization server metadata is nil")
	}

	if authMetadata.PreAuthorizedGrantAnonymousAccessSupported == nil || !*authMetadata.PreAuthorizedGrantAnonymousAccessSupported {
		return nil, fmt.Errorf(
			"anonymous access support is missing on authorization server that the credential issuer relies on; PreAuthorizedGrantAnonymousAccessSupported: %v",
			authMetadata.PreAuthorizedGrantAnonymousAccessSupported,
		)
	}

	if authMetadata.TokenEndpoint == nil {
		return nil, fmt.Errorf("token endpoint is missing on authorization server")
	}

	accessToken, err := c.receiver.FetchAccessToken(req.Type, *authMetadata.TokenEndpoint, preAuthCode)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch access token: %w", err)
	}

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

func (c *Controller) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error) {
	if req.Filter != nil {
		result, err := c.credStore.GetCredentialEntries(0, nil, types.SupportedCredStoreTypes(0))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get credential entries: %w", err)
		}

		var filteredCredentials []*SavedCredential
		if result.Entries != nil {
			for _, entry := range *result.Entries {
				f, err := entry.SerializationFlavor()
				if err != nil {
					continue
				}
				credential, err := c.serializer.DeserializeCredential(f, entry.Raw)
				if err != nil {
					continue
				}

				savedCred := &SavedCredential{
					Credential: credential,
					Entry:      &entry,
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
			f, err := entry.SerializationFlavor()
			if err != nil {
				continue
			}
			credential, err := c.serializer.DeserializeCredential(f, entry.Raw)
			if err != nil {
				continue
			}

			savedCredentials = append(savedCredentials, &SavedCredential{
				Credential: credential,
				Entry:      &entry,
			})
		}
	}

	totalCount := 0
	if result.TotalCount != nil {
		totalCount = *result.TotalCount
	}

	return savedCredentials, totalCount, nil
}

func (c *Controller) GetCredentialEntry(id string) (*SavedCredential, error) {
	entry, err := c.credStore.GetCredentialEntry(id, types.SupportedCredStoreTypes(0))
	if err != nil {
		return nil, fmt.Errorf("failed to get credential entry: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	f, err := entry.SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}
	credential, err := c.serializer.DeserializeCredential(f, entry.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return &SavedCredential{
		Credential: credential,
		Entry:      entry,
	}, nil
}

func (c *Controller) PresentCredential(uriString string, key IKeyEntry) error {
	req, err := c.presenter.ParseRequestURI(uriString)
	if err != nil {
		return fmt.Errorf("failed to parse request URI: %w", err)
	}

	var descriptorMap []presenterTypes.DescriptorMapItem
	var serializedCredentials [][]byte

	// Parse redirect_uri as endpoint
	if req.RedirectURI == "" {
		return fmt.Errorf("redirect_uri is not specified")
	}

	var endpoint *url.URL

	// if Response Mode direct_post is used, response_uri is used instead of redirect_uri
	if req.ResponseMode == oid4vp.OAuthAuthzReqResponseModeDirectPost {
		if req.ResponseURI == "" {
			return fmt.Errorf("response_uri is not specified for response_mode=direct_post")
		}
		endpoint, err = url.Parse(req.ResponseURI)
		if err != nil {
			return fmt.Errorf("invalid response_uri: %w", err)
		}
	} else {
		endpoint, err = url.Parse(req.RedirectURI)
		if err != nil {
			return fmt.Errorf("invalid redirect_uri: %w", err)
		}
	}

	if req.PresentationDefinition == nil {
		return fmt.Errorf("presentation definition is not specified")
	}

	// In a real implementation, this should match credentials based on input_descriptors
	entries, _, err := c.GetCredentialEntries(GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
	})
	if err != nil {
		return fmt.Errorf("failed to get credential entries: %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("no credentials available for presentation")
	}

	// Use the first credential for testing
	selectedCredentials := entries[:1]

	for i, entry := range selectedCredentials {
		serializedCredentials = append(serializedCredentials, entry.Entry.Raw)

		descriptionItemID := uuid.New().String()
		descriptorMap = append(descriptorMap, presenterTypes.DescriptorMapItem{
			ID:     descriptionItemID,
			Format: "jwt_vp_json",
			Path:   fmt.Sprintf("$.vp_token[%d]", i),
			PathNested: &presenterTypes.DescriptorMapItem{
				ID:     descriptionItemID,
				Format: "jwt_vc_json",
				Path:   fmt.Sprintf("$.verifiableCredential[%d]", i),
			},
		})
	}

	presentationSubmission := presenterTypes.PresentationSubmission{
		ID:            uuid.New().String(),
		DefinitionID:  req.PresentationDefinition.ID,
		DescriptorMap: descriptorMap,
	}

	// generate `did:key` for given key
	did, err := c.GenerateDID(DIDCreateOptions{
		TypeID:    "did:key",
		PublicKey: key.PublicKey(),
	})
	if err != nil {
		return fmt.Errorf("failed to generate DID: %w", err)
	}

	didURL, err := url.Parse(did.ID)
	if err != nil {
		return fmt.Errorf("failed to parse DID URL: %w", err)
	}

	presentation := &credential.CredentialPresentation{
		ID:          &url.URL{Scheme: "urn", Opaque: "uuid:" + uuid.New().String()},
		Types:       []string{"VerifiablePresentation"},
		Credentials: serializedCredentials,
		Holder:      didURL,
		Nonce:       &req.Nonce,
	}

	// generate VP and serialize
	bytes, _, err := c.serializer.SerializePresentation(
		credential.JwtVc,
		presentation,
		key,
	)
	if err != nil {
		return fmt.Errorf("failed to serialize presentation: %w", err)
	}

	return c.presenter.Present(presenterTypes.Oid4vp, *endpoint, bytes, presentationSubmission)
}

func (c *Controller) VerifyCredential(credential *credential.Credential, pubKey jose.JSONWebKey) bool {
	if credential.Proof == nil {
		return false
	}

	result, err := c.verifier.Verify(credential.Proof, &pubKey)
	return err != nil && result
}
