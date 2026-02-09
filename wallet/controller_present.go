package wallet

import (
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

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
