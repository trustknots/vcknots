// Package mock provides a mock receiver plugin for testing purposes
// that reads Verifiable Credentials from txt files
package mock

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// MockReceiver implements the Receiver interface for mock/testing purposes
// It reads Verifiable Credentials from txt files
type MockReceiver struct {
	// BasePath is the base directory path where txt files containing VCs are stored
	BasePath string
}

// NewMockReceiver creates a new MockReceiver instance
func NewMockReceiver(basePath string) *MockReceiver {
	return &MockReceiver{
		BasePath: basePath,
	}
}

// FetchIssuerMetadata returns mock credential issuer metadata
// For mock implementation, this returns minimal metadata
func (m *MockReceiver) FetchIssuerMetadata(endpoint common.URIField, receivingType types.SupportedReceivingTypes) (*types.CredentialIssuerMetadata, error) {
	if receivingType != types.Mock {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "FetchIssuerMetadata", fmt.Errorf("unsupported receiving type for mock receiver"))
	}

	// Return minimal mock metadata
	credentialEndpoint, _ := common.ParseURIField("mock://example_vc_jwt")
	authServer, _ := common.ParseURIField("mock://auth-server")
	metadata := &types.CredentialIssuerMetadata{
		CredentialIssuer:     "mock://issuer",
		CredentialEndpoint:   *credentialEndpoint,
		AuthorizationServers: []common.URIField{*authServer},
	}

	return metadata, nil
}

// FetchAuthorizationServerMetadata returns mock authorization server metadata
// For mock implementation, this returns minimal metadata
func (m *MockReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, receivingType types.SupportedReceivingTypes) (*types.AuthorizationServerMetadata, error) {
	if receivingType != types.Mock {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "FetchAuthorizationServerMetadata", fmt.Errorf("unsupported receiving type for mock receiver"))
	}

	// Return minimal mock metadata
	issuer, _ := common.ParseURIField("mock://issuer")

	metadata := &types.AuthorizationServerMetadata{
		Issuer: *issuer,
		PreAuthorizedGrantAnonymousAccessSupported: &[]bool{true}[0],
		TokenEndpoint:         &common.URIField{Scheme: "mock", Host: "token"},
		AuthorizationEndpoint: &common.URIField{Scheme: "mock", Host: "authorize"},
	}

	return metadata, nil
}

// FetchAccessToken returns a mock access token
// For mock implementation, this returns a static mock token
func (m *MockReceiver) FetchAccessToken(receivingType types.SupportedReceivingTypes, endpoint common.URIField, authzCode string) (*types.CredentialIssuanceAccessToken, error) {
	if receivingType != types.Mock {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "FetchAccessToken", fmt.Errorf("unsupported receiving type for mock receiver"))
	}

	// Return mock access token
	token := &types.CredentialIssuanceAccessToken{
		Token:     "mock_access_token",
		TokenType: "Bearer",
		ExpiresIn: 3600,
	}

	return token, nil
}

// ReceiveCredential reads a Verifiable Credential from a txt file
// The endpoint parameter is treated as a filename (without extension) relative to BasePath
func (m *MockReceiver) ReceiveCredential(
	receivingType types.SupportedReceivingTypes,
	endpoint common.URIField,
	format string,
	accessToken types.CredentialIssuanceAccessToken,
	credentialDefinition *types.CredentialDefinition,
	jwtProof *string,
) (*string, error) {
	if receivingType != types.Mock {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "ReceiveCredential", fmt.Errorf("unsupported receiving type for mock receiver"))
	}

	// Convert endpoint to filename
	filename := strings.TrimPrefix(endpoint.String(), "mock://")
	if !strings.HasSuffix(filename, ".txt") {
		filename += ".txt"
	}

	// Construct full path
	fullPath := filepath.Join(m.BasePath, filename)

	// Read the VC content from txt file
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, types.NewReceiverError(
			receivingType, endpoint.String(), "ReceiveCredential",
			fmt.Errorf("failed to read VC file %s: %w", fullPath, err),
		)
	}

	// Return the content as credential
	credentialContent := string(content)
	return &credentialContent, nil
}
