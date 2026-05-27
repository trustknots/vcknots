// Package receiver provides credential receiving functionality with protocol dispatching
package receiver

import (
	"fmt"
	"path/filepath"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/mock"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// ReceivingDispatcher implements the main receiving interface with protocol dispatching
type ReceivingDispatcher struct {
	plugins map[types.SupportedReceivingTypes]types.Receiver
}

// NewReceivingDispatcher creates a new receiving dispatcher
func NewReceivingDispatcher(options ...func(*ReceivingDispatcher) error) (*ReceivingDispatcher, error) {
	d := &ReceivingDispatcher{
		plugins: make(map[types.SupportedReceivingTypes]types.Receiver),
	}

	for _, option := range options {
		if err := option(d); err != nil {
			return nil, fmt.Errorf("failed to configure receiving dispatcher: %w", err)
		}
	}

	return d, nil
}

// WithDefaultConfig is an option function to configure the dispatcher with built-in components
func WithDefaultConfig() func(d *ReceivingDispatcher) error {
	return func(d *ReceivingDispatcher) error {
		// Register built-in receiving components
		oid4vciReceiver := &oid4vci.Oid4vciReceiver{}
		d.registerPlugin(types.Oid4vci, oid4vciReceiver)

		examplesDir, _ := filepath.Abs("./examples")
		mockReceiver := mock.NewMockReceiver(examplesDir)
		d.registerPlugin(types.Mock, mockReceiver)

		return nil
	}
}

// WithPlugin is an option function to register a custom receiving component
func WithPlugin(receivingType types.SupportedReceivingTypes, plugin types.Receiver) func(*ReceivingDispatcher) error {
	return func(d *ReceivingDispatcher) error {
		return d.registerPlugin(receivingType, plugin)
	}
}

// RegisterPlugin registers a receiving component for a specific protocol type
func (d *ReceivingDispatcher) registerPlugin(receivingType types.SupportedReceivingTypes, plugin types.Receiver) error {
	if plugin == nil {
		return types.NewReceiverError(receivingType, "", "register", types.ErrNilPlugin)
	}
	d.plugins[receivingType] = plugin
	return nil
}

// getPlugin returns the plugin for the given receiving type
func (d *ReceivingDispatcher) getPlugin(receivingType types.SupportedReceivingTypes) (types.Receiver, error) {
	plugin, exists := d.plugins[receivingType]
	if !exists {
		return nil, types.NewReceiverError(receivingType, "", "get_plugin", types.ErrUnsupportedProtocol)
	}
	return plugin, nil
}

// FetchIssuerMetadata fetches OID4VCI Credential Issuer Metadata using the appropriate plugin
func (d *ReceivingDispatcher) FetchIssuerMetadata(endpoint common.URIField, receivingType types.SupportedReceivingTypes) (*types.CredentialIssuerMetadata, error) {
	plugin, err := d.getPlugin(receivingType)
	if err != nil {
		return nil, err
	}

	metadata, err := plugin.FetchIssuerMetadata(endpoint, receivingType)
	if err != nil {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "fetch_issuer_metadata", err)
	}

	return metadata, nil
}

// FetchAuthorizationServerMetadata fetches authorization server metadata using the appropriate plugin
func (d *ReceivingDispatcher) FetchAuthorizationServerMetadata(endpoint common.URIField, receivingType types.SupportedReceivingTypes) (*types.AuthorizationServerMetadata, error) {
	plugin, err := d.getPlugin(receivingType)
	if err != nil {
		return nil, err
	}

	metadata, err := plugin.FetchAuthorizationServerMetadata(endpoint, receivingType)
	if err != nil {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "fetch_auth_server_metadata", err)
	}

	return metadata, nil
}

// FetchAccessToken fetches access token using the appropriate plugin
func (d *ReceivingDispatcher) FetchAccessToken(receivingType types.SupportedReceivingTypes, endpoint common.URIField, authzCode string, txCode string, dpopProof *string) (*types.CredentialIssuanceAccessToken, error) {
	if authzCode == "" {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "fetch_access_token", types.ErrAuthorizationFailed)
	}

	plugin, err := d.getPlugin(receivingType)
	if err != nil {
		return nil, err
	}

	token, err := plugin.FetchAccessToken(receivingType, endpoint, authzCode, txCode, dpopProof)
	if err != nil {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "fetch_access_token", err)
	}

	return token, nil
}

// FetchNonce fetches nonce using the appropriate plugin
func (d *ReceivingDispatcher) FetchNonce(receivingType types.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	plugin, err := d.getPlugin(receivingType)
	if err != nil {
		return nil, err
	}

	nonce, err := plugin.FetchNonce(receivingType, endpoint)
	if err != nil {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "fetch_nonce", err)
	}

	return nonce, nil
}

// ReceiveCredential receives credential using the appropriate plugin
func (d *ReceivingDispatcher) ReceiveCredential(
	receivingType types.SupportedReceivingTypes,
	endpoint common.URIField,
	credentialConfigurationID string,
	credentialIdentifier *string,
	accessToken types.CredentialIssuanceAccessToken,
	credentialDefinition *types.CredentialDefinition,
	jwtProof *string,
	options ...*types.CredentialRequestOptions,
) (*string, error) {
	hasCredentialIdentifier := credentialIdentifier != nil && *credentialIdentifier != ""
	if credentialConfigurationID == "" && !hasCredentialIdentifier {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "receive_credential", types.ErrInvalidCredentialResponse)
	}

	plugin, err := d.getPlugin(receivingType)
	if err != nil {
		return nil, err
	}

	credential, err := plugin.ReceiveCredential(receivingType, endpoint, credentialConfigurationID, credentialIdentifier, accessToken, credentialDefinition, jwtProof, options...)
	if err != nil {
		return nil, types.NewReceiverError(receivingType, endpoint.String(), "receive_credential", err)
	}

	return credential, nil
}
