// Package serializer provides credential serialization and deserialization functionality with format dispatching
package serializer

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/jwtvc"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

// SerializationDispatcher implements the main serialization interface with format dispatching
type SerializationDispatcher struct {
	plugins map[credential.SupportedSerializationFlavor]types.Serializer
}

// NewSerializationDispatcher creates a new serialization dispatcher
func NewSerializationDispatcher(options ...func(*SerializationDispatcher) error) (*SerializationDispatcher, error) {
	d := &SerializationDispatcher{
		plugins: make(map[credential.SupportedSerializationFlavor]types.Serializer),
	}

	for _, option := range options {
		if err := option(d); err != nil {
			return nil, fmt.Errorf("failed to configure serialization dispatcher: %w", err)
		}
	}

	return d, nil
}

// WithDefaultConfig is an option function to configure the dispatcher with built-in components
func WithDefaultConfig() func(*SerializationDispatcher) error {
	return func(d *SerializationDispatcher) error {
		jwtVcPlugin, err := jwtvc.NewJwtVcSerializer()
		if err != nil {
			return types.NewFormatError(credential.JwtVc, err, "failed to create JWT VC serializer")
		}
		d.RegisterPlugin(credential.JwtVc, jwtVcPlugin)

		sdJwtVcPlugin, err := sdjwtvc.NewSdJwtVcSerializer()
		if err != nil {
			return types.NewFormatError(credential.JwtVc, err, "failed to create SD-JWT VC serializer")
		}
		d.RegisterPlugin(credential.SDJwtVC, sdJwtVcPlugin)

		return nil
	}
}

// WithPlugin is an option function to register a custom serialization plugin
func WithPlugin(flavor credential.SupportedSerializationFlavor, plugin types.Serializer) func(*SerializationDispatcher) error {
	return func(d *SerializationDispatcher) error {
		return d.RegisterPlugin(flavor, plugin)
	}
}

// RegisterPlugin registers a serialization plugin for a specific format
func (d *SerializationDispatcher) RegisterPlugin(flavor credential.SupportedSerializationFlavor, plugin types.Serializer) error {
	if plugin == nil {
		return types.NewFormatError(flavor, types.ErrNilPlugin, "plugin cannot be nil")
	}

	d.plugins[flavor] = plugin
	return nil
}

// getPlugin returns the serialization plugin for the given format
func (d *SerializationDispatcher) getPlugin(flavor credential.SupportedSerializationFlavor) (types.Serializer, error) {
	plugin, exists := d.plugins[flavor]
	if !exists {
		return nil, types.NewFormatError(flavor, types.ErrPluginNotFound, "plugin not found")
	}
	return plugin, nil
}

// SerializeCredential serializes a credential using the appropriate format-specific plugin
func (d *SerializationDispatcher) SerializeCredential(flavor credential.SupportedSerializationFlavor, cred *credential.Credential) ([]byte, error) {
	if cred == nil {
		return nil, types.NewFormatError(flavor, types.ErrInvalidCredential, "credential cannot be nil")
	}

	plugin, err := d.getPlugin(flavor)
	if err != nil {
		return nil, err
	}

	result, err := plugin.SerializeCredential(flavor, cred)
	if err != nil {
		return nil, types.NewFormatError(flavor, err, "serialization failed")
	}

	return result, nil
}

// DeserializeCredential deserializes a credential using the appropriate format-specific plugin
func (d *SerializationDispatcher) DeserializeCredential(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.Credential, error) {
	if len(data) == 0 {
		return nil, types.NewFormatError(flavor, types.ErrDecodingFailed, "data cannot be empty")
	}

	plugin, err := d.getPlugin(flavor)
	if err != nil {
		return nil, err
	}

	result, err := plugin.DeserializeCredential(flavor, data)
	if err != nil {
		return nil, types.NewFormatError(flavor, err, "deserialization failed")
	}

	return result, nil
}

// SerializePresentation serializes a credential presentation using the appropriate format-specific plugin
func (d *SerializationDispatcher) SerializePresentation(flavor credential.SupportedSerializationFlavor, presentation *credential.CredentialPresentation, key keystore.KeyEntry, options types.SerializePresentationOptions) ([]byte, *credential.CredentialPresentation, error) {
	if presentation == nil {
		return nil, nil, types.NewFormatError(flavor, types.ErrInvalidPresentation, "presentation cannot be nil")
	}
	if key == nil {
		return nil, nil, types.NewFormatError(flavor, types.ErrSigningFailed, "key cannot be nil")
	}

	plugin, err := d.getPlugin(flavor)
	if err != nil {
		return nil, nil, err
	}

	result, signedPresentation, err := plugin.SerializePresentation(flavor, presentation, key, options)
	if err != nil {
		return nil, nil, types.NewFormatError(flavor, err, "presentation serialization failed")
	}

	return result, signedPresentation, nil
}

// DeserializePresentation deserializes a credential presentation using the appropriate format-specific plugin
func (d *SerializationDispatcher) DeserializePresentation(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.CredentialPresentation, error) {
	if len(data) == 0 {
		return nil, types.NewFormatError(flavor, types.ErrDecodingFailed, "data cannot be empty")
	}

	plugin, err := d.getPlugin(flavor)
	if err != nil {
		return nil, err
	}

	result, err := plugin.DeserializePresentation(flavor, data)
	if err != nil {
		return nil, types.NewFormatError(flavor, err, "presentation deserialization failed")
	}

	return result, nil
}

// GetSupportedFormats returns a list of supported serialization formats
func (d *SerializationDispatcher) GetSupportedFormats() []credential.SupportedSerializationFlavor {
	formats := make([]credential.SupportedSerializationFlavor, 0, len(d.plugins))
	for flavor := range d.plugins {
		formats = append(formats, flavor)
	}
	return formats
}
