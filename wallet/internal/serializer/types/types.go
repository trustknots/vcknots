// Package types defines the interfaces and error types for the serialization system
package types

import (
	"errors"
	"fmt"

	"github.com/trustknots/vcknots/wallet/internal/credential"
	"github.com/trustknots/vcknots/wallet/internal/keystore"
)

// Sentinel errors for common serialization failures
var (
	ErrUnsupportedFormat    = errors.New("unsupported serialization format")
	ErrInvalidJWT           = errors.New("invalid JWT format")
	ErrInvalidCredential    = errors.New("invalid credential structure")
	ErrInvalidPresentation  = errors.New("invalid presentation structure")
	ErrMissingProof         = errors.New("missing or invalid proof")
	ErrSigningFailed        = errors.New("failed to sign data")
	ErrDecodingFailed       = errors.New("failed to decode data")
	ErrUnsupportedAlgorithm = errors.New("unsupported cryptographic algorithm")
	ErrPluginNotFound       = errors.New("serialization plugin not found")
	ErrNilPlugin            = errors.New("serialization plugin cannot be nil")
)

// SerializePresentationOptions is a marker interface for presentation serialization options
// Each plugin can define its own options struct that implements this interface
type SerializePresentationOptions interface {
	IsSerializePresentationOptions()
}

// Serializer defines the interface that all serialization plugins must implement
type Serializer interface {
	// SerializeCredential serializes a Credential struct to byte array
	SerializeCredential(flavor credential.SupportedSerializationFlavor, cred *credential.Credential) ([]byte, error)

	// DeserializeCredential deserializes byte array to Credential struct
	DeserializeCredential(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.Credential, error)

	// SerializePresentation serializes a CredentialPresentation struct to byte array with signature
	// options: Plugin-specific options (can be nil for defaults)
	// Returns (serialized bytes, signed presentation with proof)
	SerializePresentation(flavor credential.SupportedSerializationFlavor, presentation *credential.CredentialPresentation, key keystore.KeyEntry, options SerializePresentationOptions) ([]byte, *credential.CredentialPresentation, error)

	// DeserializePresentation deserializes byte array to CredentialPresentation struct
	DeserializePresentation(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.CredentialPresentation, error)
}

// NewFormatError creates a format-specific error with context
func NewFormatError(format credential.SupportedSerializationFlavor, err error, msg string) error {
	return fmt.Errorf("serialization format %v: %s: %w", format, msg, err)
}

// NewInvalidJWTError creates an error for invalid JWT format
func NewInvalidJWTError(msg string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalidJWT, msg, cause)
	}
	return fmt.Errorf("%w: %s", ErrInvalidJWT, msg)
}

// NewInvalidCredentialError creates an error for invalid credential data
func NewInvalidCredentialError(msg string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %s: %w", ErrInvalidCredential, msg, cause)
	}
	return fmt.Errorf("%w: %s", ErrInvalidCredential, msg)
}

// NewDecodingError creates an error for decoding failures
func NewDecodingError(msg string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %s: %w", ErrDecodingFailed, msg, cause)
	}
	return fmt.Errorf("%w: %s", ErrDecodingFailed, msg)
}
