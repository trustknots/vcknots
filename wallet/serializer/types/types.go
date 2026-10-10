// Package types defines the interfaces and error types for the serialization system
package types

import (
	"errors"
	"fmt"

	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/keystore"
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
	// ErrClaimsNotSatisfiable reports that a Credential cannot deliver the claims a
	// ClaimsQuery asks for. OID4VP 1.0 Section 6.4.1 then forbids returning it at all.
	ErrClaimsNotSatisfiable = errors.New("credential cannot satisfy the requested claims")
)

// ClaimsQuery is the format-neutral part of a DCQL Credential Query that decides
// which claims a presentation discloses (OID4VP 1.0 Sections 6.3 and 6.4.1).
type ClaimsQuery struct {
	// Claims is nil when the Credential Query has no claims. Only the claims that
	// are mandatory to present may then be disclosed.
	Claims []ClaimQuery
	// ClaimSets lists alternative combinations of Claims ids; the first one the
	// Credential can satisfy is disclosed.
	ClaimSets [][]string
}

// ClaimQuery is one entry of a DCQL claims array.
type ClaimQuery struct {
	ID string
	// Path is a claims path pointer (OID4VP 1.0 Section 7): strings, nulls and
	// non-negative integers.
	Path []any
}

// SerializePresentationOptions is a marker interface for presentation serialization options
// Each plugin can define its own options struct that implements this interface
type SerializePresentationOptions interface {
	IsSerializePresentationOptions()
	SetAudience(audience string)
	SetNonce(nonce string)
	// SetClaimsQuery sets the claims the Verifier asked for. A plugin whose format
	// supports selective disclosure must disclose only those claims and fail with
	// ErrClaimsNotSatisfiable when it cannot deliver them.
	SetClaimsQuery(query *ClaimsQuery)
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

	GetDefaultOption(flavor credential.SupportedSerializationFlavor) (SerializePresentationOptions, error)
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
