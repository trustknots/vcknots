// Package types provides common types and interfaces for identity profiles
package types

import (
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Sentinel errors for identity profile operations
var (
	ErrProfileNotFound   = errors.New("identity profile not found")
	ErrInvalidProfileID  = errors.New("invalid profile ID")
	ErrUnsupportedTypeID = errors.New("unsupported profile type ID")
	ErrProfileExists     = errors.New("profile already exists")
	ErrInvalidKeys       = errors.New("invalid key set")
	ErrProfileValidation = errors.New("profile validation failed")
	ErrResolutionFailed  = errors.New("failed to resolve profile from remote source")
	ErrUpdateFailed      = errors.New("failed to update profile")
	ErrInvalidConfig     = errors.New("invalid configuration")
	ErrPluginNotFound    = errors.New("identity profile plugin not found")
	ErrNilPlugin         = errors.New("identity profile plugin cannot be nil")
)

// IdentityProfileError represents an error with identity profile operations
type IdentityProfileError struct {
	TypeID string `json:"type_id"`
	ID     string `json:"id,omitempty"`
	Op     string `json:"operation"`
	Err    error  `json:"error"`
}

func (e *IdentityProfileError) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("identity profile %s (type: %s) operation %s: %v", e.ID, e.TypeID, e.Op, e.Err)
	}
	return fmt.Sprintf("identity profile type %s operation %s: %v", e.TypeID, e.Op, e.Err)
}

func (e *IdentityProfileError) Unwrap() error {
	return e.Err
}

// NewIdentityProfileError creates a new IdentityProfileError
func NewIdentityProfileError(typeID, id, op string, err error) *IdentityProfileError {
	return &IdentityProfileError{
		TypeID: typeID,
		ID:     id,
		Op:     op,
		Err:    err,
	}
}

// IdentityProfile defines the struct for an identity profile.
// Identity profiles are used to represent various types of identities,
// such as decentralized identifiers (DIDs) or other identity constructs.
// Each identity profile contains an ID, type identifier, and associated keys.
// It serves as a base for different identity profile implementations, such as DIDKeyProfile.
type IdentityProfile struct {
	// ID returns the identifier of the identity profile, which should be unique across same IdentityProfile type.
	// For example, for a DID-based identity profile, this would be the DID.
	ID string

	// TypeID returns the type identifier of the identity profile.
	// This is used to distinguish between different types of identity profiles.
	TypeID string

	// Keys returns the cryptographic keys associated with the identity profile, used as verification methods.
	Keys *jose.JSONWebKeySet
}

// CreateOption is a function type for configuring identity profile creation
type CreateOption func(config *CreateConfig) error

// UpdateOption is a function type for configuring identity profile updates
type UpdateOption func(config *UpdateConfig) error

// CreateConfig holds configuration for creating identity profiles
type CreateConfig struct {
	// params holds configuration parameters - use Get/Set methods to access
	params map[string]interface{}
}

// UpdateConfig holds configuration for updating identity profiles
type UpdateConfig struct {
	// params holds configuration parameters - use Get/Set methods to access
	params map[string]interface{}
}

// NewCreateConfig creates a new CreateConfig with initialized map
func NewCreateConfig() *CreateConfig {
	return &CreateConfig{
		params: make(map[string]interface{}),
	}
}

// NewUpdateConfig creates a new UpdateConfig with initialized map
func NewUpdateConfig() *UpdateConfig {
	return &UpdateConfig{
		params: make(map[string]interface{}),
	}
}

// Set sets a parameter value in the CreateConfig
func (c *CreateConfig) Set(key string, value interface{}) {
	c.params[key] = value
}

// Get retrieves a parameter value from the CreateConfig
func (c *CreateConfig) Get(key string) (interface{}, bool) {
	value, exists := c.params[key]
	return value, exists
}

// Has checks if a parameter exists in the CreateConfig
func (c *CreateConfig) Has(key string) bool {
	_, exists := c.params[key]
	return exists
}

// Set sets a parameter value in the UpdateConfig
func (u *UpdateConfig) Set(key string, value interface{}) {
	u.params[key] = value
}

// Get retrieves a parameter value from the UpdateConfig
func (u *UpdateConfig) Get(key string) (interface{}, bool) {
	value, exists := u.params[key]
	return value, exists
}

// Has checks if a parameter exists in the UpdateConfig
func (u *UpdateConfig) Has(key string) bool {
	_, exists := u.params[key]
	return exists
}

// IdentityProfiler is an interface that defines methods for creating and managing identity profiles.
// It handles the core operations for identity profiles without concerning itself with storage.
type IdentityProfiler interface {
	// Create creates a new identity profile with the given options.
	// This operation may involve local key generation or initialization.
	Create(opts ...CreateOption) (*IdentityProfile, error)

	// Resolve resolves an identity profile from remote sources (e.g., DID documents, JWKs endpoints).
	// This is used to fetch the latest verification methods from authoritative sources.
	// The id parameter is the identifier to resolve (e.g., DID, JWKs URL).
	Resolve(id string) (*IdentityProfile, error)

	// Update updates an existing identity profile.
	// This operation may involve updating keys, metadata, or publishing changes to remote sources.
	// For example, for did:ethr, this might update the keyset on-chain.
	Update(profile *IdentityProfile, opts ...UpdateOption) (*IdentityProfile, error)

	// GetTypeID returns the type identifier that this profiler handles.
	GetTypeID() string

	// Validate validates that a profile conforms to the requirements of this profiler type.
	Validate(profile *IdentityProfile) error
}
