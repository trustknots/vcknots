// Package store provides the feature for storing and managing ID profiles.
package store

import "github.com/trustknots/vcknots/wallet/idprof/types"

// IDProfileStore defines the interface for storing and retrieving ID profiles.
type IDProfileStore interface {
	// TypeID returns the type ID of the store.
	TypeID() string

	// Save stores the given ID profile.
	Save(profile *types.IdentityProfile) error

	// Get retrieves the ID profile with the given ID.
	Get(id string) (*types.IdentityProfile, error)

	// Delete removes the ID profile with the given ID.
	Delete(id string) error

	// List retrieves all stored ID profiles.
	List() ([]*types.IdentityProfile, error)
}
