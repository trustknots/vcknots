// Package idprof provides the definition and management of identity profiles.
package idprof

import (
	"fmt"
	"sync"

	"github.com/trustknots/vcknots/wallet/idprof/plugins/did"
	"github.com/trustknots/vcknots/wallet/idprof/plugins/jwks"
	"github.com/trustknots/vcknots/wallet/idprof/store"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

type IdentityProfile = types.IdentityProfile
type IdentityProfiler = types.IdentityProfiler

type IDProfileStore = store.IDProfileStore

// IdentityProfileDispatcher routes each type to the corresponding plugin and manages storage
type IdentityProfileDispatcher struct {
	plugins map[string]IdentityProfiler
	store   IDProfileStore
	mu      sync.RWMutex
}

// NewIdentityProfileDispatcher creates a new empty dispatcher
func NewIdentityProfileDispatcher(options ...func(*IdentityProfileDispatcher) error) (*IdentityProfileDispatcher, error) {
	d := &IdentityProfileDispatcher{
		plugins: make(map[string]IdentityProfiler),
		store:   nil,
	}

	for _, option := range options {
		if err := option(d); err != nil {
			return nil, fmt.Errorf("failed to configure identity profile dispatcher: %w", err)
		}
	}

	return d, nil
}

// WithStore is an option function to configure the dispatcher with a store
func WithStore(store IDProfileStore) func(*IdentityProfileDispatcher) error {
	return func(d *IdentityProfileDispatcher) error {
		if store == nil {
			return fmt.Errorf("store cannot be nil")
		}
		d.store = store
		return nil
	}
}

// GetStoreType returns the type ID of the store
func (d *IdentityProfileDispatcher) GetStoreType() string {
	if d.store != nil {
		return d.store.TypeID()
	}
	return ""
}

// RegisterPlugin registers a plugin for a specific type ID
func (d *IdentityProfileDispatcher) RegisterPlugin(typeID string, plugin IdentityProfiler) error {
	if plugin == nil {
		return types.NewIdentityProfileError(typeID, "", "register", types.ErrNilPlugin)
	}
	if typeID == "" {
		return types.NewIdentityProfileError("", "", "register", types.ErrInvalidProfileID)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.plugins[typeID] = plugin
	return nil
}

// getPlugin returns the plugin for the given type ID
func (d *IdentityProfileDispatcher) getPlugin(typeID string) (IdentityProfiler, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	plugin, exists := d.plugins[typeID]
	if !exists {
		return nil, types.NewIdentityProfileError(typeID, "", "get_plugin", types.ErrUnsupportedTypeID)
	}
	return plugin, nil
}

// Create creates a new identity profile using the appropriate plugin
func (d *IdentityProfileDispatcher) Create(typeID string, opts ...types.CreateOption) (*IdentityProfile, error) {
	if typeID == "" {
		return nil, types.NewIdentityProfileError("", "", "create", types.ErrInvalidProfileID)
	}

	plugin, err := d.getPlugin(typeID)
	if err != nil {
		return nil, err
	}

	profile, err := plugin.Create(opts...)
	if err != nil {
		return nil, types.NewIdentityProfileError(typeID, "", "create", err)
	}

	return profile, nil
}

// Resolve resolves an identity profile from remote sources using the appropriate plugin
func (d *IdentityProfileDispatcher) Resolve(typeID string, id string) (*IdentityProfile, error) {
	if typeID == "" {
		return nil, types.NewIdentityProfileError("", id, "resolve", types.ErrInvalidProfileID)
	}
	if id == "" {
		return nil, types.NewIdentityProfileError(typeID, "", "resolve", types.ErrInvalidProfileID)
	}

	plugin, err := d.getPlugin(typeID)
	if err != nil {
		return nil, err
	}

	profile, err := plugin.Resolve(id)
	if err != nil {
		return nil, types.NewIdentityProfileError(typeID, id, "resolve", err)
	}

	return profile, nil
}

// Update updates an existing identity profile using the appropriate plugin
func (d *IdentityProfileDispatcher) Update(profile *IdentityProfile, opts ...types.UpdateOption) (*IdentityProfile, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile cannot be nil")
	}

	plugin, err := d.getPlugin(profile.TypeID)
	if err != nil {
		return nil, err
	}
	return plugin.Update(profile, opts...)
}

// Validate validates a profile using the appropriate plugin
func (d *IdentityProfileDispatcher) Validate(profile *IdentityProfile) error {
	if profile == nil {
		return fmt.Errorf("profile cannot be nil")
	}

	plugin, err := d.getPlugin(profile.TypeID)
	if err != nil {
		return err
	}
	return plugin.Validate(profile)
}

// SaveProfile saves a profile to the store
func (d *IdentityProfileDispatcher) SaveProfile(profile *IdentityProfile) error {
	if d.store == nil {
		return fmt.Errorf("no store configured: use WithStore() option to configure a store")
	}
	return d.store.Save(profile)
}

// GetProfile retrieves a profile from the store by ID
func (d *IdentityProfileDispatcher) GetProfile(id string) (*IdentityProfile, error) {
	if d.store == nil {
		return nil, fmt.Errorf("no store configured: use WithStore() option to configure a store")
	}
	return d.store.Get(id)
}

// DeleteProfile deletes a profile from the store by ID
func (d *IdentityProfileDispatcher) DeleteProfile(id string) error {
	if d.store == nil {
		return fmt.Errorf("no store configured: use WithStore() option to configure a store")
	}
	return d.store.Delete(id)
}

// ListProfiles lists all profiles from the store
func (d *IdentityProfileDispatcher) ListProfiles() ([]*IdentityProfile, error) {
	if d.store == nil {
		return nil, fmt.Errorf("no store configured: use WithStore() option to configure a store")
	}
	return d.store.List()
}

// GetSupportedTypes returns a list of supported identity profile types
func (d *IdentityProfileDispatcher) GetSupportedTypes() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	types := make([]string, 0, len(d.plugins))
	for typeID := range d.plugins {
		types = append(types, typeID)
	}
	return types
}

// WithDefaultConfig is an option function to configure the dispatcher with built-in plugins
func WithDefaultConfig() func(*IdentityProfileDispatcher) error {
	return func(d *IdentityProfileDispatcher) error {
		// Register DID plugin
		didPlugin := did.NewDIDPlugin()
		if err := d.RegisterPlugin("did", didPlugin); err != nil {
			return fmt.Errorf("failed to register DID plugin: %w", err)
		}

		// Register JWKS plugin
		jwksPlugin := jwks.NewJWKSPlugin()
		if err := d.RegisterPlugin("jwks", jwksPlugin); err != nil {
			return fmt.Errorf("failed to register JWKS plugin: %w", err)
		}

		return nil
	}
}
