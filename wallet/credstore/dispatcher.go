package credstore

import (
	"fmt"
	"os"

	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	"github.com/trustknots/vcknots/wallet/credstore/types"
)

type CredStoreDispatcher struct {
	plugins map[SupportedCredStoreTypes]CredStore
}

func NewCredStoreDispatcher(options ...func(*CredStoreDispatcher) error) (*CredStoreDispatcher, error) {
	d := &CredStoreDispatcher{
		plugins: make(map[SupportedCredStoreTypes]CredStore),
	}
	for _, option := range options {
		if err := option(d); err != nil {
			return nil, types.NewCredStoreError(0, "", "configure", fmt.Errorf("failed to configure credstore dispatcher: %w", err))
		}
	}

	return d, nil
}

func WithDefaultConfig() func(*CredStoreDispatcher) error {
	return func(d *CredStoreDispatcher) error {
		appDir, err := os.UserConfigDir()
		if err != nil {
			return types.NewCredStoreError(local.Local, "", "get_config_dir", fmt.Errorf("failed to get user config dir: %w", err))
		}
		appPath := fmt.Sprintf("%s/%s/%s", appDir, "vcknots", "wallet")
		if err := os.MkdirAll(appPath, 0700); err != nil {
			return types.NewCredStoreError(local.Local, "", "create_directory", fmt.Errorf("failed to create app directory: %w", err))
		}
		plugin, err := local.NewLocalCredentialStorage(fmt.Sprintf("%s/.local_credstore.db", appPath))
		if err != nil {
			return types.NewCredStoreError(local.Local, "", "initialize", fmt.Errorf("failed to initialize local credential storage: %w", err))
		}
		return d.registerPlugin(local.Local, plugin)
	}
}

func WithPlugin(credStoreType types.SupportedCredStoreTypes, plugin CredStore) func(*CredStoreDispatcher) error {
	return func(d *CredStoreDispatcher) error {
		return d.registerPlugin(credStoreType, plugin)
	}
}

func (d *CredStoreDispatcher) registerPlugin(credStoreType types.SupportedCredStoreTypes, plugin CredStore) error {
	if plugin == nil {
		return types.NewCredStoreError(credStoreType, "", "register", types.ErrNilPlugin)
	}
	d.plugins[credStoreType] = plugin
	return nil
}

func (d *CredStoreDispatcher) getPlugin(credStoreType SupportedCredStoreTypes) (CredStore, error) {
	plugin, exists := d.plugins[credStoreType]
	if !exists {
		return nil, types.NewCredStoreError(credStoreType, "", "get_plugin", types.ErrPluginNotFound)
	}
	return plugin, nil
}

// Implementation of CredStore interface
func (d *CredStoreDispatcher) SaveCredentialEntry(credentialEntry CredentialEntry, location SupportedCredStoreTypes) error {
	if credentialEntry.Id == "" {
		return types.NewCredStoreError(location, "", "save", types.ErrInvalidCredentialID)
	}

	plugin, err := d.getPlugin(location)
	if err != nil {
		return err
	}

	if err := plugin.SaveCredentialEntry(credentialEntry, location); err != nil {
		return types.NewCredStoreError(location, credentialEntry.Id, "save", err)
	}

	return nil
}

func (d *CredStoreDispatcher) GetCredentialEntries(offset int, limit *int, location types.SupportedCredStoreTypes) (*types.GetCredentialEntriesResult, error) {
	plugin, err := d.getPlugin(location)
	if err != nil {
		return nil, err
	}

	result, err := plugin.GetCredentialEntries(offset, limit, location)
	if err != nil {
		return nil, types.NewCredStoreError(location, "", "get_entries", err)
	}

	return result, nil
}

func (d *CredStoreDispatcher) GetCredentialEntry(id string, location SupportedCredStoreTypes) (*CredentialEntry, error) {
	if id == "" {
		return nil, types.NewCredStoreError(location, "", "get", types.ErrInvalidCredentialID)
	}

	plugin, err := d.getPlugin(location)
	if err != nil {
		return nil, err
	}

	entry, err := plugin.GetCredentialEntry(id, location)
	if err != nil {
		return nil, types.NewCredStoreError(location, id, "get", err)
	}

	return entry, nil
}
