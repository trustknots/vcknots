package credstore

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	"github.com/trustknots/vcknots/wallet/credstore/types"
)

// Mock implementation
type mockStore struct {
	entries map[string]types.CredentialEntry
	fail    bool
}

func newMockStore() *mockStore {
	return &mockStore{
		entries: make(map[string]types.CredentialEntry),
	}
}

func (m *mockStore) SaveCredentialEntry(entry types.CredentialEntry, location types.SupportedCredStoreTypes) error {
	if m.fail {
		return errors.New("mock save error")
	}
	m.entries[entry.Id] = entry
	return nil
}

func (m *mockStore) GetCredentialEntry(id string, location types.SupportedCredStoreTypes) (*types.CredentialEntry, error) {
	if m.fail {
		return nil, errors.New("mock get error")
	}
	entry, ok := m.entries[id]
	if !ok {
		return nil, types.ErrCredentialNotFound
	}
	return &entry, nil
}

func (m *mockStore) GetCredentialEntries(offset int, limit *int, location types.SupportedCredStoreTypes) (*types.GetCredentialEntriesResult, error) {
	if m.fail {
		return nil, errors.New("mock list error")
	}
	entries := make([]types.CredentialEntry, 0, len(m.entries))
	for _, entry := range m.entries {
		entries = append(entries, entry)
	}
	total := len(entries)
	return &types.GetCredentialEntriesResult{
		Entries:    &entries,
		TotalCount: &total,
	}, nil
}

// Existing tests

func TestNewCredStoreDispatcher(t *testing.T) {
	t.Run("Default config", func(t *testing.T) {
		_, err := NewCredStoreDispatcher(WithDefaultConfig())
		if err != nil {
			t.Errorf("NewCredStoreDispatcher() with default config should not fail, got: %v", err)
		}
	})

	t.Run("Option function fails", func(t *testing.T) {
		failingOption := func(d *CredStoreDispatcher) error {
			return errors.New("a configuration error")
		}
		_, err := NewCredStoreDispatcher(failingOption)
		if err == nil {
			t.Error("NewCredStoreDispatcher() should fail when an option returns an error")
		}
	})
}

func TestWithDefaultConfig(t *testing.T) {
	t.Run("Check local plugin is registered", func(t *testing.T) {
		d, _ := NewCredStoreDispatcher(WithDefaultConfig())
		if _, exist := d.plugins[local.Local]; !exist {
			t.Errorf("LocalCredStore is not registered.")
			return
		}
	})
	appDir, _ := os.UserConfigDir()
	appPath := fmt.Sprintf("%s/%s/%s", appDir, "vcknots", "wallet")
	_ = os.Remove(fmt.Sprintf("%s/.local_credstore.db", appPath))
}

// Additional Test
func TestCredStoreDispatcher_Operations(t *testing.T) {
	mock := newMockStore()
	mockLocation := types.SupportedCredStoreTypes(100)
	d, err := NewCredStoreDispatcher(WithPlugin(mockLocation, mock))
	if err != nil {
		t.Fatalf("Failed to create dispatcher with mock plugin: %v", err)
	}

	testEntry := types.CredentialEntry{Id: "test-001", Raw: []byte("data")}

	t.Run("SaveCredentialEntry", func(t *testing.T) {
		err := d.SaveCredentialEntry(testEntry, mockLocation)
		if err != nil {
			t.Errorf("SaveCredentialEntry() failed: %v", err)
		}

		err = d.SaveCredentialEntry(types.CredentialEntry{Id: ""}, mockLocation)
		if !errors.Is(err, types.ErrInvalidCredentialID) {
			t.Errorf("Expected ErrInvalidCredentialID for empty ID, got %v", err)
		}

		err = d.SaveCredentialEntry(testEntry, 999)
		if !errors.Is(err, types.ErrPluginNotFound) {
			t.Errorf("Expected ErrPluginNotFound for unregistered location, got %v", err)
		}

		mock.fail = true
		err = d.SaveCredentialEntry(testEntry, mockLocation)
		if err == nil {
			t.Error("Expected error when underlying plugin save fails")
		}
		mock.fail = false
	})

	t.Run("GetCredentialEntry", func(t *testing.T) {
		retrieved, err := d.GetCredentialEntry("test-001", mockLocation)
		if err != nil {
			t.Errorf("GetCredentialEntry() failed: %v", err)
		}
		if !reflect.DeepEqual(*retrieved, testEntry) {
			t.Errorf("GetCredentialEntry() got = %v, want %v", *retrieved, testEntry)
		}

		_, err = d.GetCredentialEntry("", mockLocation)
		if !errors.Is(err, types.ErrInvalidCredentialID) {
			t.Errorf("Expected ErrInvalidCredentialID for empty ID, got %v", err)
		}

		_, err = d.GetCredentialEntry("test-001", 999)
		if !errors.Is(err, types.ErrPluginNotFound) {
			t.Errorf("Expected ErrPluginNotFound for unregistered location, got %v", err)
		}
	})

	t.Run("GetCredentialEntries", func(t *testing.T) {
		result, err := d.GetCredentialEntries(0, nil, mockLocation)
		if err != nil {
			t.Errorf("GetCredentialEntries() failed: %v", err)
		}
		if len(*result.Entries) != 1 {
			t.Errorf("Expected 1 entry, got %d", len(*result.Entries))
		}

		mock.fail = true
		_, err = d.GetCredentialEntries(0, nil, mockLocation)
		if err == nil {
			t.Error("Expected error when underlying plugin list fails")
		}
		mock.fail = false
	})

	t.Run("Register nil plugin", func(t *testing.T) {
		err := d.registerPlugin(101, nil)
		if !errors.Is(err, types.ErrNilPlugin) {
			t.Errorf("Expected ErrNilPlugin, got %v", err)
		}
	})
}
