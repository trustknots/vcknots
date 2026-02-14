package idprof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/idprof/plugins/did"
	"github.com/trustknots/vcknots/wallet/idprof/store/local"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

func TestNewIdentityProfileDispatcher(t *testing.T) {
	dispatcher, err := NewIdentityProfileDispatcher()
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	if dispatcher == nil {
		t.Fatal("NewIdentityProfileDispatcher() returned nil")
	}

	if dispatcher.plugins == nil {
		t.Fatal("plugins map should not be nil")
	}

	// Should be empty initially
	if len(dispatcher.plugins) != 0 {
		t.Error("dispatcher should be empty initially")
	}
}

func TestWithStore(t *testing.T) {
	localStore := local.NewIDProfileLocalStore()
	dispatcher, err := NewIdentityProfileDispatcher(
		WithStore(localStore),
	)
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	// Test that store operations work (indirectly testing store is configured)
	profile := &types.IdentityProfile{
		ID:     "test:withstore:verify",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}

	err = dispatcher.SaveProfile(profile)
	if err != nil {
		t.Errorf("SaveProfile should work with configured store: %v", err)
	}

	retrieved, err := dispatcher.GetProfile(profile.ID)
	if err != nil {
		t.Errorf("GetProfile should work with configured store: %v", err)
	}
	if retrieved.ID != profile.ID {
		t.Errorf("expected ID '%s', got '%s'", profile.ID, retrieved.ID)
	}
}

func TestWithDefaultConfig(t *testing.T) {
	dispatcher, err := NewIdentityProfileDispatcher(WithDefaultConfig())
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	if dispatcher == nil {
		t.Fatal("WithDefaultConfig() returned nil")
	}

	if dispatcher.plugins == nil {
		t.Fatal("plugins map should not be nil")
	}

	// Should have built-in plugins registered
	if len(dispatcher.plugins) == 0 {
		t.Error("default dispatcher should have built-in plugins registered")
	}

	// Check that DID plugin is registered
	_, err = dispatcher.getPlugin("did")
	if err != nil {
		t.Error("DID plugin should be registered by default")
	}
}

func TestIdentityProfileDispatcher_GetStoreType(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		localStore := local.NewIDProfileLocalStore()
		dispatcher, err := NewIdentityProfileDispatcher(
			WithStore(localStore),
		)
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		storeType := dispatcher.GetStoreType()

		if storeType != localStore.TypeID() {
			t.Errorf("IdentityProfileDispatcher.GetStoreType() = %v, want %v", storeType, localStore.TypeID())
		}
	})

	t.Run("No store", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		storeType := dispatcher.GetStoreType()

		if storeType != "" {
			t.Errorf("IdentityProfileDispatcher.GetStoreType() should return empty string when store is nil")
		}
	})
}

func TestIdentityProfileDispatcher_RegisterPlugin(t *testing.T) {
	dispatcher, err := NewIdentityProfileDispatcher()
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}
	mockPlugin := &mockIdentityProfilePlugin{}

	dispatcher.RegisterPlugin("test", mockPlugin)

	// Check if the plugin was registered
	if plugin, exists := dispatcher.plugins["test"]; !exists {
		t.Error("plugin should be registered")
	} else if plugin != mockPlugin {
		t.Error("registered plugin should be the same instance")
	}
}

func TestIdentityProfileDispatcher_getPlugin(t *testing.T) {
	dispatcher, err := NewIdentityProfileDispatcher()
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}
	mockPlugin := &mockIdentityProfilePlugin{}
	dispatcher.RegisterPlugin("test", mockPlugin)

	// Test existing plugin
	plugin, err := dispatcher.getPlugin("test")
	if err != nil {
		t.Errorf("getPlugin('test') should not return error: %v", err)
	}
	if plugin != mockPlugin {
		t.Error("getPlugin should return the registered plugin")
	}

	// Test non-existing plugin
	_, err = dispatcher.getPlugin("nonexistent")
	if err == nil {
		t.Error("getPlugin('nonexistent') should return an error")
	}
	expectedError := "identity profile type nonexistent operation get_plugin: unsupported profile type ID"
	if err.Error() != expectedError {
		t.Errorf("expected error message '%s', got '%s'", expectedError, err.Error())
	}
}

func TestIdentityProfileDispatcher_Create(t *testing.T) {
	dispatcher, err := NewIdentityProfileDispatcher()
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}
	mockPlugin := &mockIdentityProfilePlugin{}
	dispatcher.RegisterPlugin("test", mockPlugin)

	// Test with registered plugin
	profile, err := dispatcher.Create("test") // No options needed for mock
	if err != nil {
		t.Errorf("Create() should not return error: %v", err)
	}
	if profile == nil {
		t.Fatal("Create() should return a profile")
	}
	if profile.TypeID != "test" {
		t.Errorf("expected TypeID 'test', got '%s'", profile.TypeID)
	}

	// Test with unregistered plugin
	_, err = dispatcher.Create("unregistered") // No options needed for mock
	if err == nil {
		t.Error("Create() should return error for unregistered plugin")
	}
}

func TestManualPluginRegistration(t *testing.T) {
	dispatcher, err := NewIdentityProfileDispatcher()
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}
	mockPlugin1 := &mockIdentityProfilePlugin{}
	mockPlugin2 := &mockIdentityProfilePlugin{}

	// Manually register plugins
	dispatcher.RegisterPlugin("plugin1", mockPlugin1)
	dispatcher.RegisterPlugin("plugin2", mockPlugin2)

	// Check if both plugins were registered
	if len(dispatcher.plugins) != 2 {
		t.Errorf("expected 2 plugins registered, got %d", len(dispatcher.plugins))
	}

	if dispatcher.plugins["plugin1"] != mockPlugin1 {
		t.Error("plugin1 should be registered correctly")
	}

	if dispatcher.plugins["plugin2"] != mockPlugin2 {
		t.Error("plugin2 should be registered correctly")
	}
}

// Mock implementation for testing
type mockIdentityProfilePlugin struct{}

func (m *mockIdentityProfilePlugin) Create(opts ...types.CreateOption) (*types.IdentityProfile, error) {
	return &types.IdentityProfile{
		ID:     "test:profile:123",
		TypeID: "test",
		Keys:   nil,
	}, nil
}

func (m *mockIdentityProfilePlugin) Resolve(id string) (*types.IdentityProfile, error) {
	return &types.IdentityProfile{
		ID:     id,
		TypeID: "test",
		Keys:   nil,
	}, nil
}

func (m *mockIdentityProfilePlugin) Update(profile *types.IdentityProfile, opts ...types.UpdateOption) (*types.IdentityProfile, error) {
	return profile, nil
}

func (m *mockIdentityProfilePlugin) GetTypeID() string {
	return "test"
}

func (m *mockIdentityProfilePlugin) Validate(profile *types.IdentityProfile) error {
	return nil
}

// Tests for store functionality

func TestDispatcherWithStore(t *testing.T) {
	localStore := local.NewIDProfileLocalStore()
	dispatcher, err := NewIdentityProfileDispatcher(
		WithStore(localStore),
	)
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	if dispatcher == nil {
		t.Fatal("Dispatcher creation should not return nil")
	}

	if dispatcher.plugins == nil {
		t.Fatal("plugins map should not be nil")
	}

	// Test that store operations work (indirectly testing store is set)
	profile := &types.IdentityProfile{
		ID:     "test:store:check",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}

	err = dispatcher.SaveProfile(profile)
	if err != nil {
		t.Errorf("SaveProfile should work with configured store: %v", err)
	}

	retrieved, err := dispatcher.GetProfile(profile.ID)
	if err != nil {
		t.Errorf("GetProfile should work with configured store: %v", err)
	}
	if retrieved.ID != profile.ID {
		t.Errorf("expected ID '%s', got '%s'", profile.ID, retrieved.ID)
	}
}

func TestIdentityProfileDispatcher_StoreOperations(t *testing.T) {
	// Use WithDefaultConfig and WithStore for store operations
	localStore := local.NewIDProfileLocalStore()
	dispatcher, err := NewIdentityProfileDispatcher(
		WithDefaultConfig(),
		WithStore(localStore),
	)
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	profile := &types.IdentityProfile{
		ID:     "test:profile:store",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}

	// Test operations - should work with configured local store
	err = dispatcher.SaveProfile(profile)
	if err != nil {
		t.Errorf("SaveProfile() should not return error with configured store: %v", err)
	}

	// Test get
	retrieved, err := dispatcher.GetProfile(profile.ID)
	if err != nil {
		t.Errorf("GetProfile() should not return error with configured store: %v", err)
	}
	if retrieved.ID != profile.ID {
		t.Errorf("expected ID '%s', got '%s'", profile.ID, retrieved.ID)
	}

	// Test list
	profiles, err := dispatcher.ListProfiles()
	if err != nil {
		t.Errorf("ListProfiles() should not return error with configured store: %v", err)
	}
	if len(profiles) != 1 {
		t.Errorf("expected 1 profile, got %d", len(profiles))
	}

	// Test delete
	err = dispatcher.DeleteProfile(profile.ID)
	if err != nil {
		t.Errorf("DeleteProfile() should not return error with auto store: %v", err)
	}

	// Verify deletion
	profiles, err = dispatcher.ListProfiles()
	if err != nil {
		t.Errorf("ListProfiles() should not return error after deletion: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles after deletion, got %d", len(profiles))
	}
}

func TestIdentityProfileDispatcher_GetSupportedTypes(t *testing.T) {
	dispatcher, err := NewIdentityProfileDispatcher()
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	// Initially should have no types
	types := dispatcher.GetSupportedTypes()
	if len(types) != 0 {
		t.Error("GetSupportedTypes() should return empty slice initially")
	}

	// Register some mock plugins
	mockPlugin1 := &mockIdentityProfilePlugin{}
	mockPlugin2 := &mockIdentityProfilePlugin{}

	dispatcher.RegisterPlugin("type1", mockPlugin1)
	dispatcher.RegisterPlugin("type2", mockPlugin2)

	types = dispatcher.GetSupportedTypes()
	if len(types) != 2 {
		t.Errorf("GetSupportedTypes() should return 2 types, got %d", len(types))
	} // Check that both types are present
	typeMap := make(map[string]bool)
	for _, typeID := range types {
		typeMap[typeID] = true
	}

	if !typeMap["type1"] || !typeMap["type2"] {
		t.Error("GetSupportedTypes() should include both registered types")
	}
}

func TestIdentityProfileDispatcher_ConcurrentAccess(t *testing.T) {
	dispatcher, err := NewIdentityProfileDispatcher()
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	// Test concurrent registration and access
	done := make(chan bool, 10)

	// Start 5 goroutines registering plugins
	for i := 0; i < 5; i++ {
		go func(id int) {
			mockPlugin := &mockIdentityProfilePlugin{}
			dispatcher.RegisterPlugin(fmt.Sprintf("type%d", id), mockPlugin)
			done <- true
		}(i)
	}

	// Start 5 goroutines accessing plugins
	for i := 0; i < 5; i++ {
		go func(id int) {
			// Try to get a plugin (might not exist yet, that's ok)
			_, _ = dispatcher.getPlugin(fmt.Sprintf("type%d", id))
			// Get supported types
			_ = dispatcher.GetSupportedTypes()
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify final state
	types := dispatcher.GetSupportedTypes()
	if len(types) != 5 {
		t.Errorf("Expected 5 types registered, got %d", len(types))
	}
}

func TestDispatcherWithStoreConfiguration(t *testing.T) {
	localStore := local.NewIDProfileLocalStore()
	dispatcher, err := NewIdentityProfileDispatcher(
		WithStore(localStore),
	)
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	if dispatcher == nil {
		t.Fatal("Dispatcher creation should not return nil")
	}

	if dispatcher.plugins == nil {
		t.Fatal("plugins map should not be nil")
	}

	// Test that store operations work (indirectly testing store is set)
	profile := &types.IdentityProfile{
		ID:     "test:store:config",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}

	err = dispatcher.SaveProfile(profile)
	if err != nil {
		t.Errorf("SaveProfile should work with configured store: %v", err)
	}

	retrieved, err := dispatcher.GetProfile(profile.ID)
	if err != nil {
		t.Errorf("GetProfile should work with configured store: %v", err)
	}
	if retrieved.ID != profile.ID {
		t.Errorf("expected ID '%s', got '%s'", profile.ID, retrieved.ID)
	}
}

func TestIdentityProfileDispatcher_NoStoreError(t *testing.T) {
	dispatcher, err := NewIdentityProfileDispatcher()
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	profile := &types.IdentityProfile{
		ID:     "test:profile:no-store",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}

	// Test save - should return error when no store is configured
	err = dispatcher.SaveProfile(profile)
	if err == nil {
		t.Error("SaveProfile() should return error when no store is configured")
	}

	// Test get - should return error when no store is configured
	_, err = dispatcher.GetProfile(profile.ID)
	if err == nil {
		t.Error("GetProfile() should return error when no store is configured")
	}

	// Test delete - should return error when no store is configured
	err = dispatcher.DeleteProfile(profile.ID)
	if err == nil {
		t.Error("DeleteProfile() should return error when no store is configured")
	}

	// Test list - should return error when no store is configured
	_, err = dispatcher.ListProfiles()
	if err == nil {
		t.Error("ListProfiles() should return error when no store is configured")
	}
}

func TestIdentityProfileDispatcher_CreateAndSaveProfile(t *testing.T) {
	localStore := local.NewIDProfileLocalStore()
	dispatcher, err := NewIdentityProfileDispatcher(
		WithDefaultConfig(),
		WithStore(localStore),
	)
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyJWK := &jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "test-key-create-save",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	// Test create and save
	profile, err := dispatcher.Create("did",
		did.WithMethod("key"),
		did.WithPublicKey(publicKeyJWK),
	)
	if err != nil {
		t.Errorf("Create() should not return error: %v", err)
	}

	if profile == nil {
		t.Fatal("Create() should return a profile")
	}

	// Save the profile
	err = dispatcher.SaveProfile(profile)
	if err != nil {
		t.Errorf("SaveProfile() should not return error: %v", err)
	}

	// Verify profile was saved
	retrieved, err := dispatcher.GetProfile(profile.ID)
	if err != nil {
		t.Errorf("GetProfile() should not return error after save: %v", err)
	}
	if retrieved.ID != profile.ID {
		t.Errorf("expected ID '%s', got '%s'", profile.ID, retrieved.ID)
	}

	// Test create and save with another store
	localStore2 := local.NewIDProfileLocalStore()
	dispatcherNoStore, err := NewIdentityProfileDispatcher(
		WithDefaultConfig(),
		WithStore(localStore2),
	)
	if err != nil {
		t.Fatalf("NewIdentityProfileDispatcher() should not return error: %v", err)
	}

	profile2, err := dispatcherNoStore.Create("did",
		did.WithMethod("key"),
		did.WithPublicKey(publicKeyJWK),
	)
	if err != nil {
		t.Errorf("Create() should not return error: %v", err)
	}
	if profile2 == nil {
		t.Error("Create() should still return a profile")
	}

	// Save the profile
	err = dispatcherNoStore.SaveProfile(profile2)
	if err != nil {
		t.Errorf("SaveProfile() should not return error: %v", err)
	}
}

func TestIdentityProfileDispatcher_StoreIntegration(t *testing.T) {
	// Complete integration test
	localStore := local.NewIDProfileLocalStore()
	dispatcher, err := NewIdentityProfileDispatcher(
		WithDefaultConfig(),
		WithStore(localStore),
	)
	if err != nil {
		t.Fatalf("Configure() should not return error: %v", err)
	}

	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyJWK := &jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "test-key-integration",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	// 1. Create and save profile
	profile, err := dispatcher.Create("did",
		did.WithMethod("key"),
		did.WithPublicKey(publicKeyJWK),
	)
	if err != nil {
		t.Fatalf("Integration test failed at Create: %v", err)
	}

	err = dispatcher.SaveProfile(profile)
	if err != nil {
		t.Fatalf("Integration test failed at SaveProfile: %v", err)
	}

	// 2. List profiles
	profiles, err := dispatcher.ListProfiles()
	if err != nil {
		t.Errorf("Integration test failed at ListProfiles: %v", err)
	}
	if len(profiles) != 1 {
		t.Errorf("Integration test: expected 1 profile, got %d", len(profiles))
	}

	// 3. Get profile
	retrieved, err := dispatcher.GetProfile(profile.ID)
	if err != nil {
		t.Errorf("Integration test failed at GetProfile: %v", err)
	}
	if retrieved.ID != profile.ID {
		t.Errorf("Integration test: expected ID '%s', got '%s'", profile.ID, retrieved.ID)
	}

	// 4. Delete profile
	err = dispatcher.DeleteProfile(profile.ID)
	if err != nil {
		t.Errorf("Integration test failed at DeleteProfile: %v", err)
	}

	// 5. Verify deletion
	profiles, err = dispatcher.ListProfiles()
	if err != nil {
		t.Errorf("Integration test failed at final ListProfiles: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("Integration test: expected 0 profiles after deletion, got %d", len(profiles))
	}
}

func TestIdentityProfileDispatcher_Resolve(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		dispatcher.RegisterPlugin("hoge", &mockIdentityProfilePlugin{})
		expected := &IdentityProfile{
			ID:     "fuga",
			TypeID: "test",
			Keys:   nil,
		}
		got, err := dispatcher.Resolve("hoge", "fuga")
		if err != nil {
			t.Errorf("IdentityProfileDispatcher.Resolve() error = %v", err)
			return
		}
		if !reflect.DeepEqual(got, expected) {

		}
	})

	t.Run("Non-exist case", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		_, err = dispatcher.Resolve("hoge", "fuga")
		if err == nil {
			t.Errorf("IdentityProfileDispatcher.Resolve() should return error when plugin is not registerd.")
		}
	})

	t.Run("Non-exist case", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		_, err = dispatcher.Resolve("hoge", "fuga")
		if err == nil {
			t.Errorf("IdentityProfileDispatcher.Resolve() should return error when plugin is not registerd.")
		}
	})

	t.Run("Wrong arguments case", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		_, err = dispatcher.Resolve("", "fuga")
		if err == nil {
			t.Errorf("IdentityProfileDispatcher.Resolve() should return error when typeID/id is empty.")
		}
	})

	t.Run("Wrong arguments case", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		_, err = dispatcher.Resolve("hoge", "")
		if err == nil {
			t.Errorf("IdentityProfileDispatcher.Resolve() should return error when typeID/id is empty.")
		}
	})

}

func TestIdentityProfileDispatcher_Update(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		dispatcher.RegisterPlugin("hoge", &mockIdentityProfilePlugin{})
		profile := types.IdentityProfile{ID: "fuga", TypeID: "hoge"}
		result, err := dispatcher.Update(&profile)
		if err != nil {
			t.Errorf("Update failed: %v", err)
		}
		if !reflect.DeepEqual(result, &profile) {
			t.Errorf("IdentityProfileDispatcher.Update() = %v, want %v", result, &profile)
		}
	})

	t.Run("Non-exist plugin case", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		dispatcher.RegisterPlugin("hoge", &mockIdentityProfilePlugin{})
		profile := types.IdentityProfile{ID: "fuga", TypeID: "piyo"}
		_, err = dispatcher.Update(&profile)
		if err == nil {
			t.Errorf("IdentityProfileDispatcher.Update() should return error when plugin doesn't exist.")
		}
	})

	t.Run("Wrong argument case", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		dispatcher.RegisterPlugin("hoge", &mockIdentityProfilePlugin{})
		_, err = dispatcher.Update(nil)
		if err == nil {
			t.Errorf("IdentityProfileDispatcher.Update() should return error when profile argument is nil")
		}
	})
}

func TestIdentityProfileDispatcher_Validate(t *testing.T) {
	t.Run("Normal case", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		dispatcher.RegisterPlugin("hoge", &mockIdentityProfilePlugin{})
		profile := types.IdentityProfile{ID: "fuga", TypeID: "hoge"}
		err = dispatcher.Validate(&profile)
		if err != nil {
			t.Errorf("IdentityProfileDispatcher.Validate() return error %v", err)
		}
	})

	t.Run("Non-exist plugin", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		dispatcher.RegisterPlugin("hoge", &mockIdentityProfilePlugin{})
		profile := types.IdentityProfile{ID: "fuga", TypeID: "piyo"}
		err = dispatcher.Validate(&profile)
		if err == nil {
			t.Errorf("IdentityProfileDispatcher.Validate() should return error when plugin doesn't exist")
		}
	})

	t.Run("Wrong arguments", func(t *testing.T) {
		dispatcher, err := NewIdentityProfileDispatcher()
		if err != nil {
			t.Fatalf("NewIdentityProfileDispatcher() error: %v", err)
		}
		dispatcher.RegisterPlugin("hoge", &mockIdentityProfilePlugin{})
		err = dispatcher.Validate(nil)
		if err == nil {
			t.Errorf("IdentityProfileDispatcher.Validate() should return error when argument is nil")
		}
	})
}
