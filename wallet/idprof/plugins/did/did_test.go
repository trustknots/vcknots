package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

// mockDIDMethodPlugin is a mock implementation of DIDMethodPlugin for testing

type mockDIDMethodPlugin struct {
	CreateFunc   func(opts ...types.CreateOption) (*types.IdentityProfile, error)
	ResolveFunc  func(id string) (*types.IdentityProfile, error)
	UpdateFunc   func(profile *types.IdentityProfile, opts ...types.UpdateOption) (*types.IdentityProfile, error)
	ValidateFunc func(profile *types.IdentityProfile) error
}

func (m *mockDIDMethodPlugin) Create(opts ...types.CreateOption) (*types.IdentityProfile, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(opts...)
	}
	return &types.IdentityProfile{ID: "did:mock:created"}, nil
}
func (m *mockDIDMethodPlugin) Resolve(id string) (*types.IdentityProfile, error) {
	if m.ResolveFunc != nil {
		return m.ResolveFunc(id)
	}
	return &types.IdentityProfile{ID: id}, nil
}
func (m *mockDIDMethodPlugin) Update(profile *types.IdentityProfile, opts ...types.UpdateOption) (*types.IdentityProfile, error) {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(profile, opts...)
	}
	return profile, nil
}
func (m *mockDIDMethodPlugin) Validate(profile *types.IdentityProfile) error {
	if m.ValidateFunc != nil {
		return m.ValidateFunc(profile)
	}
	return nil
}

func newTestPublicKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	return &jose.JSONWebKey{Key: &privateKey.PublicKey, Algorithm: string(jose.ES256)}
}

// Existing Tests

func TestNewDIDPlugin(t *testing.T) {
	plugin := NewDIDPlugin()
	if plugin == nil {
		t.Fatal("NewDIDPlugin() returned nil")
	}
	if _, exists := plugin.methodPlugins["key"]; !exists {
		t.Error("key method plugin should be registered by default")
	}
}

func TestDIDPlugin_Create(t *testing.T) {
	plugin := NewDIDPlugin()

	t.Run("Happy path", func(t *testing.T) {
		profile, err := plugin.Create(WithMethod("key"), WithPublicKey(newTestPublicKey(t)))
		if err != nil {
			t.Errorf("Create() should not return error: %v", err)
		}
		if profile == nil {
			t.Error("Create() should return a profile")
		}
	})

	t.Run("Missing method", func(t *testing.T) {
		_, err := plugin.Create()
		if err == nil {
			t.Error("Create() should return error when method is missing")
		}
	})

	t.Run("Option function fails", func(t *testing.T) {
		failingOption := func(c *types.CreateConfig) error {
			return errors.New("option failed")
		}
		_, err := plugin.Create(failingOption)
		if err == nil {
			t.Error("Create() should return error when an option fails")
		}
	})

	t.Run("Method is not a string", func(t *testing.T) {
		notStringOption := func(c *types.CreateConfig) error {
			c.Set("method", 123)
			return nil
		}
		_, err := plugin.Create(notStringOption)
		if err == nil {
			t.Error("Create() should return error when method is not a string")
		}
	})
}

func TestDIDPlugin_Resolve(t *testing.T) {
	plugin := NewDIDPlugin()
	mock := &mockDIDMethodPlugin{}
	plugin.RegisterMethodPlugin("mock", mock)

	t.Run("Happy path", func(t *testing.T) {
		did := "did:mock:1234"
		profile, err := plugin.Resolve(did)
		if err != nil {
			t.Errorf("Resolve() should not return error: %v", err)
		}
		if profile.ID != did {
			t.Errorf("expected ID %s, got %s", did, profile.ID)
		}
	})

	t.Run("Invalid DID format", func(t *testing.T) {
		_, err := plugin.Resolve("not-a-did")
		if err == nil {
			t.Error("Resolve() should return error for invalid DID format")
		}
	})

	t.Run("Unsupported DID method", func(t *testing.T) {
		_, err := plugin.Resolve("did:unsupported:123")
		if err == nil {
			t.Error("Resolve() should return error for unsupported DID method")
		}
	})
}

func TestDIDPlugin_Update(t *testing.T) {
	plugin := NewDIDPlugin()
	mock := &mockDIDMethodPlugin{}
	plugin.RegisterMethodPlugin("mock", mock)
	testProfile := &types.IdentityProfile{ID: "did:mock:123"}

	t.Run("Happy path", func(t *testing.T) {
		updatedProfile, err := plugin.Update(testProfile)
		if err != nil {
			t.Errorf("Update() should not return error: %v", err)
		}
		if !reflect.DeepEqual(updatedProfile, testProfile) {
			t.Error("Update() should return the same profile")
		}
	})

	t.Run("Nil profile", func(t *testing.T) {
		_, err := plugin.Update(nil)
		if err == nil {
			t.Error("Update() should return error for nil profile")
		}
	})

	t.Run("Invalid DID in profile", func(t *testing.T) {
		invalidProfile := &types.IdentityProfile{ID: "invalid-did"}
		_, err := plugin.Update(invalidProfile)
		if err == nil {
			t.Error("Update() should return error for profile with invalid DID")
		}
	})
}

func TestDIDPlugin_Validate(t *testing.T) {
	plugin := NewDIDPlugin()
	mock := &mockDIDMethodPlugin{}
	plugin.RegisterMethodPlugin("mock", mock)
	testProfile := &types.IdentityProfile{ID: "did:mock:123"}

	t.Run("Happy path", func(t *testing.T) {
		err := plugin.Validate(testProfile)
		if err != nil {
			t.Errorf("Validate() should not return error: %v", err)
		}
	})

	t.Run("Nil profile", func(t *testing.T) {
		err := plugin.Validate(nil)
		if err == nil {
			t.Error("Validate() should return error for nil profile")
		}
	})

	t.Run("Unsupported method in profile", func(t *testing.T) {
		unsupportedProfile := &types.IdentityProfile{ID: "did:unsupported:123"}
		err := plugin.Validate(unsupportedProfile)
		if err == nil {
			t.Error("Validate() should return error for profile with unsupported method")
		}
	})
}

func TestDIDPlugin_GetTypeID(t *testing.T) {
	plugin := NewDIDPlugin()
	if plugin.GetTypeID() != IDProfileTypeID {
		t.Errorf("GetTypeID() returned %s, want %s", plugin.GetTypeID(), IDProfileTypeID)
	}
}

func TestExtractDIDMethod(t *testing.T) {
	t.Run("Invalid format no prefix", func(t *testing.T) {
		_, err := extractDIDMethod("key:123")
		if err == nil {
			t.Error("expected error for missing 'did:' prefix")
		}
	})
	t.Run("Invalid format too few parts", func(t *testing.T) {
		_, err := extractDIDMethod("did:key")
		if err == nil {
			t.Error("expected error for too few parts")
		}
	})
}

// Additional Test
func TestNewDIDProfile(t *testing.T) {
	t.Run("Happy path with DIDKeyProfileCreateOptions", func(t *testing.T) {
		opts := DIDKeyProfileCreateOptions{
			DIDProfileCreateOptions: DIDProfileCreateOptions{Method: "key"},
			PublicKey:               newTestPublicKey(t),
		}
		profile, err := NewDIDProfile(IDProfileTypeID, opts)
		if err != nil {
			t.Errorf("NewDIDProfile() should not return an error: %v", err)
		}
		if profile == nil {
			t.Error("NewDIDProfile() should return a profile")
		}
	})

	t.Run("Unsupported type ID", func(t *testing.T) {
		_, err := NewDIDProfile("unsupported", nil)
		if err == nil {
			t.Error("NewDIDProfile() should return an error for unsupported type ID")
		}
	})

	t.Run("Invalid options type", func(t *testing.T) {
		_, err := NewDIDProfile(IDProfileTypeID, "not-a-struct")
		if err == nil {
			t.Error("NewDIDProfile() should return an error for invalid options type")
		}
	})

	t.Run("DIDKeyProfileCreateOptions with unsupported method", func(t *testing.T) {
		opts := DIDKeyProfileCreateOptions{
			DIDProfileCreateOptions: DIDProfileCreateOptions{Method: "unsupported"},
			PublicKey:               newTestPublicKey(t),
		}
		_, err := NewDIDProfile(IDProfileTypeID, opts)
		if err == nil {
			t.Error("NewDIDProfile() should return an error for unsupported method in DIDKeyProfileCreateOptions")
		}
	})

	t.Run("DIDProfileCreateOptions with key method", func(t *testing.T) {
		opts := DIDProfileCreateOptions{Method: "key"}
		_, err := NewDIDProfile(IDProfileTypeID, opts)
		if err == nil {
			t.Error("NewDIDProfile() should return an error when using DIDProfileCreateOptions with 'key' method")
		}
	})

	t.Run("DIDProfileCreateOptions with unsupported method", func(t *testing.T) {
		opts := DIDProfileCreateOptions{Method: "unsupported"}
		_, err := NewDIDProfile(IDProfileTypeID, opts)
		if err == nil {
			t.Error("NewDIDProfile() should return an error for unsupported method in DIDProfileCreateOptions")
		}
	})
}
