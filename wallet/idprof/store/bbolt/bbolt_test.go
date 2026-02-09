package bbolt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

func createTestProfile(id, typeID string) *types.IdentityProfile {
	// Generate a real ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err) // This is acceptable in test code
	}

	key := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "test-key-1",
		Algorithm: "ES256",
		Use:       "sig",
	}

	keySet := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{key},
	}

	return &types.IdentityProfile{
		ID:     id,
		TypeID: typeID,
		Keys:   keySet,
	}
}

func TestBBoltStore_TypeID(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	if got := store.TypeID(); got != "bbolt" {
		t.Errorf("TypeID() = %v, want %v", got, "bbolt")
	}
}

func TestBBoltStore_SaveAndGet(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	// Test profile
	profile := createTestProfile("test-id-1", "did")

	// Test Save
	err = store.Save(profile)
	if err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Test Get
	retrieved, err := store.Get("test-id-1")
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}

	if retrieved.ID != profile.ID {
		t.Errorf("Retrieved ID = %v, want %v", retrieved.ID, profile.ID)
	}
	if retrieved.TypeID != profile.TypeID {
		t.Errorf("Retrieved TypeID = %v, want %v", retrieved.TypeID, profile.TypeID)
	}
}

func TestBBoltStore_GetNonExistent(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	// Test Get non-existent profile
	_, err = store.Get("non-existent")
	if err == nil {
		t.Error("Expected error when getting non-existent profile, got nil")
	}
}

func TestBBoltStore_Delete(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	// Test profile
	profile := createTestProfile("test-id-1", "did")

	// Save profile
	err = store.Save(profile)
	if err != nil {
		t.Fatalf("Failed to save profile: %v", err)
	}

	// Delete profile
	err = store.Delete("test-id-1")
	if err != nil {
		t.Fatalf("Failed to delete profile: %v", err)
	}

	// Verify profile is deleted
	_, err = store.Get("test-id-1")
	if err == nil {
		t.Error("Expected error when getting deleted profile, got nil")
	}
}

func TestBBoltStore_DeleteNonExistent(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	// Test Delete non-existent profile
	err = store.Delete("non-existent")
	if err == nil {
		t.Error("Expected error when deleting non-existent profile, got nil")
	}
}

func TestBBoltStore_List(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	// Test profiles
	profile1 := createTestProfile("test-id-1", "did")
	profile2 := createTestProfile("test-id-2", "did")

	// Save profiles
	err = store.Save(profile1)
	if err != nil {
		t.Fatalf("Failed to save profile1: %v", err)
	}

	err = store.Save(profile2)
	if err != nil {
		t.Fatalf("Failed to save profile2: %v", err)
	}

	// List profiles
	profiles, err := store.List()
	if err != nil {
		t.Fatalf("Failed to list profiles: %v", err)
	}

	if len(profiles) != 2 {
		t.Errorf("Expected 2 profiles, got %d", len(profiles))
	}

	// Check IDs are present
	ids := make(map[string]bool)
	for _, p := range profiles {
		ids[p.ID] = true
	}

	if !ids["test-id-1"] {
		t.Error("Profile test-id-1 not found in list")
	}
	if !ids["test-id-2"] {
		t.Error("Profile test-id-2 not found in list")
	}
}

func TestBBoltStore_ListEmpty(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	// List profiles from empty store
	profiles, err := store.List()
	if err != nil {
		t.Fatalf("Failed to list profiles: %v", err)
	}

	if len(profiles) != 0 {
		t.Errorf("Expected 0 profiles, got %d", len(profiles))
	}
}

func TestBBoltStore_SaveNilProfile(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	// Test Save with nil profile
	err = store.Save(nil)
	if err == nil {
		t.Error("Expected error when saving nil profile, got nil")
	}
}

func TestBBoltStore_SaveEmptyID(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	// Test profile with empty ID
	profile := createTestProfile("", "did")

	// Test Save with empty ID
	err = store.Save(profile)
	if err == nil {
		t.Error("Expected error when saving profile with empty ID, got nil")
	}
}

func TestBBoltStore_GetEmptyID(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	// Test Get with empty ID
	_, err = store.Get("")
	if err == nil {
		t.Error("Expected error when getting profile with empty ID, got nil")
	}
}

func TestBBoltStore_DeleteEmptyID(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewBBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore: %v", err)
	}
	defer store.Close()

	// Test Delete with empty ID
	err = store.Delete("")
	if err == nil {
		t.Error("Expected error when deleting profile with empty ID, got nil")
	}
}

func TestNewBBoltStoreWithBucket(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	customBucket := "custom_bucket"

	store, err := NewBBoltStoreWithBucket(dbPath, customBucket)
	if err != nil {
		t.Fatalf("Failed to create BBoltStore with custom bucket: %v", err)
	}
	defer store.Close()

	// Test that the store works with custom bucket
	profile := createTestProfile("test-id-1", "did")
	err = store.Save(profile)
	if err != nil {
		t.Fatalf("Failed to save profile to custom bucket: %v", err)
	}

	retrieved, err := store.Get("test-id-1")
	if err != nil {
		t.Fatalf("Failed to get profile from custom bucket: %v", err)
	}

	if retrieved.ID != profile.ID {
		t.Errorf("Retrieved ID = %v, want %v", retrieved.ID, profile.ID)
	}
}
