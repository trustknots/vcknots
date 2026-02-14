package local

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

func TestNewIDProfileLocalStore(t *testing.T) {
	store := NewIDProfileLocalStore()

	if store == nil {
		t.Fatal("NewIDProfileLocalStore() should not return nil")
	}

	if store.profiles == nil {
		t.Fatal("profiles map should not be nil")
	}

	if len(store.profiles) != 0 {
		t.Error("profiles map should be empty initially")
	}
}

func TestIDProfileLocalStore_Save(t *testing.T) {
	store := NewIDProfileLocalStore()

	profile := &types.IdentityProfile{
		ID:     "test:profile:123",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}

	// Test successful save
	err := store.Save(profile)
	if err != nil {
		t.Errorf("Save() should not return error: %v", err)
	}

	// Verify profile was saved
	if len(store.profiles) != 1 {
		t.Errorf("expected 1 profile, got %d", len(store.profiles))
	}

	if store.profiles[profile.ID] != profile {
		t.Error("saved profile should match the original")
	}

	// Test save with nil profile
	err = store.Save(nil)
	if err == nil {
		t.Error("Save() should return error for nil profile")
	}

	// Test save with empty ID
	emptyIDProfile := &types.IdentityProfile{
		ID:     "",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}
	err = store.Save(emptyIDProfile)
	if err == nil {
		t.Error("Save() should return error for empty ID")
	}
}

func TestIDProfileLocalStore_Get(t *testing.T) {
	store := NewIDProfileLocalStore()

	profile := &types.IdentityProfile{
		ID:     "test:profile:123",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}

	// Save profile first
	store.Save(profile)

	// Test successful get
	retrieved, err := store.Get(profile.ID)
	if err != nil {
		t.Errorf("Get() should not return error: %v", err)
	}
	if retrieved != profile {
		t.Error("retrieved profile should match the original")
	}

	// Test get with non-existent ID
	_, err = store.Get("nonexistent")
	if err == nil {
		t.Error("Get() should return error for non-existent ID")
	}

	// Test get with empty ID
	_, err = store.Get("")
	if err == nil {
		t.Error("Get() should return error for empty ID")
	}
}

func TestIDProfileLocalStore_Delete(t *testing.T) {
	store := NewIDProfileLocalStore()

	profile := &types.IdentityProfile{
		ID:     "test:profile:123",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}

	// Save profile first
	store.Save(profile)

	// Test successful delete
	err := store.Delete(profile.ID)
	if err != nil {
		t.Errorf("Delete() should not return error: %v", err)
	}

	// Verify profile was deleted
	if len(store.profiles) != 0 {
		t.Error("profile should be deleted")
	}

	// Test delete with non-existent ID
	err = store.Delete("nonexistent")
	if err == nil {
		t.Error("Delete() should return error for non-existent ID")
	}

	// Test delete with empty ID
	err = store.Delete("")
	if err == nil {
		t.Error("Delete() should return error for empty ID")
	}
}

func TestIDProfileLocalStore_List(t *testing.T) {
	store := NewIDProfileLocalStore()

	// Test empty list
	profiles, err := store.List()
	if err != nil {
		t.Errorf("List() should not return error: %v", err)
	}
	if len(profiles) != 0 {
		t.Error("list should be empty initially")
	}

	// Add some profiles
	profile1 := &types.IdentityProfile{
		ID:     "test:profile:1",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}
	profile2 := &types.IdentityProfile{
		ID:     "test:profile:2",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}

	store.Save(profile1)
	store.Save(profile2)

	// Test list with profiles
	profiles, err = store.List()
	if err != nil {
		t.Errorf("List() should not return error: %v", err)
	}
	if len(profiles) != 2 {
		t.Errorf("expected 2 profiles, got %d", len(profiles))
	}

	// Verify profiles are in the list
	foundProfile1 := false
	foundProfile2 := false
	for _, p := range profiles {
		if p.ID == profile1.ID {
			foundProfile1 = true
		}
		if p.ID == profile2.ID {
			foundProfile2 = true
		}
	}

	if !foundProfile1 {
		t.Error("profile1 should be in the list")
	}
	if !foundProfile2 {
		t.Error("profile2 should be in the list")
	}
}

func TestIDProfileLocalStore_Concurrency(t *testing.T) {
	store := NewIDProfileLocalStore()

	profile := &types.IdentityProfile{
		ID:     "test:profile:concurrent",
		TypeID: "test",
		Keys:   &jose.JSONWebKeySet{},
	}

	// Test concurrent operations
	done := make(chan bool, 2)

	// Concurrent saves
	go func() {
		for i := 0; i < 100; i++ {
			store.Save(profile)
		}
		done <- true
	}()

	// Concurrent gets
	go func() {
		for i := 0; i < 100; i++ {
			store.Get(profile.ID)
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// Verify final state
	retrieved, err := store.Get(profile.ID)
	if err != nil {
		t.Errorf("final Get() should not return error: %v", err)
	}
	if retrieved != profile {
		t.Error("final retrieved profile should match the original")
	}
}
