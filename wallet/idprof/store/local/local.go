// Package local provides an in-memory implementation of IDProfileStore
package local

import (
	"fmt"
	"sync"

	"github.com/trustknots/vcknots/wallet/idprof/types"
)

// IDProfileLocalStore provides an in-memory implementation of IDProfileStore
type IDProfileLocalStore struct {
	profiles map[string]*types.IdentityProfile
	mutex    sync.RWMutex
}

// NewIDProfileLocalStore creates a new local store instance
func NewIDProfileLocalStore() *IDProfileLocalStore {
	return &IDProfileLocalStore{
		profiles: make(map[string]*types.IdentityProfile),
	}
}

func (s *IDProfileLocalStore) Save(profile *types.IdentityProfile) error {
	if profile == nil {
		return fmt.Errorf("profile cannot be nil")
	}
	if profile.ID == "" {
		return fmt.Errorf("profile ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.profiles[profile.ID] = profile
	return nil
}

func (s *IDProfileLocalStore) Get(id string) (*types.IdentityProfile, error) {
	if id == "" {
		return nil, fmt.Errorf("profile ID cannot be empty")
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	profile, exists := s.profiles[id]
	if !exists {
		return nil, fmt.Errorf("profile with ID '%s' not found", id)
	}
	return profile, nil
}

func (s *IDProfileLocalStore) Delete(id string) error {
	if id == "" {
		return fmt.Errorf("profile ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.profiles[id]; !exists {
		return fmt.Errorf("profile with ID '%s' not found", id)
	}

	delete(s.profiles, id)
	return nil
}

func (s *IDProfileLocalStore) List() ([]*types.IdentityProfile, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	profiles := make([]*types.IdentityProfile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		profiles = append(profiles, profile)
	}

	return profiles, nil
}

// TypeID returns the type ID of the store
func (s *IDProfileLocalStore) TypeID() string {
	return "local"
}
