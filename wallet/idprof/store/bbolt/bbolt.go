// Package bbolt provides a BoltDB-based implementation of the IDProfileStore interface.
package bbolt

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/trustknots/vcknots/wallet/idprof/types"
	"go.etcd.io/bbolt"
)

const (
	// DefaultBucketName is the default bucket name for storing identity profiles
	DefaultBucketName = "identity_profiles"
	// DefaultDBName is the default database file name
	DefaultDBName = "idprofiles.db"
)

// BBoltStore implements IDProfileStore using BoltDB
type BBoltStore struct {
	db         *bbolt.DB
	bucketName []byte
}

// NewBBoltStore creates a new BBoltStore with the given database path
func NewBBoltStore(dbPath string) (*BBoltStore, error) {
	return NewBBoltStoreWithBucket(dbPath, DefaultBucketName)
}

// NewBBoltStoreWithBucket creates a new BBoltStore with the given database path and bucket name
func NewBBoltStoreWithBucket(dbPath, bucketName string) (*BBoltStore, error) {
	// Ensure the directory exists
	dir := filepath.Dir(dbPath)
	if dir != "." {
		// In a real implementation, you might want to create the directory
		// For now, we'll assume the directory exists
	}

	// Open the database
	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &BBoltStore{
		db:         db,
		bucketName: []byte(bucketName),
	}

	// Create the bucket if it doesn't exist
	err = store.initBucket()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize bucket: %w", err)
	}

	return store, nil
}

// initBucket creates the bucket if it doesn't exist
func (s *BBoltStore) initBucket() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(s.bucketName)
		return err
	})
}

// TypeID returns the type ID of the store
func (s *BBoltStore) TypeID() string {
	return "bbolt"
}

// Save stores the given ID profile
func (s *BBoltStore) Save(profile *types.IdentityProfile) error {
	if profile == nil {
		return fmt.Errorf("profile cannot be nil")
	}
	if profile.ID == "" {
		return fmt.Errorf("profile ID cannot be empty")
	}

	data, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(s.bucketName)
		if bucket == nil {
			return fmt.Errorf("bucket %s not found", s.bucketName)
		}
		return bucket.Put([]byte(profile.ID), data)
	})
}

// Get retrieves the ID profile with the given ID
func (s *BBoltStore) Get(id string) (*types.IdentityProfile, error) {
	if id == "" {
		return nil, fmt.Errorf("profile ID cannot be empty")
	}

	var profile *types.IdentityProfile
	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(s.bucketName)
		if bucket == nil {
			return fmt.Errorf("bucket %s not found", s.bucketName)
		}

		data := bucket.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("profile with ID %s not found", id)
		}

		profile = &types.IdentityProfile{}
		return json.Unmarshal(data, profile)
	})

	if err != nil {
		return nil, err
	}
	return profile, nil
}

// Delete removes the ID profile with the given ID
func (s *BBoltStore) Delete(id string) error {
	if id == "" {
		return fmt.Errorf("profile ID cannot be empty")
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(s.bucketName)
		if bucket == nil {
			return fmt.Errorf("bucket %s not found", s.bucketName)
		}

		// Check if the key exists
		if bucket.Get([]byte(id)) == nil {
			return fmt.Errorf("profile with ID %s not found", id)
		}

		return bucket.Delete([]byte(id))
	})
}

// List retrieves all stored ID profiles
func (s *BBoltStore) List() ([]*types.IdentityProfile, error) {
	var profiles []*types.IdentityProfile

	err := s.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(s.bucketName)
		if bucket == nil {
			return fmt.Errorf("bucket %s not found", s.bucketName)
		}

		return bucket.ForEach(func(k, v []byte) error {
			var profile types.IdentityProfile
			if err := json.Unmarshal(v, &profile); err != nil {
				return fmt.Errorf("failed to unmarshal profile %s: %w", k, err)
			}
			profiles = append(profiles, &profile)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}
	return profiles, nil
}

// Close closes the database connection
func (s *BBoltStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
