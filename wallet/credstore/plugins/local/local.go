package local

import (
	"errors"
	"fmt"

	"github.com/trustknots/vcknots/wallet/credstore/types"
	bolt "go.etcd.io/bbolt"
)

const bucketName = "CredentialStorage"

const (
	Local types.SupportedCredStoreTypes = iota
)

type LocalCredentialStorage struct {
	path string
}

func NewLocalCredentialStorage(path string) (*LocalCredentialStorage, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: false})
	if err != nil {
		return nil, err
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	})
	if err != nil {
		return nil, err
	}

	return &LocalCredentialStorage{path: path}, nil
}

func (l *LocalCredentialStorage) SaveCredentialEntry(credentialEntry types.CredentialEntry, location types.SupportedCredStoreTypes) error {
	if location != Local {
		return fmt.Errorf("locations is unexpected. expected = %v, actual = %v", Local, location)
	}
	db, err := bolt.Open(l.path, 0600, &bolt.Options{ReadOnly: false})
	if err != nil {
		return err
	}
	defer db.Close()

	serialized, err := credentialEntry.Serialize()
	if err != nil {
		return err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return errors.New("bucket not found")
		}
		err := b.Put([]byte(credentialEntry.Id), serialized)
		return err
	})
	return err
}

func (l *LocalCredentialStorage) GetCredentialEntries(offset int, limit *int, location types.SupportedCredStoreTypes) (*types.GetCredentialEntriesResult, error) {
	if location != Local {
		return nil, fmt.Errorf("locations is unexpected. expected = %v, actual = %v", Local, location)
	}
	db, err := bolt.Open(l.path, 0600, &bolt.Options{ReadOnly: false})
	if err != nil {
		return nil, err
	}
	defer db.Close()

	result := types.GetCredentialEntriesResult{}
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return errors.New("bucket not found")
		}

		var entries []types.CredentialEntry
		total := b.Stats().KeyN
		skipped := 0
		collected := 0

		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if skipped < offset {
				skipped++
				continue
			}
			if limit != nil && collected >= *limit {
				break
			}

			entry, err := types.ParseCredentialEntry(v)
			if err != nil {
				return err
			}
			entries = append(entries, entry)
			collected++
		}
		result.Entries = &entries
		result.TotalCount = &total
		return nil
	})

	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (l *LocalCredentialStorage) GetCredentialEntry(id string, location types.SupportedCredStoreTypes) (*types.CredentialEntry, error) {
	if location != Local {
		return nil, fmt.Errorf("locations is unexpected. expected = %v, actual = %v", Local, location)
	}
	db, err := bolt.Open(l.path, 0600, &bolt.Options{ReadOnly: false})
	if err != nil {
		return nil, err
	}
	defer db.Close()

	result := &types.CredentialEntry{}
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return errors.New("bucket not found")
		}
		data := b.Get([]byte(id))
		if data == nil {
			return errors.New("credential entry not found")
		}
		entry, err := types.ParseCredentialEntry(data)
		if err != nil {
			return err
		}
		result = &entry
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
