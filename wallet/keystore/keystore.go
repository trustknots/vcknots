package keystore

import (
	"github.com/go-jose/go-jose/v4"
)

// CreateKeyPairOptions is an interface that defines options for key pair generation
type CreateKeyPairOptions interface {
	// The algorithm returns the cryptographic algorithm for the generated key
	Algorithm() jose.KeyAlgorithm
}

// KeyStorageComponent is an interface that synchronously manages the lifecycle of key pairs
type KeyStorageComponent interface {
	// GenerateKeyPair generates a new key pair and returns its storage ID
	GenerateKeyPair(opts CreateKeyPairOptions) (string, error)

	// GetKeyEntry retrieves the key entry with the specified ID
	GetKeyEntry(id string) (KeyEntry, error)

	// GetKeyEntries retrieves all key entries in the storage
	GetKeyEntries() ([]KeyEntry, error)

	// DeleteKeyEntry deletes the key entry with the specified ID
	DeleteKeyEntry(id string) error
}

// KeyEntry is an interface representing individual key-pair entries
type KeyEntry interface {
	// The ID returns a unique identifier for the key entry
	ID() string

	// PublicKey returns the public key of the key pair in JWK format
	PublicKey() jose.JSONWebKey

	// Sign the given data
	Sign(binary []byte) ([]byte, error)
}
