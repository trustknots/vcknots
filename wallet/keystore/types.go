package keystore

import (
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Sentinel errors for keystore operations
var (
	ErrKeyNotFound          = errors.New("key not found")
	ErrInvalidKeyID         = errors.New("invalid key ID")
	ErrKeyExists            = errors.New("key already exists")
	ErrInvalidKeyEntry      = errors.New("invalid key entry")
	ErrKeyGenerationFailed  = errors.New("key generation failed")
	ErrSigningFailed        = errors.New("signing operation failed")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrUnsupportedAlgorithm = errors.New("unsupported key algorithm")
	ErrInvalidOptions       = errors.New("invalid key generation options")
	ErrStorageFailed        = errors.New("key storage operation failed")
	ErrKeyDeletionFailed    = errors.New("key deletion failed")
	ErrInvalidPublicKey     = errors.New("invalid public key")
	ErrInvalidPrivateKey    = errors.New("invalid private key")
	ErrPluginNotFound       = errors.New("keystore plugin not found")
	ErrNilPlugin            = errors.New("keystore plugin cannot be nil")
)

// KeyStoreError represents an error during keystore operations
type KeyStoreError struct {
	Algorithm jose.KeyAlgorithm `json:"algorithm,omitempty"`
	KeyID     string            `json:"key_id,omitempty"`
	Op        string            `json:"operation"`
	Err       error             `json:"error"`
}

func (e *KeyStoreError) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("keystore operation %s for key %s (algorithm: %s): %v", e.Op, e.KeyID, e.Algorithm, e.Err)
	}
	if e.Algorithm != "" {
		return fmt.Sprintf("keystore operation %s (algorithm: %s): %v", e.Op, e.Algorithm, e.Err)
	}
	return fmt.Sprintf("keystore operation %s: %v", e.Op, e.Err)
}

func (e *KeyStoreError) Unwrap() error {
	return e.Err
}

// NewKeyStoreError creates a new KeyStoreError
func NewKeyStoreError(algorithm jose.KeyAlgorithm, keyID, op string, err error) *KeyStoreError {
	return &KeyStoreError{
		Algorithm: algorithm,
		KeyID:     keyID,
		Op:        op,
		Err:       err,
	}
}
