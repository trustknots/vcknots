package keystore

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
)

// Sentinel errors for keystore operations
var (
	ErrKeyNotFound          = common.NewCodedError("keystore_key_not_found", "key not found")
	ErrInvalidKeyID         = common.NewCodedError("keystore_invalid_key_id", "invalid key ID")
	ErrKeyExists            = common.NewCodedError("keystore_key_exists", "key already exists")
	ErrInvalidKeyEntry      = common.NewCodedError("keystore_invalid_key_entry", "invalid key entry")
	ErrKeyGenerationFailed  = common.NewCodedError("keystore_key_generation_failed", "key generation failed")
	ErrSigningFailed        = common.NewCodedError("keystore_signing_failed", "signing operation failed")
	ErrInvalidSignature     = common.NewCodedError("keystore_invalid_signature", "invalid signature")
	ErrUnsupportedAlgorithm = common.NewCodedError("keystore_unsupported_algorithm", "unsupported key algorithm")
	ErrInvalidOptions       = common.NewCodedError("keystore_invalid_options", "invalid key generation options")
	ErrStorageFailed        = common.NewCodedError("keystore_storage_failed", "key storage operation failed")
	ErrKeyDeletionFailed    = common.NewCodedError("keystore_key_deletion_failed", "key deletion failed")
	ErrInvalidPublicKey     = common.NewCodedError("keystore_invalid_public_key", "invalid public key")
	ErrInvalidPrivateKey    = common.NewCodedError("keystore_invalid_private_key", "invalid private key")
	ErrPluginNotFound       = common.NewCodedError("keystore_plugin_not_found", "keystore plugin not found")
	ErrNilPlugin            = common.NewCodedError("keystore_nil_plugin", "keystore plugin cannot be nil")
)

// KeyStoreError represents an error during keystore operations
type KeyStoreError struct {
	Algorithm jose.KeyAlgorithm `json:"algorithm,omitempty"`
	KeyID     string            `json:"key_id,omitempty"`
	Op        string            `json:"operation"`
	Err       error             `json:"error"`
}

// Error implements error.
func (e *KeyStoreError) Error() string {
	if e.KeyID != "" {
		return fmt.Sprintf("keystore operation %s for key %s (algorithm: %s): %v", e.Op, e.KeyID, e.Algorithm, e.Err)
	}
	if e.Algorithm != "" {
		return fmt.Sprintf("keystore operation %s (algorithm: %s): %v", e.Op, e.Algorithm, e.Err)
	}
	return fmt.Sprintf("keystore operation %s: %v", e.Op, e.Err)
}

// Unwrap returns the wrapped error.
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
