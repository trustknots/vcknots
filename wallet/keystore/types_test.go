package keystore

import (
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestNewKeyStoreError(t *testing.T) {
	algorithm := jose.KeyAlgorithm(jose.ES256)
	keyID := "test-key-id"
	op := "test-operation"
	origErr := errors.New("original error")

	err := NewKeyStoreError(algorithm, keyID, op, origErr)

	if err.Algorithm != algorithm {
		t.Errorf("KeyStoreError.Algorithm = %v, want %v", err.Algorithm, algorithm)
	}
	if err.KeyID != keyID {
		t.Errorf("KeyStoreError.KeyID = %v, want %v", err.KeyID, keyID)
	}
	if err.Op != op {
		t.Errorf("KeyStoreError.Op = %v, want %v", err.Op, op)
	}
	if err.Err != origErr {
		t.Errorf("KeyStoreError.Err = %v, want %v", err.Err, origErr)
	}
}

func TestKeyStoreError_Error(t *testing.T) {
	algorithm := jose.KeyAlgorithm(jose.ES256)
	keyID := "test-key-id"
	op := "test-operation"
	origErr := errors.New("original error")

	err := NewKeyStoreError(algorithm, keyID, op, origErr)
	errorMsg := err.Error()

	// Check that error message contains each field
	expectedSubstrings := []string{
		string(algorithm),
		keyID,
		op,
		origErr.Error(),
	}
	for _, substr := range expectedSubstrings {
		if !contains(errorMsg, substr) {
			t.Errorf("KeyStoreError.Error() = %v, should contain %v", errorMsg, substr)
		}
	}
}

func TestKeyStoreError_Unwrap(t *testing.T) {
	origErr := errors.New("original error")
	err := NewKeyStoreError(jose.KeyAlgorithm(jose.ES256), "key-id", "operation", origErr)

	unwrapped := err.Unwrap()
	if unwrapped != origErr {
		t.Errorf("KeyStoreError.Unwrap() = %v, want %v", unwrapped, origErr)
	}
}

func TestPredefinedErrors(t *testing.T) {
	// Check existence of predefined error variables
	predefinedErrors := []error{
		ErrKeyNotFound,
		ErrInvalidKeyID,
		ErrKeyExists,
		ErrInvalidKeyEntry,
		ErrKeyGenerationFailed,
		ErrSigningFailed,
		ErrInvalidSignature,
		ErrUnsupportedAlgorithm,
		ErrInvalidOptions,
		ErrStorageFailed,
		ErrKeyDeletionFailed,
		ErrInvalidPublicKey,
		ErrInvalidPrivateKey,
		ErrPluginNotFound,
		ErrNilPlugin,
	}

	for i, err := range predefinedErrors {
		if err == nil {
			t.Errorf("predefined error %d is nil", i)
		}
		if err.Error() == "" {
			t.Errorf("predefined error %d has empty message", i)
		}
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && someContains(s, substr)))
}

func someContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}