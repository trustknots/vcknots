// Package types provides common types and interfaces for verifier components
package types

import (
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
)

// Sentinel errors for verification operations
var (
	ErrInvalidProof         = errors.New("invalid proof structure")
	ErrUnsupportedAlgorithm = errors.New("unsupported verification algorithm")
	ErrInvalidPublicKey     = errors.New("invalid public key")
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrInvalidPayload       = errors.New("invalid payload")
	ErrVerificationFailed   = errors.New("verification failed")
	ErrInvalidCredential    = errors.New("invalid credential")
	ErrExpiredCredential    = errors.New("credential has expired")
	ErrPluginNotFound       = errors.New("verifier plugin not found")
	ErrNilPlugin            = errors.New("verifier plugin cannot be nil")
)

// VerificationComponent defines the interface for algorithm-specific verifiers
type VerificationComponent interface {
	Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error)
}

// Verifier defines the main verification interface
type Verifier interface {
	Verify(credential []byte, proof credential.CredentialProof) (bool, error)
}

// VerificationError represents an error during verification
type VerificationError struct {
	Algorithm jose.SignatureAlgorithm `json:"algorithm"`
	Message   string                  `json:"message"`
	Cause     error                   `json:"cause,omitempty"`
}

func (e *VerificationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("verification error (algorithm: %s): %s: %v", e.Algorithm, e.Message, e.Cause)
	}
	return fmt.Sprintf("verification error (algorithm: %s): %s", e.Algorithm, e.Message)
}

func (e *VerificationError) Unwrap() error {
	return e.Cause
}

// NewVerificationError creates a new VerificationError
func NewVerificationError(algorithm jose.SignatureAlgorithm, message string, cause error) *VerificationError {
	return &VerificationError{
		Algorithm: algorithm,
		Message:   message,
		Cause:     cause,
	}
}
