// Package types provides common types and interfaces for verifier components
package types

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"

	"github.com/trustknots/vcknots/wallet/common"
)

// Sentinel errors for verification operations
var (
	ErrInvalidProof         = common.NewCodedError("verifier_invalid_proof", "invalid proof structure")
	ErrUnsupportedAlgorithm = common.NewCodedError("verifier_unsupported_algorithm", "unsupported verification algorithm")
	ErrInvalidPublicKey     = common.NewCodedError("verifier_invalid_public_key", "invalid public key")
	ErrInvalidSignature     = common.NewCodedError("verifier_invalid_signature", "invalid signature")
	ErrInvalidPayload       = common.NewCodedError("verifier_invalid_payload", "invalid payload")
	ErrVerificationFailed   = common.NewCodedError("verifier_verification_failed", "verification failed")
	ErrInvalidCredential    = common.NewCodedError("verifier_invalid_credential", "invalid credential")
	ErrExpiredCredential    = common.NewCodedError("verifier_expired_credential", "credential has expired")
	ErrPluginNotFound       = common.NewCodedError("verifier_plugin_not_found", "verifier plugin not found")
	ErrNilPlugin            = common.NewCodedError("verifier_nil_plugin", "verifier plugin cannot be nil")
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

// Error implements error.
func (e *VerificationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("verification error (algorithm: %s): %s: %v", e.Algorithm, e.Message, e.Cause)
	}
	return fmt.Sprintf("verification error (algorithm: %s): %s", e.Algorithm, e.Message)
}

// Unwrap returns the wrapped error.
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
