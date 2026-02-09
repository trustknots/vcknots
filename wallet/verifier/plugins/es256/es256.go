// Package es256 provides ES256 (ECDSA with P-256 and SHA-256) verification implementation
package es256

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/types"
)

// ES256Verifier implements VerificationComponent for ES256 algorithm
type ES256Verifier struct{}

// NewES256Verifier creates a new ES256 verifier
func NewES256Verifier() *ES256Verifier {
	return &ES256Verifier{}
}

// Verify implements the VerificationComponent interface for ES256
func (v *ES256Verifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	// Verify algorithm matches
	if proof.Algorithm != jose.ES256 {
		return false, types.NewVerificationError(proof.Algorithm,
			fmt.Sprintf("algorithm mismatch: expected ES256, got %s", proof.Algorithm),
			types.ErrUnsupportedAlgorithm)
	}

	if publicKey == nil {
		return false, types.NewVerificationError(proof.Algorithm, "public key cannot be nil", types.ErrInvalidPublicKey)
	}

	// Extract the ECDSA public key for cryptographic verification
	ecdsaKey, ok := publicKey.Key.(*ecdsa.PublicKey)
	if !ok {
		return false, types.NewVerificationError(proof.Algorithm,
			fmt.Sprintf("invalid key type: expected *ecdsa.PublicKey, got %T", publicKey.Key),
			types.ErrInvalidPublicKey)
	}

	// Validate payload
	if len(proof.Payload) == 0 {
		return false, types.NewVerificationError(proof.Algorithm, "payload cannot be empty", types.ErrInvalidPayload)
	}

	// Hash the payload using SHA-256 (crypto/sha256 - standard library)
	hash := sha256.Sum256(proof.Payload)

	// Validate signature format (r||s, 64 bytes for ES256)
	if len(proof.Signature) != 64 {
		return false, types.NewVerificationError(proof.Algorithm,
			fmt.Sprintf("invalid signature length: expected 64 bytes, got %d", len(proof.Signature)),
			types.ErrInvalidSignature)
	}

	// Parse signature components (r||s)
	r := new(big.Int).SetBytes(proof.Signature[:32])
	s := new(big.Int).SetBytes(proof.Signature[32:])

	// Verify signature using crypto/ecdsa (standard library)
	valid := ecdsa.Verify(ecdsaKey, hash[:], r, s)
	if !valid {
		return false, types.NewVerificationError(proof.Algorithm, "signature verification failed", types.ErrVerificationFailed)
	}

	return true, nil
}
