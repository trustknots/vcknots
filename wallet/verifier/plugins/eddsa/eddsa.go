// Package eddsa provides EdDSA (Ed25519, RFC 8037) verification implementation
package eddsa

import (
	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/internal/signature"
)

// EdDSAVerifier implements VerificationComponent for EdDSA algorithm
type EdDSAVerifier struct{}

// NewEdDSAVerifier creates a new EdDSA verifier
func NewEdDSAVerifier() *EdDSAVerifier {
	return &EdDSAVerifier{}
}

// Verify implements the VerificationComponent interface for EdDSA. The proof
// must name EdDSA and the public key must be an Ed25519 key: RFC 8037 Section
// 3.1 shares the identifier between Ed25519 and Ed448, and only Ed25519 is
// implemented, so a key of any other curve is rejected rather than guessed at.
// Ed25519 signs the payload itself, so nothing is pre-hashed here.
func (v *EdDSAVerifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	return signature.Ed25519(proof, publicKey)
}
