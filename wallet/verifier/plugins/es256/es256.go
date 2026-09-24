// Package es256 provides ES256 (ECDSA with P-256 and SHA-256) verification implementation
package es256

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/internal/signature"
)

// ES256Verifier implements VerificationComponent for ES256 algorithm
type ES256Verifier struct{}

// NewES256Verifier creates a new ES256 verifier
func NewES256Verifier() *ES256Verifier {
	return &ES256Verifier{}
}

// Verify implements the VerificationComponent interface for ES256. The proof
// must name ES256, the public key must be an ECDSA key on P-256 and the
// signature must be the 64 byte R || S concatenation RFC 7518 Section 3.4
// defines for it.
func (v *ES256Verifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	return signature.ECDSA(proof, publicKey, jose.ES256, elliptic.P256(), crypto.SHA256)
}
