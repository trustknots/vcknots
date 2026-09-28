// Package es384 provides ES384 (ECDSA with P-384 and SHA-384) verification implementation
package es384

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/internal/signature"
)

// ES384Verifier implements VerificationComponent for ES384 algorithm
type ES384Verifier struct{}

// NewES384Verifier creates a new ES384 verifier
func NewES384Verifier() *ES384Verifier {
	return &ES384Verifier{}
}

// Verify implements the VerificationComponent interface for ES384. The proof
// must name ES384, the public key must be an ECDSA key on P-384 and the
// signature must be the 96 byte R || S concatenation RFC 7518 Section 3.4
// defines for it.
func (v *ES384Verifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	return signature.ECDSA(proof, publicKey, jose.ES384, elliptic.P384(), crypto.SHA384)
}
