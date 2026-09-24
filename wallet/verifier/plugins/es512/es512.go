// Package es512 provides ES512 (ECDSA with P-521 and SHA-512) verification implementation
package es512

import (
	"crypto"
	"crypto/elliptic"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/internal/signature"
)

// ES512Verifier implements VerificationComponent for ES512 algorithm
type ES512Verifier struct{}

// NewES512Verifier creates a new ES512 verifier
func NewES512Verifier() *ES512Verifier {
	return &ES512Verifier{}
}

// Verify implements the VerificationComponent interface for ES512. The proof
// must name ES512, the public key must be an ECDSA key on P-521 and the
// signature must be the 132 byte R || S concatenation RFC 7518 Section 3.4
// defines for it.
func (v *ES512Verifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	return signature.ECDSA(proof, publicKey, jose.ES512, elliptic.P521(), crypto.SHA512)
}
