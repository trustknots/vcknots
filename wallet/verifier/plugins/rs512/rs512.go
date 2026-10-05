// Package rs512 provides RS512 (RSASSA-PKCS1-v1_5 with SHA-512) verification implementation
package rs512

import (
	"crypto"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/internal/signature"
)

// RS512Verifier implements VerificationComponent for RS512 algorithm
type RS512Verifier struct{}

// NewRS512Verifier creates a new RS512 verifier
func NewRS512Verifier() *RS512Verifier {
	return &RS512Verifier{}
}

// Verify implements the VerificationComponent interface for RS512. The proof
// must name RS512 and the public key must be an RSA key whose modulus is at
// least signature.MinimumRSAModulusBits bits, which RFC 7518 Section 3.3
// requires of RSASSA-PKCS1-v1_5.
func (v *RS512Verifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	return signature.RSAPKCS1v15(proof, publicKey, jose.RS512, crypto.SHA512)
}
