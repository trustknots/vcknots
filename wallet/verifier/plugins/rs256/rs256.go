// Package rs256 provides RS256 (RSASSA-PKCS1-v1_5 with SHA-256) verification implementation
package rs256

import (
	"crypto"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/internal/signature"
)

// RS256Verifier implements VerificationComponent for RS256 algorithm
type RS256Verifier struct{}

// NewRS256Verifier creates a new RS256 verifier
func NewRS256Verifier() *RS256Verifier {
	return &RS256Verifier{}
}

// Verify implements the VerificationComponent interface for RS256. The proof
// must name RS256 and the public key must be an RSA key whose modulus is at
// least signature.MinimumRSAModulusBits bits, which RFC 7518 Section 3.3
// requires of RSASSA-PKCS1-v1_5.
func (v *RS256Verifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	return signature.RSAPKCS1v15(proof, publicKey, jose.RS256, crypto.SHA256)
}
