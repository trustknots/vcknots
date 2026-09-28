// Package ps512 provides PS512 (RSASSA-PSS with SHA-512) verification implementation
package ps512

import (
	"crypto"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/internal/signature"
)

// PS512Verifier implements VerificationComponent for PS512 algorithm
type PS512Verifier struct{}

// NewPS512Verifier creates a new PS512 verifier
func NewPS512Verifier() *PS512Verifier {
	return &PS512Verifier{}
}

// Verify implements the VerificationComponent interface for PS512. The proof
// must name PS512 and the public key must be an RSA key whose modulus is at
// least signature.MinimumRSAModulusBits bits, which RFC 7518 Section 3.5
// requires of RSASSA-PSS.
func (v *PS512Verifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	return signature.RSAPSS(proof, publicKey, jose.PS512, crypto.SHA512)
}
