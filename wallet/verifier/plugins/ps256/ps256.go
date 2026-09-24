// Package ps256 provides PS256 (RSASSA-PSS with SHA-256) verification implementation
package ps256

import (
	"crypto"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/internal/signature"
)

// PS256Verifier implements VerificationComponent for PS256 algorithm
type PS256Verifier struct{}

// NewPS256Verifier creates a new PS256 verifier
func NewPS256Verifier() *PS256Verifier {
	return &PS256Verifier{}
}

// Verify implements the VerificationComponent interface for PS256. The proof
// must name PS256 and the public key must be an RSA key whose modulus is at
// least signature.MinimumRSAModulusBits bits, which RFC 7518 Section 3.5
// requires of RSASSA-PSS.
func (v *PS256Verifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	return signature.RSAPSS(proof, publicKey, jose.PS256, crypto.SHA256)
}
