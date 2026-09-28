// Package ps384 provides PS384 (RSASSA-PSS with SHA-384) verification implementation
package ps384

import (
	"crypto"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/internal/signature"
)

// PS384Verifier implements VerificationComponent for PS384 algorithm
type PS384Verifier struct{}

// NewPS384Verifier creates a new PS384 verifier
func NewPS384Verifier() *PS384Verifier {
	return &PS384Verifier{}
}

// Verify implements the VerificationComponent interface for PS384. The proof
// must name PS384 and the public key must be an RSA key whose modulus is at
// least signature.MinimumRSAModulusBits bits, which RFC 7518 Section 3.5
// requires of RSASSA-PSS.
func (v *PS384Verifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	return signature.RSAPSS(proof, publicKey, jose.PS384, crypto.SHA384)
}
