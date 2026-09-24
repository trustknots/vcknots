// Package rs384 provides RS384 (RSASSA-PKCS1-v1_5 with SHA-384) verification implementation
package rs384

import (
	"crypto"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/internal/signature"
)

// RS384Verifier implements VerificationComponent for RS384 algorithm
type RS384Verifier struct{}

// NewRS384Verifier creates a new RS384 verifier
func NewRS384Verifier() *RS384Verifier {
	return &RS384Verifier{}
}

// Verify implements the VerificationComponent interface for RS384. The proof
// must name RS384 and the public key must be an RSA key whose modulus is at
// least signature.MinimumRSAModulusBits bits, which RFC 7518 Section 3.3
// requires of RSASSA-PKCS1-v1_5.
func (v *RS384Verifier) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	return signature.RSAPKCS1v15(proof, publicKey, jose.RS384, crypto.SHA384)
}
