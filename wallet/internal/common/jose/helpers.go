package jose

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/internal/credential"
	"github.com/trustknots/vcknots/wallet/internal/serializer/types"
)

// ReconstructJWT reconstructs a complete JWT string from a CredentialProof
// The proof contains:
// - Payload: "header.payload" (signing input)
// - Signature: raw signature bytes
//
// This function base64url-encodes the signature and concatenates to create:
// "header.payload.signature"
func ReconstructJWT(proof *credential.CredentialProof) string {
	if proof == nil {
		return ""
	}

	// Payload already contains "header.payload"
	// Encode signature using URL-safe base64 without padding
	sigEncoded := base64.RawURLEncoding.EncodeToString(proof.Signature)

	// Concatenate to form complete JWT
	return string(proof.Payload) + "." + sigEncoded
}

// ParseAlgorithm converts string algorithm to jose.SignatureAlgorithm
func ParseAlgorithm(algStr string) (jose.SignatureAlgorithm, error) {
	switch algStr {
	case "ES256":
		return jose.ES256, nil
	case "ES384":
		return jose.ES384, nil
	case "ES512":
		return jose.ES512, nil
	case "EdDSA":
		return jose.EdDSA, nil
	case "RS256":
		return jose.RS256, nil
	default:
		return "", fmt.Errorf("unsupported algorithm %s: %w", algStr, types.ErrUnsupportedAlgorithm)
	}
}

// NewHashFromAlgorithm returns a hash.Hash instance based on the given signature algorithm
func NewHashFromAlgorithm(alg jose.SignatureAlgorithm) hash.Hash {
	switch alg {
	case jose.ES256, jose.RS256:
		return sha256.New()
	case jose.ES384:
		return sha512.New384()
	case jose.ES512:
		return sha512.New()
	case jose.EdDSA:
		return sha512.New()
	default:
		return sha256.New()
	}
}
