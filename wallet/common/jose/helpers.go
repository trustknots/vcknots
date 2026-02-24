package jose

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/serializer/types"
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

// ParseAlgorithm converts an algorithm name string to the corresponding jose.SignatureAlgorithm.
// It returns the matching jose.SignatureAlgorithm for recognized names ("ES256", "ES384", "ES512", "EdDSA", "RS256").
// If algStr is not supported it returns an empty algorithm and an error wrapped with types.ErrUnsupportedAlgorithm.
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

// EqualPublicKey reports whether two JWKs represent the same public key
// EqualPublicKey reports whether two JSON Web Keys represent the same public key using RFC 7638 SHA-256 thumbprints.
// It computes each key's thumbprint with SHA-256 and returns true if the resulting thumbprints are identical.
// If computing a thumbprint for either key fails, it returns false and the wrapped error.
func EqualPublicKey(a, b jose.JSONWebKey) (bool, error) {
	tpA, err := a.Thumbprint(crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("failed to compute thumbprint: %w", err)
	}
	tpB, err := b.Thumbprint(crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("failed to compute thumbprint: %w", err)
	}
	return bytes.Equal(tpA, tpB), nil
}

// NewHashFromAlgorithm selects a hash.Hash implementation appropriate for the provided jose.SignatureAlgorithm.
// ES256 and RS256 use SHA-256; ES384 uses SHA-384; ES512 and EdDSA use SHA-512. If the algorithm is unrecognized, SHA-256 is used.
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
