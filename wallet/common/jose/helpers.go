package jose

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

// acceptedSignatureAlgorithms backs AcceptedSignatureAlgorithms and
// ParseAlgorithm; it is never handed out.
var acceptedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

// AcceptedSignatureAlgorithms returns a copy of the JWS algorithms this
// library can verify: ES256/ES384/ES512 (RFC 7518 Section 3.4),
// RS256/RS384/RS512 (Section 3.3), PS256/PS384/PS512 (Section 3.5) and EdDSA
// (RFC 8037). The MAC algorithms and "none" are never included. Every other
// algorithm list in the library is derived from, or narrower than, this one.
func AcceptedSignatureAlgorithms() []jose.SignatureAlgorithm {
	return slices.Clone(acceptedSignatureAlgorithms)
}

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

// ParseAlgorithm returns algStr as a jose.SignatureAlgorithm when it is one of
// AcceptedSignatureAlgorithms, compared case-sensitively (RFC 7515 Section
// 4.1.1). Otherwise it returns an error wrapping types.ErrUnsupportedAlgorithm.
func ParseAlgorithm(algStr string) (jose.SignatureAlgorithm, error) {
	alg := jose.SignatureAlgorithm(algStr)
	if slices.Contains(acceptedSignatureAlgorithms, alg) {
		return alg, nil
	}
	return "", fmt.Errorf("unsupported algorithm %s: %w", algStr, types.ErrUnsupportedAlgorithm)
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
// ES256, RS256 and PS256 use SHA-256; ES384, RS384 and PS384 use SHA-384; ES512, RS512, PS512 and EdDSA use SHA-512.
// If the algorithm is unrecognized, SHA-256 is used.
func NewHashFromAlgorithm(alg jose.SignatureAlgorithm) hash.Hash {
	switch alg {
	case jose.ES256, jose.RS256, jose.PS256:
		return sha256.New()
	case jose.ES384, jose.RS384, jose.PS384:
		return sha512.New384()
	case jose.ES512, jose.RS512, jose.PS512:
		return sha512.New()
	case jose.EdDSA:
		return sha512.New()
	default:
		return sha256.New()
	}
}
