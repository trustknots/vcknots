package jose

import (
	"fmt"
	"math/big"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/keystore"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// JWKSigner adapts KeyEntry to go-jose's signing interface
// It bridges the gap between our KeyEntry interface and go-jose's OpaqueSigner
type JWKSigner struct {
	keyEntry  keystore.KeyEntry
	algorithm jose.SignatureAlgorithm
}

// NewJWKSigner creates a new JWKSigner that adapts KeyEntry to go-jose
func NewJWKSigner(keyEntry keystore.KeyEntry, alg jose.SignatureAlgorithm) (*JWKSigner, error) {
	if keyEntry == nil {
		return nil, fmt.Errorf("keyEntry cannot be nil")
	}

	return &JWKSigner{
		keyEntry:  keyEntry,
		algorithm: alg,
	}, nil
}

// Public returns a pointer to the public key as JSONWebKey
// This method is required by go-jose's OpaqueSigner interface
func (s *JWKSigner) Public() *jose.JSONWebKey {
	jwk := s.keyEntry.PublicKey()
	return &jwk
}

// Algs returns the list of supported signature algorithms
// This method is required by go-jose's OpaqueSigner interface
func (s *JWKSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{s.algorithm}
}

// SignPayload implements the jose.OpaqueSigner interface
// It calls KeyEntry.Sign() and converts the signature format as needed
func (s *JWKSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	// Verify the requested algorithm matches our algorithm
	if alg != s.algorithm {
		return nil, fmt.Errorf("algorithm mismatch: requested %s, signer supports %s", alg, s.algorithm)
	}

	// Call the underlying KeyEntry.Sign method
	signature, err := s.keyEntry.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("keyEntry.Sign failed: %w", err)
	}

	// Convert signature format based on algorithm
	switch s.algorithm {
	case jose.ES256:
		// For ES256, go-jose expects raw IEEE P1363 format (r||s, 64 bytes)
		// KeyEntry.Sign() might return DER format, so convert if needed
		return ConvertDERToRaw(signature, 32)

	case jose.ES384:
		// For ES384, raw format is 96 bytes (48 bytes r + 48 bytes s)
		return ConvertDERToRaw(signature, 48)

	case jose.ES512:
		// For ES512, raw format is 132 bytes (66 bytes r + 66 bytes s)
		return ConvertDERToRaw(signature, 66)

	case jose.EdDSA:
		// EdDSA signatures are already in the correct format
		return signature, nil

	case jose.RS256, jose.RS384, jose.RS512:
		// RSA signatures are already in the correct format
		return signature, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", s.algorithm)
	}
}

// ConvertDERToRaw converts DER-encoded ECDSA signature to raw IEEE P1363 format
// DER format: SEQUENCE { INTEGER R, INTEGER S }
// Raw format: [R-bytes][S-bytes] with fixed length per component
//
// keySize is the size in bytes of each component (r and s)
// - ES256 (P-256): keySize = 32 bytes
// - ES384 (P-384): keySize = 48 bytes
// - ES512 (P-521): keySize = 66 bytes
func ConvertDERToRaw(derSig []byte, keySize int) ([]byte, error) {
	if len(derSig) < 8 {
		return nil, fmt.Errorf("DER signature too short: %d bytes", len(derSig))
	}

	// Raw IEEE P1363 signatures have a fixed length and can begin with 0x30 by
	// chance, so accept the raw length before using the DER sequence-tag heuristic.
	if len(derSig) == keySize*2 {
		return derSig, nil
	}

	// Check if it's DER format (starts with 0x30)
	if derSig[0] != 0x30 {
		return nil, fmt.Errorf("signature is not in DER format and length (%d) doesn't match expected raw format (%d)", len(derSig), keySize*2)
	}

	// P-521 signatures exceed 127 bytes, so their SEQUENCE length is long-form.
	// cryptobyte reads both length forms; a fixed 2-byte header skip cannot.
	var r, s big.Int
	var inner cryptobyte.String
	input := cryptobyte.String(derSig)
	if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) || !input.Empty() ||
		!inner.ReadASN1Integer(&r) || !inner.ReadASN1Integer(&s) || !inner.Empty() {
		return nil, fmt.Errorf("invalid DER format: expected a SEQUENCE of exactly two INTEGERs")
	}

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, fmt.Errorf("invalid DER signature: R and S must be positive")
	}

	// Get bytes (big.Int drops leading zeros) and pad with leading zeros if necessary
	rRaw := r.Bytes()
	sRaw := s.Bytes()
	if len(rRaw) > keySize || len(sRaw) > keySize {
		return nil, fmt.Errorf("DER signature components exceed key size %d: R=%d bytes, S=%d bytes", keySize, len(rRaw), len(sRaw))
	}

	// Convert to fixed-length raw format
	rawSig := make([]byte, keySize*2)

	// Copy R to first half, S to second half (right-aligned with zero padding)
	copy(rawSig[keySize-len(rRaw):keySize], rRaw)
	copy(rawSig[keySize*2-len(sRaw):keySize*2], sRaw)

	return rawSig, nil
}

// GetKeySizeForAlgorithm returns the key size in bytes for the given algorithm
func GetKeySizeForAlgorithm(alg jose.SignatureAlgorithm) (int, error) {
	switch alg {
	case jose.ES256:
		return 32, nil
	case jose.ES384:
		return 48, nil
	case jose.ES512:
		return 66, nil
	default:
		return 0, fmt.Errorf("key size not defined for algorithm: %s", alg)
	}
}
