package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/go-jose/go-jose/v4"
)

// jwkKeyEntry is a KeyEntry backed by an EC private key parsed from a JWK.
//
// Sign returns DER-encoded ASN.1 signatures. Callers that need JWS-compatible
// IEEE P1363 signatures should wrap the entry with JWKSigner, which normalizes
// the encoding.
type jwkKeyEntry struct {
	id      string
	privKey *ecdsa.PrivateKey
	pubJWK  jose.JSONWebKey
}

// NewKeyEntryFromJWK builds a signing KeyEntry from a JWK that carries private
// key material.
//
// Only EC keys on P-256, P-384 and P-521 are supported, matching the ES256,
// ES384 and ES512 algorithms defined in RFC 7518 section 3.4. The returned
// entry exposes only the public half through PublicKey, preserving the kid,
// use and alg parameters of the source JWK.
//
// It returns an error wrapping ErrInvalidPrivateKey when the JWK holds no
// private component, and ErrUnsupportedAlgorithm for key types or curves that
// cannot be used for signing.
func NewKeyEntryFromJWK(jwk jose.JSONWebKey) (KeyEntry, error) {
	op := "NewKeyEntryFromJWK"
	alg := jose.KeyAlgorithm(jwk.Algorithm)

	privKey, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		if _, isPublic := jwk.Key.(*ecdsa.PublicKey); isPublic {
			return nil, NewKeyStoreError(alg, jwk.KeyID, op,
				fmt.Errorf("JWK contains no private key material: %w", ErrInvalidPrivateKey))
		}
		return nil, NewKeyStoreError(alg, jwk.KeyID, op,
			fmt.Errorf("only EC private keys are supported for signing: %w", ErrUnsupportedAlgorithm))
	}

	if privKey.D == nil {
		return nil, NewKeyStoreError(alg, jwk.KeyID, op,
			fmt.Errorf("JWK contains no private key material: %w", ErrInvalidPrivateKey))
	}

	if _, err := hashForCurve(privKey.Curve); err != nil {
		return nil, NewKeyStoreError(alg, jwk.KeyID, op, err)
	}

	id := jwk.KeyID
	if id == "" {
		// RFC 7638 thumbprint keeps the entry identifiable even when the JWK
		// omits kid. PublicKey still reports the empty kid so that callers
		// requiring one (private_key_jwt) fail their own validation.
		thumbprint, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, NewKeyStoreError(alg, jwk.KeyID, op,
				fmt.Errorf("failed to compute key thumbprint: %w: %w", err, ErrInvalidKeyEntry))
		}
		id = base64.RawURLEncoding.EncodeToString(thumbprint)
	}

	return &jwkKeyEntry{
		id:      id,
		privKey: privKey,
		pubJWK: jose.JSONWebKey{
			Key:       &privKey.PublicKey,
			KeyID:     jwk.KeyID,
			Algorithm: jwk.Algorithm,
			Use:       jwk.Use,
		},
	}, nil
}

// NewKeyEntryFromJWKBytes parses a single JWK JSON document and delegates to
// NewKeyEntryFromJWK.
func NewKeyEntryFromJWKBytes(data []byte) (KeyEntry, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, NewKeyStoreError("", "", "NewKeyEntryFromJWKBytes",
			fmt.Errorf("failed to parse JWK: %w: %w", err, ErrInvalidKeyEntry))
	}
	return NewKeyEntryFromJWK(jwk)
}

// ID returns the key identifier, which is the JWK kid when present and the
// RFC 7638 thumbprint otherwise.
func (k *jwkKeyEntry) ID() string {
	return k.id
}

// PublicKey returns the public half of the key pair in JWK format.
func (k *jwkKeyEntry) PublicKey() jose.JSONWebKey {
	return k.pubJWK
}

// Sign hashes data with the digest paired with the key's curve and returns a
// DER-encoded ASN.1 ECDSA signature.
func (k *jwkKeyEntry) Sign(binary []byte) ([]byte, error) {
	op := "Sign"

	h, err := hashForCurve(k.privKey.Curve)
	if err != nil {
		return nil, NewKeyStoreError("", k.id, op, err)
	}
	if _, err := h.Write(binary); err != nil {
		return nil, NewKeyStoreError("", k.id, op,
			fmt.Errorf("failed to hash payload: %w: %w", err, ErrSigningFailed))
	}

	signature, err := ecdsa.SignASN1(rand.Reader, k.privKey, h.Sum(nil))
	if err != nil {
		return nil, NewKeyStoreError("", k.id, op,
			fmt.Errorf("failed to sign with ECDSA: %w: %w", err, ErrSigningFailed))
	}
	return signature, nil
}

// hashForCurve returns the digest that RFC 7518 section 3.4 pairs with the
// curve: SHA-256 for P-256 (ES256), SHA-384 for P-384 (ES384) and SHA-512 for
// P-521 (ES512).
func hashForCurve(curve elliptic.Curve) (hash.Hash, error) {
	if curve == nil || curve.Params() == nil {
		return nil, fmt.Errorf("EC key has no curve: %w", ErrInvalidPrivateKey)
	}

	switch curve.Params().Name {
	case elliptic.P256().Params().Name:
		return sha256.New(), nil
	case elliptic.P384().Params().Name:
		return sha512.New384(), nil
	case elliptic.P521().Params().Name:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported curve %q: %w", curve.Params().Name, ErrUnsupportedAlgorithm)
	}
}
