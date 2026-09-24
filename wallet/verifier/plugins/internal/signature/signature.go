// Package signature implements the cryptographic checks the bundled
// verification plugins share.
//
// Each plugin under wallet/verifier/plugins stays a package of its own, named
// after the JOSE algorithm it registers for, and holds the algorithm's
// parameters: its curve or key type, its digest and, for RSASSA-PSS, its mask
// generation function. The checks those parameters feed — the algorithm of the
// proof, the type of the key, the length of the signature and the verification
// itself — are written once here so that every algorithm the wallet accepts is
// checked the same way and only the standard library performs the mathematics.
package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-256 for crypto.Hash.New and RSA verification
	_ "crypto/sha512" // registers SHA-384 and SHA-512 for the same reason
	"fmt"
	"math/big"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/types"
)

// MinimumRSAModulusBits is the smallest RSA modulus the RSASSA plugins accept.
// RFC 7518 Section 3.3 states for RSASSA-PKCS1-v1_5, and Section 3.5 repeats
// for RSASSA-PSS, that "a key of size 2048 bits or larger MUST be used with
// these algorithms". A shorter key is refused rather than verified, so an
// issuer cannot downgrade the signature strength of a credential by presenting
// one.
const MinimumRSAModulusBits = 2048

// ECDSA verifies an ECDSA proof of algorithm with the curve and digest RFC 7518
// Section 3.4 binds to it. The signature is the fixed-width R || S
// concatenation of that section, never a DER SEQUENCE, and a key on another
// curve is rejected: the curve is part of the algorithm, so accepting one key
// for two algorithms would let a signature be verified under an algorithm its
// issuer never named.
func ECDSA(proof *credential.CredentialProof, publicKey *jose.JSONWebKey, algorithm jose.SignatureAlgorithm, curve elliptic.Curve, digest crypto.Hash) (bool, error) {
	if err := checkProof(proof, publicKey, algorithm); err != nil {
		return false, err
	}

	key, err := ecdsaPublicKey(publicKey, algorithm)
	if err != nil {
		return false, err
	}
	if key.Curve == nil || key.Curve.Params().Name != curve.Params().Name {
		return false, types.NewVerificationError(algorithm,
			fmt.Sprintf("invalid key curve: expected %s, got %s", curve.Params().Name, curveName(key.Curve)),
			types.ErrInvalidPublicKey)
	}

	componentSize := (curve.Params().BitSize + 7) / 8
	if len(proof.Signature) != componentSize*2 {
		return false, types.NewVerificationError(algorithm,
			fmt.Sprintf("invalid signature length: expected %d bytes, got %d", componentSize*2, len(proof.Signature)),
			types.ErrInvalidSignature)
	}

	hashed := hashPayload(digest, proof.Payload)
	r := new(big.Int).SetBytes(proof.Signature[:componentSize])
	s := new(big.Int).SetBytes(proof.Signature[componentSize:])
	if !ecdsa.Verify(key, hashed, r, s) {
		return false, types.NewVerificationError(algorithm, "signature verification failed", types.ErrVerificationFailed)
	}
	return true, nil
}

// RSAPKCS1v15 verifies an RSASSA-PKCS1-v1_5 proof (RFC 7518 Section 3.3) with
// the digest the algorithm names.
func RSAPKCS1v15(proof *credential.CredentialProof, publicKey *jose.JSONWebKey, algorithm jose.SignatureAlgorithm, digest crypto.Hash) (bool, error) {
	key, hashed, err := prepareRSA(proof, publicKey, algorithm, digest)
	if err != nil {
		return false, err
	}
	if err := rsa.VerifyPKCS1v15(key, digest, hashed, proof.Signature); err != nil {
		return false, types.NewVerificationError(algorithm, "signature verification failed", types.ErrVerificationFailed)
	}
	return true, nil
}

// RSAPSS verifies an RSASSA-PSS proof (RFC 7518 Section 3.5) with the digest
// the algorithm names, as MGF1 with that same digest and a salt as long as the
// digest output, which is what the section requires.
func RSAPSS(proof *credential.CredentialProof, publicKey *jose.JSONWebKey, algorithm jose.SignatureAlgorithm, digest crypto.Hash) (bool, error) {
	key, hashed, err := prepareRSA(proof, publicKey, algorithm, digest)
	if err != nil {
		return false, err
	}
	options := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: digest}
	if err := rsa.VerifyPSS(key, digest, hashed, proof.Signature, options); err != nil {
		return false, types.NewVerificationError(algorithm, "signature verification failed", types.ErrVerificationFailed)
	}
	return true, nil
}

// Ed25519 verifies an EdDSA proof (RFC 8037 Section 3.1) made with an Ed25519
// key. Ed448 is not accepted: the JOSE identifier is shared, so the key states
// which curve was used and only this one is implemented.
func Ed25519(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	if err := checkProof(proof, publicKey, jose.EdDSA); err != nil {
		return false, err
	}

	key, ok := publicKey.Key.(ed25519.PublicKey)
	if !ok {
		if pointer, isPointer := publicKey.Key.(*ed25519.PublicKey); isPointer && pointer != nil {
			key = *pointer
		} else {
			return false, types.NewVerificationError(jose.EdDSA,
				fmt.Sprintf("invalid key type: expected ed25519.PublicKey, got %T", publicKey.Key),
				types.ErrInvalidPublicKey)
		}
	}
	if len(key) != ed25519.PublicKeySize {
		return false, types.NewVerificationError(jose.EdDSA,
			fmt.Sprintf("invalid key length: expected %d bytes, got %d", ed25519.PublicKeySize, len(key)),
			types.ErrInvalidPublicKey)
	}
	if len(proof.Signature) != ed25519.SignatureSize {
		return false, types.NewVerificationError(jose.EdDSA,
			fmt.Sprintf("invalid signature length: expected %d bytes, got %d", ed25519.SignatureSize, len(proof.Signature)),
			types.ErrInvalidSignature)
	}
	if !ed25519.Verify(key, proof.Payload, proof.Signature) {
		return false, types.NewVerificationError(jose.EdDSA, "signature verification failed", types.ErrVerificationFailed)
	}
	return true, nil
}

// checkProof runs the checks every algorithm shares: the proof must exist and
// name the algorithm of the plugin it reached, the key must be present and the
// payload must not be empty.
func checkProof(proof *credential.CredentialProof, publicKey *jose.JSONWebKey, algorithm jose.SignatureAlgorithm) error {
	if proof == nil {
		return types.NewVerificationError(algorithm, "proof cannot be nil", types.ErrInvalidProof)
	}
	if proof.Algorithm != algorithm {
		return types.NewVerificationError(proof.Algorithm,
			fmt.Sprintf("algorithm mismatch: expected %s, got %s", algorithm, proof.Algorithm),
			types.ErrUnsupportedAlgorithm)
	}
	if publicKey == nil {
		return types.NewVerificationError(algorithm, "public key cannot be nil", types.ErrInvalidPublicKey)
	}
	if len(proof.Payload) == 0 {
		return types.NewVerificationError(algorithm, "payload cannot be empty", types.ErrInvalidPayload)
	}
	return nil
}

// prepareRSA resolves the RSA public key of a proof, enforces the minimum
// modulus and returns the digest of the payload.
func prepareRSA(proof *credential.CredentialProof, publicKey *jose.JSONWebKey, algorithm jose.SignatureAlgorithm, digest crypto.Hash) (*rsa.PublicKey, []byte, error) {
	if err := checkProof(proof, publicKey, algorithm); err != nil {
		return nil, nil, err
	}

	var key *rsa.PublicKey
	switch typed := publicKey.Key.(type) {
	case *rsa.PublicKey:
		key = typed
	case rsa.PublicKey:
		key = &typed
	default:
		return nil, nil, types.NewVerificationError(algorithm,
			fmt.Sprintf("invalid key type: expected *rsa.PublicKey, got %T", publicKey.Key),
			types.ErrInvalidPublicKey)
	}
	if key.N == nil {
		return nil, nil, types.NewVerificationError(algorithm, "RSA public key has no modulus", types.ErrInvalidPublicKey)
	}
	if bits := key.N.BitLen(); bits < MinimumRSAModulusBits {
		return nil, nil, types.NewVerificationError(algorithm,
			fmt.Sprintf("RSA modulus is %d bits, below the %d bit minimum", bits, MinimumRSAModulusBits),
			types.ErrInvalidPublicKey)
	}
	if len(proof.Signature) == 0 {
		return nil, nil, types.NewVerificationError(algorithm, "signature cannot be empty", types.ErrInvalidSignature)
	}
	return key, hashPayload(digest, proof.Payload), nil
}

// ecdsaPublicKey accepts the pointer and value forms a JWK may carry.
func ecdsaPublicKey(publicKey *jose.JSONWebKey, algorithm jose.SignatureAlgorithm) (*ecdsa.PublicKey, error) {
	switch typed := publicKey.Key.(type) {
	case *ecdsa.PublicKey:
		return typed, nil
	case ecdsa.PublicKey:
		return &typed, nil
	default:
		return nil, types.NewVerificationError(algorithm,
			fmt.Sprintf("invalid key type: expected *ecdsa.PublicKey, got %T", publicKey.Key),
			types.ErrInvalidPublicKey)
	}
}

func hashPayload(digest crypto.Hash, payload []byte) []byte {
	hasher := digest.New()
	hasher.Write(payload)
	return hasher.Sum(nil)
}

func curveName(curve elliptic.Curve) string {
	if curve == nil {
		return "none"
	}
	return curve.Params().Name
}
