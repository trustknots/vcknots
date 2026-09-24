// Package jwtproof builds the JWTs a wallet signs with its own keys: RFC 9449
// DPoP proofs, OpenID4VCI key proofs, client attestation PoPs, RFC 7523 client
// assertions and self-issued attestations.
//
// Every builder signs through keystore.KeyEntry, so a key held in a hardware
// module never has to expose private material. A key that also implements
// keystore.ContextSigner is signed with the caller's context.
package jwtproof

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/trustknots/vcknots/wallet/common"
	joseutil "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/keystore"
)

// ErrProofAlgorithmNotSupported reports that the key cannot sign with any of
// the algorithms the Credential Issuer lists in
// proof_signing_alg_values_supported (OpenID4VCI 1.0 Appendix F.1).
var ErrProofAlgorithmNotSupported = common.NewCodedError("proof_algorithm_not_supported", "no proof signing algorithm shared with the issuer")

// Algorithm returns the JWS algorithm key signs with: PublicKey().Algorithm
// when set, otherwise the algorithm its curve implies (P-256, P-384 and P-521
// give ES256, ES384 and ES512; Ed25519 gives EdDSA). An RSA key must set its
// algorithm. A set algorithm the key cannot produce is an error.
func Algorithm(key keystore.KeyEntry) (jose.SignatureAlgorithm, error) {
	if key == nil {
		return "", errors.New("signing key is required")
	}
	public := key.PublicKey()
	if public.Algorithm == "" {
		return impliedAlgorithm(public.Key)
	}
	alg := jose.SignatureAlgorithm(public.Algorithm)
	if err := checkAlgorithm(public.Key, alg); err != nil {
		return "", err
	}
	return alg, nil
}

// SelectAlgorithm returns Algorithm(key) when supported lists it or is empty,
// and an error wrapping ErrProofAlgorithmNotSupported otherwise. Algorithm
// identifiers are compared as case-sensitive strings.
func SelectAlgorithm(key keystore.KeyEntry, supported []jose.SignatureAlgorithm) (jose.SignatureAlgorithm, error) {
	alg, err := Algorithm(key)
	if err != nil {
		return "", err
	}
	if len(supported) == 0 || slices.Contains(supported, alg) {
		return alg, nil
	}
	return "", fmt.Errorf("key signs with %s, the issuer accepts %v: %w", alg, supported, ErrProofAlgorithmNotSupported)
}

// Sign signs claims with key. header holds the protected header members
// besides "alg", which is alg, or Algorithm(key) when alg is empty. No member
// is added on the caller's behalf: in particular no "kid" is derived from the
// key.
func Sign(ctx context.Context, key keystore.KeyEntry, alg jose.SignatureAlgorithm, header map[string]any, claims map[string]any) (string, error) {
	if key == nil {
		return "", errors.New("signing key is required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if alg == "" {
		var err error
		if alg, err = Algorithm(key); err != nil {
			return "", err
		}
	} else if err := checkAlgorithm(key.PublicKey().Key, alg); err != nil {
		return "", err
	}
	adapter, err := joseutil.NewJWKSigner(contextKey{key: key, ctx: ctx}, alg)
	if err != nil {
		return "", err
	}
	options := &jose.SignerOptions{}
	for name, value := range header {
		if strings.EqualFold(name, "alg") {
			continue
		}
		options = options.WithHeader(jose.HeaderKey(name), value)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: adapter}, options)
	if err != nil {
		return "", fmt.Errorf("failed to create %s signer: %w", alg, err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}
	return token, nil
}

// contextKey routes signing to SignContext when the key supports it. Its
// public key has no kid, so go-jose never adds a kid header on its own.
type contextKey struct {
	key keystore.KeyEntry
	ctx context.Context
}

func (k contextKey) ID() string { return k.key.ID() }

func (k contextKey) PublicKey() jose.JSONWebKey {
	public := k.key.PublicKey()
	public.KeyID = ""
	return public
}

func (k contextKey) Sign(data []byte) ([]byte, error) {
	if signer, ok := k.key.(keystore.ContextSigner); ok {
		return signer.SignContext(k.ctx, data)
	}
	return k.key.Sign(data)
}

// PublicJWK returns the public half of key's JWK for a jwk or cnf member, with
// alg set to alg (or left as published when alg is empty) and use defaulting
// to "sig". It fails when the key publishes no valid public key.
func PublicJWK(key jose.JSONWebKey, alg jose.SignatureAlgorithm) (jose.JSONWebKey, error) {
	public := key.Public()
	if public.Key == nil || !public.Valid() {
		return jose.JSONWebKey{}, fmt.Errorf("key has no valid public key (%T)", key.Key)
	}
	public.Certificates = nil
	if alg != "" {
		public.Algorithm = string(alg)
	} else if public.Algorithm == "" {
		if implied, err := impliedAlgorithm(public.Key); err == nil {
			public.Algorithm = string(implied)
		}
	}
	if public.Use == "" {
		public.Use = "sig"
	}
	return public, nil
}

func impliedAlgorithm(key any) (jose.SignatureAlgorithm, error) {
	switch public := publicKeyOf(key).(type) {
	case *ecdsa.PublicKey:
		return curveAlgorithm(public.Curve)
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	case *rsa.PublicKey:
		return "", errors.New("an RSA key must set its algorithm (alg)")
	default:
		return "", fmt.Errorf("unsupported signing key type %T", key)
	}
}

// checkAlgorithm reports whether a key of this type can produce alg with the
// signature encodings keystore.KeyEntry implementations return.
func checkAlgorithm(key any, alg jose.SignatureAlgorithm) error {
	switch public := publicKeyOf(key).(type) {
	case *ecdsa.PublicKey:
		implied, err := curveAlgorithm(public.Curve)
		if err != nil {
			return err
		}
		if alg != implied {
			return fmt.Errorf("algorithm %s does not match the key's curve, which signs with %s", alg, implied)
		}
	case ed25519.PublicKey:
		if alg != jose.EdDSA {
			return fmt.Errorf("algorithm %s cannot be produced by an Ed25519 key", alg)
		}
	case *rsa.PublicKey:
		if alg != jose.RS256 && alg != jose.RS384 && alg != jose.RS512 {
			return fmt.Errorf("algorithm %s is not supported for an RSA key", alg)
		}
	default:
		return fmt.Errorf("unsupported signing key type %T", key)
	}
	return nil
}

func publicKeyOf(key any) any {
	switch typed := key.(type) {
	case ecdsa.PublicKey:
		return &typed
	case rsa.PublicKey:
		return &typed
	case crypto.Signer:
		return typed.Public()
	default:
		return key
	}
}

func curveAlgorithm(curve elliptic.Curve) (jose.SignatureAlgorithm, error) {
	switch curve {
	case elliptic.P256():
		return jose.ES256, nil
	case elliptic.P384():
		return jose.ES384, nil
	case elliptic.P521():
		return jose.ES512, nil
	default:
		return "", fmt.Errorf("unsupported elliptic curve %v", curve)
	}
}
