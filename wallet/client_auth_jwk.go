package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// ClientAuthJWKConfig is the JSON representation used to configure
// private_key_jwt client authentication.
//
// SigningKeyID is optional when jwks contains exactly one usable private ES256
// signing key. It is required to select the active key when multiple usable
// keys are present during key rotation.
type ClientAuthJWKConfig struct {
	ClientID                    string                                `json:"client_id"`
	TokenEndpointAuthMethod     receiverTypes.TokenEndpointAuthMethod `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg jose.SignatureAlgorithm               `json:"token_endpoint_auth_signing_alg,omitempty"`
	ClientAssertionAudience     string                                `json:"client_assertion_audience,omitempty"`
	SigningKeyID                string                                `json:"signing_key_id,omitempty"`
	JWKS                        jose.JSONWebKeySet                    `json:"jwks"`
}

type jwkKeyEntry struct {
	jwk        jose.JSONWebKey
	privateKey *ecdsa.PrivateKey
}

// ParseClientAuthJWKConfig parses a private_key_jwt client configuration and
// converts its selected private JWK into the Wallet signing-key abstraction.
func ParseClientAuthJWKConfig(data []byte) (ClientAuthConfig, error) {
	var input ClientAuthJWKConfig
	if err := json.Unmarshal(data, &input); err != nil {
		return ClientAuthConfig{}, fmt.Errorf("failed to parse client authentication JWK config: %w", err)
	}

	method := input.TokenEndpointAuthMethod
	if method == "" {
		method = receiverTypes.PrivateKeyJwt
	}
	if method != receiverTypes.PrivateKeyJwt {
		return ClientAuthConfig{}, fmt.Errorf("unsupported JWK client authentication method: %q", method)
	}
	if alg := input.TokenEndpointAuthSigningAlg; alg != "" && alg != jose.ES256 {
		return ClientAuthConfig{}, fmt.Errorf("unsupported private_key_jwt signing algorithm: %q", alg)
	}

	key, err := selectClientAuthJWK(input.JWKS.Keys, input.SigningKeyID)
	if err != nil {
		return ClientAuthConfig{}, err
	}

	config := ClientAuthConfig{
		Method:            method,
		ClientID:          input.ClientID,
		Key:               key,
		AssertionAudience: input.ClientAssertionAudience,
	}
	if err := validateClientAuthConfig(config); err != nil {
		return ClientAuthConfig{}, err
	}
	return config, nil
}

func selectClientAuthJWK(keys []jose.JSONWebKey, signingKeyID string) (*jwkKeyEntry, error) {
	var candidates []*jwkKeyEntry
	for _, key := range keys {
		if signingKeyID != "" && key.KeyID != signingKeyID {
			continue
		}
		entry, err := newJWKKeyEntry(key)
		if err != nil {
			continue
		}
		candidates = append(candidates, entry)
	}

	switch len(candidates) {
	case 0:
		if signingKeyID != "" {
			return nil, fmt.Errorf("no usable private ES256 signing key found for kid %q", signingKeyID)
		}
		return nil, fmt.Errorf("no usable private ES256 signing key found in jwks")
	case 1:
		return candidates[0], nil
	default:
		return nil, fmt.Errorf("multiple usable private ES256 signing keys found; signing_key_id is required")
	}
}

func newJWKKeyEntry(jwk jose.JSONWebKey) (*jwkKeyEntry, error) {
	privateKey, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok || privateKey == nil {
		return nil, fmt.Errorf("JWK must contain an EC private key")
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("JWK curve must be P-256")
	}
	if jwk.Algorithm != "" && jwk.Algorithm != string(jose.ES256) {
		return nil, fmt.Errorf("JWK alg must be ES256")
	}
	if jwk.Use != "" && !strings.EqualFold(jwk.Use, "sig") {
		return nil, fmt.Errorf("JWK use must be sig")
	}
	if strings.TrimSpace(jwk.KeyID) == "" {
		return nil, fmt.Errorf("JWK kid is required")
	}

	jwk.Algorithm = string(jose.ES256)
	jwk.Use = "sig"
	return &jwkKeyEntry{jwk: jwk, privateKey: privateKey}, nil
}

func (k *jwkKeyEntry) ID() string {
	return k.jwk.KeyID
}

func (k *jwkKeyEntry) PublicKey() jose.JSONWebKey {
	publicJWK := k.jwk.Public()
	publicJWK.Algorithm = k.jwk.Algorithm
	publicJWK.Use = k.jwk.Use
	publicJWK.KeyID = k.jwk.KeyID
	return publicJWK
}

func (k *jwkKeyEntry) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	signature, err := ecdsa.SignASN1(rand.Reader, k.privateKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign with client authentication key: %w", err)
	}
	return signature, nil
}
