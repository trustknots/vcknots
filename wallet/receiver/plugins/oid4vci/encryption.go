package oid4vci

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/internal/oid4vcijwe"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// CredentialResponseEncryptionParameters builds the OpenID4VCI 1.0 §8.2
// "credential_response_encryption" request parameter from the §12.2.4 issuer
// metadata and the wallet's public encryption key. §8.2 defines jwk, enc and
// zip. §10 requires the jwk to carry the alg the issuer encrypts with: the
// key's own alg, which must be listed in alg_values_supported, or else the
// first listed algorithm the key type can use. enc is the first advertised
// value this library can decrypt; zip is included only when
// zip_values_supported lists DEF. A missing key is an error when the issuer
// marks encryption_required true.
func CredentialResponseEncryptionParameters(metadata *types.CredentialIssuerMetadata, key *jose.JSONWebKey) (map[string]any, error) {
	if metadata == nil || metadata.CredentialResponseEncryption == nil {
		return nil, nil
	}
	encryption := metadata.CredentialResponseEncryption
	required := encryption.EncryptionRequired != nil && *encryption.EncryptionRequired
	if key == nil {
		if required {
			return nil, fmt.Errorf("credential response encryption is required but no encryption key was provided")
		}
		return nil, nil
	}

	alg, err := selectResponseEncryptionAlgorithm(key, encryption.AlgValuesSupported)
	if err != nil {
		return nil, err
	}
	enc, err := selectSupportedEnc(encryption.EncValuesSupported)
	if err != nil {
		return nil, fmt.Errorf("credential response encryption: %w", err)
	}

	publicKey := key.Public()
	publicKey.Algorithm = alg
	parameters := map[string]any{
		"jwk": publicKey,
		"enc": enc,
	}
	if containsZipDeflate(encryption.ZipValuesSupported) {
		parameters["zip"] = "DEF"
	}
	return parameters, nil
}

// requestCarriesResponseEncryption reports whether a marshalled credential or
// deferred credential request carries a non-empty credential_response_encryption
// member. The serialized form is inspected rather than the Go value so that a
// map body, a typed struct and a caller-supplied shape are all read the same way.
func requestCarriesResponseEncryption(payload []byte) bool {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(payload, &body); err != nil {
		return false
	}
	raw, present := body["credential_response_encryption"]
	if !present {
		return false
	}
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "{}":
		return false
	default:
		return true
	}
}

// selectResponseEncryptionAlgorithm resolves the JWE alg of the wallet's
// response encryption key: its own alg, or the first entry of algValues its
// key type can use. A non-empty algValues must list the result.
func selectResponseEncryptionAlgorithm(key *jose.JSONWebKey, algValues []string) (string, error) {
	if alg := strings.TrimSpace(key.Algorithm); alg != "" {
		if err := requireKeyEncryptionAlgorithm(key, alg); err != nil {
			return "", fmt.Errorf("credential response encryption: %w", err)
		}
		if len(algValues) > 0 && !slices.Contains(algValues, alg) {
			return "", fmt.Errorf("credential response encryption: key alg %q is not in the issuer's alg_values_supported %v", alg, algValues)
		}
		return alg, nil
	}
	if len(algValues) == 0 {
		alg, err := credentialRequestEncryptionAlgorithm(key)
		if err != nil {
			return "", fmt.Errorf("credential response encryption: %w", err)
		}
		return alg, nil
	}
	for _, alg := range algValues {
		if requireKeyEncryptionAlgorithm(key, alg) == nil {
			return alg, nil
		}
	}
	return "", fmt.Errorf("credential response encryption: the key cannot be used with any of the issuer's alg_values_supported %v", algValues)
}

// selectSupportedEnc returns the first enc value this library can use.
func selectSupportedEnc(encValues []string) (string, error) {
	for _, enc := range encValues {
		if enc == "" {
			continue
		}
		if _, err := parseJWEContentEncryption(enc); err == nil {
			return enc, nil
		}
	}
	return "", fmt.Errorf("issuer advertises no supported enc value in %v", encValues)
}

func containsZipDeflate(zipValues []string) bool {
	for _, value := range zipValues {
		if strings.EqualFold(strings.TrimSpace(value), "DEF") {
			return true
		}
	}
	return false
}

// selectEncryptionKey picks the Credential Request encryption key out of the
// Section 12.2.4 jwks. Section 10 leaves the choice to the Wallet: "In the case
// where multiple public keys are available, any may be selected based on the
// information about each key, such as the `kty` (Key Type), `use` (Public Key
// Use), `alg` (Algorithm), and other JWK parameters."
//
// A key published with use "sig" is never selected: RFC 7517 Section 4.2 makes
// "use" the key's intended use, and encrypting to a signature key is both
// outside that use and, for a key this wallet could otherwise encrypt to,
// harmful. Among the remaining keys the first one whose algorithm this wallet
// can actually perform wins, so that a JWKS mixing an unsupported key with a
// usable one still yields an encrypted request; only if none is usable does the
// first eligible key stand, so the caller reports the real algorithm error.
func selectEncryptionKey(jwks *jose.JSONWebKeySet) (*jose.JSONWebKey, error) {
	if jwks == nil || len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("encryption JWKS does not contain a key")
	}
	var firstEligible *jose.JSONWebKey
	for i := range jwks.Keys {
		key := &jwks.Keys[i]
		if key.Use == "sig" {
			continue
		}
		if firstEligible == nil {
			firstEligible = key
		}
		alg, err := credentialRequestEncryptionAlgorithm(key)
		if err != nil {
			continue
		}
		if _, err := parseJWEKeyAlgorithm(alg); err == nil {
			return key, nil
		}
	}
	if firstEligible != nil {
		return firstEligible, nil
	}
	return nil, fmt.Errorf("encryption JWKS contains no key usable for encryption")
}

// credentialRequestEncryptionAlgorithm resolves the JWE "alg" to encrypt a
// Credential Request with. Section 10 requires it to come from the chosen key:
// "The `alg` parameter MUST be present. The JWE `alg` algorithm used MUST be
// equal to the `alg` value of the chosen JWK."
//
// A Credential Issuer that publishes a key without "alg" is not conformant with
// that requirement, so rather than guess one algorithm for every key type the
// wallet derives the only key agreement or key encryption algorithm the key
// type admits: EC and OKP keys are used with ECDH-ES (RFC 7518 Section 4.6) and
// RSA keys with RSA-OAEP-256 (RFC 7518 Section 4.3). Any other key type - a
// symmetric "oct" key above all, which no Credential Issuer can publish as a
// public encryption key - is an error rather than a silent fallback.
func credentialRequestEncryptionAlgorithm(key *jose.JSONWebKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("credential request encryption key is missing")
	}
	alg := strings.TrimSpace(key.Algorithm)
	if alg == "" {
		switch key.Key.(type) {
		case *ecdsa.PublicKey, *ecdsa.PrivateKey:
			alg = "ECDH-ES"
		case *rsa.PublicKey, *rsa.PrivateKey:
			alg = "RSA-OAEP-256"
		case ed25519.PublicKey, ed25519.PrivateKey:
			return "", fmt.Errorf("encryption key %q is an Ed25519 signature key; ECDH-ES needs an EC key", key.KeyID)
		default:
			return "", fmt.Errorf(
				"encryption key %q omits the required alg parameter and its key type %T admits no default",
				key.KeyID, key.Key)
		}
	}
	if err := requireKeyEncryptionAlgorithm(key, alg); err != nil {
		return "", err
	}
	return alg, nil
}

// requireKeyEncryptionAlgorithm checks that alg is a key management algorithm
// this library performs and that the key's type can perform it: ECDH-ES needs
// an EC key (RFC 7518 Section 4.6), RSA-OAEP-256 an RSA key (Section 4.3).
// Ed25519 is a signature curve and is refused by name.
func requireKeyEncryptionAlgorithm(key *jose.JSONWebKey, alg string) error {
	if _, err := parseJWEKeyAlgorithm(alg); err != nil {
		return err
	}
	switch key.Key.(type) {
	case *ecdsa.PublicKey, *ecdsa.PrivateKey:
		if strings.HasPrefix(alg, "ECDH-ES") {
			return nil
		}
	case *rsa.PublicKey, *rsa.PrivateKey:
		if alg == "RSA-OAEP-256" {
			return nil
		}
	case ed25519.PublicKey, ed25519.PrivateKey:
		return fmt.Errorf("encryption key %q is an Ed25519 signature key; %s needs an EC key", key.KeyID, alg)
	}
	return fmt.Errorf("encryption key %q of type %T cannot be used with %s", key.KeyID, key.Key, alg)
}

// parseJWEKeyAlgorithm accepts a JWE "alg" from the oid4vcijwe allowlist.
func parseJWEKeyAlgorithm(alg string) (jose.KeyAlgorithm, error) {
	if keyAlg := jose.KeyAlgorithm(alg); slices.Contains(oid4vcijwe.KeyAlgorithms(), keyAlg) {
		return keyAlg, nil
	}
	return "", fmt.Errorf("unsupported encryption algorithm: %s", alg)
}

// parseJWEContentEncryption accepts a JWE "enc" from the oid4vcijwe allowlist.
func parseJWEContentEncryption(enc string) (jose.ContentEncryption, error) {
	if contentEnc := jose.ContentEncryption(enc); slices.Contains(oid4vcijwe.ContentEncryptions(), contentEnc) {
		return contentEnc, nil
	}
	return "", fmt.Errorf("unsupported encryption encoding: %s", enc)
}
