package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// encryptAuthorizationResponseJWE encrypts payload as an OID4VP 1.0 §8.3
// authorization response JWE. Metadata of a parsed request is encrypted under
// the rules that request was admitted with, so a Draft24 request is not held
// to HAIP after consent; other metadata follows the presenter's profile.
func (p *Oid4vpPresenter) encryptAuthorizationResponseJWE(payloadBytes []byte, metadata *VerifierMetadata) (string, error) {
	haip := p.Profile.IsHAIP()
	if metadata != nil && metadata.encryptionPolicy != encryptionPolicyUnset {
		haip = metadata.encryptionPolicy == encryptionPolicyHAIP
	}
	return encryptAuthorizationResponse(payloadBytes, metadata, haip)
}

// encryptAuthorizationResponse selects a usable Verifier encryption key and
// encrypts payload as an OID4VP 1.0 §8.3 authorization response JWE, applying
// the HAIP rules when haip is set.
func encryptAuthorizationResponse(payloadBytes []byte, metadata *VerifierMetadata, haip bool) (string, error) {
	selection, err := selectResponseEncryptionForProfile(metadata, haip)
	if err != nil {
		return "", err
	}

	options := (&jose.EncrypterOptions{}).WithContentType("json")
	encrypter, err := jose.NewEncrypter(
		selection.enc,
		jose.Recipient{
			Algorithm: selection.alg,
			Key:       selection.key.Key,
			KeyID:     selection.key.KeyID,
		},
		options,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt authorization response: %w", err)
	}

	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize authorization response JWE: %w", err)
	}

	return serialized, nil
}

// responseEncryption is the selected verifier key agreement and content
// encryption for one authorization response.
type responseEncryption struct {
	key *jose.JSONWebKey
	alg jose.KeyAlgorithm
	enc jose.ContentEncryption
}

// jweContentEncryptions are the content encryption algorithms the library
// supports. HAIP permits only A128GCM and A256GCM (HAIP §5).
var (
	jweContentEncryptions = map[string]jose.ContentEncryption{
		"A128GCM":       jose.A128GCM,
		"A192GCM":       jose.A192GCM,
		"A256GCM":       jose.A256GCM,
		"A128CBC-HS256": jose.A128CBC_HS256,
		"A192CBC-HS384": jose.A192CBC_HS384,
		"A256CBC-HS512": jose.A256CBC_HS512,
	}
	haipJWEOnlyContentEncryptions = map[string]jose.ContentEncryption{
		"A128GCM": jose.A128GCM,
		"A256GCM": jose.A256GCM,
	}
	// walletContentEncryptionPreference is this wallet's own order of
	// preference for the content encryption of an Authorization Response.
	// HAIP §5, which governs both the redirect profile of §5.1 and the DC API
	// profile of §5.2: "Wallets MUST support `A128GCM` or `A256GCM`, or both.
	// If both are supported, the Wallet SHOULD use `A256GCM` for the JWE
	// `enc`." The strongest AEAD therefore comes first, and the AES-CBC-HMAC
	// variants trail behind the AEADs; under HAIP they are filtered out by
	// haipJWEOnlyContentEncryptions.
	walletContentEncryptionPreference = []string{
		"A256GCM", "A192GCM", "A128GCM",
		"A256CBC-HS512", "A192CBC-HS384", "A128CBC-HS256",
	}
)

// selectResponseEncryptionForProfile applies OID4VP 1.0 §8.3 and RFC 7517 §5
// key selection, and with haip the HAIP §5 combination: ECDH-ES on P-256 with
// A128GCM or A256GCM. Parsing a request and encrypting its response share it.
// A failure wraps ErrResponseEncryptionKeyUnusable or
// ErrResponseEncryptionEncUnsupported.
func selectResponseEncryptionForProfile(metadata *VerifierMetadata, haip bool) (*responseEncryption, error) {
	if metadata == nil {
		return nil, fmt.Errorf("verifier metadata is required for encrypted authorization response: %w", ErrResponseEncryptionKeyMissing)
	}
	allowedEncryptions := jweContentEncryptions
	if haip {
		allowedEncryptions = haipJWEOnlyContentEncryptions
	}

	key := selectUsableVerifierEncryptionKey(&metadata.Jwks, haip, metadata.AuthorizationEncryptedResponseAlg)
	if key == nil {
		return nil, fmt.Errorf("no usable verifier encryption key in client_metadata.jwks: %w", ErrResponseEncryptionKeyUnusable)
	}

	// The key's own alg wins, then authorization_encrypted_response_alg, then
	// ECDH-ES.
	algName := key.Algorithm
	if algName == "" {
		algName = metadata.AuthorizationEncryptedResponseAlg
	}
	if algName == "" {
		algName = "ECDH-ES"
	}
	if haip && algName != "ECDH-ES" {
		return nil, fmt.Errorf("HAIP profile requires ECDH-ES for response encryption, got %q: %w", algName, ErrResponseEncryptionKeyUnusable)
	}
	alg, err := parseJWEKeyAlgorithm(algName)
	if err != nil {
		return nil, err
	}

	var enc jose.ContentEncryption
	if len(metadata.EncryptedResponseEncValuesSupported) > 0 {
		offered := make(map[string]bool, len(metadata.EncryptedResponseEncValuesSupported))
		for _, candidate := range metadata.EncryptedResponseEncValuesSupported {
			offered[candidate] = true
		}
		// The wallet's own preference order decides, not the verifier's list
		// order (HAIP §5: "If both are supported, the Wallet SHOULD use
		// `A256GCM`"; §5 also requires Verifiers to list both).
		for _, preferred := range walletContentEncryptionPreference {
			value, supported := allowedEncryptions[preferred]
			if !supported || !offered[preferred] {
				continue
			}
			enc = value
			break
		}
		if enc == "" {
			// §8.3 default does not rescue an explicit list with no usable
			// value; the verifier offered only unsupported algorithms.
			return nil, fmt.Errorf("encrypted_response_enc_values_supported has no supported content encryption: %w", ErrResponseEncryptionEncUnsupported)
		}
	} else {
		// §8.3: absent list defaults to A128GCM.
		enc = jose.A128GCM
	}

	return &responseEncryption{key: key, alg: alg, enc: enc}, nil
}

// selectUsableVerifierEncryptionKey iterates client_metadata.jwks.keys in order
// and returns the first key usable for response encryption, skipping unusable
// keys silently (RFC 7517 §5, "ignore unusable keys").
func selectUsableVerifierEncryptionKey(set *jose.JSONWebKeySet, haip bool, legacyAlg string) *jose.JSONWebKey {
	if set == nil {
		return nil
	}
	for i := range set.Keys {
		key := &set.Keys[i]
		if usableVerifierEncryptionKey(key, haip, legacyAlg) {
			return key
		}
	}
	return nil
}

// usableVerifierEncryptionKey reports whether key supports ECDH-ES response
// encryption. use must be "enc" or empty, the key must be EC (P-256, plus
// P-384/P-521 under Final only) and alg must be present (OID4VP 1.0 §8.3:
// "The `alg` parameter MUST be present in the JWKs.") and a supported key
// agreement algorithm.
func usableVerifierEncryptionKey(key *jose.JSONWebKey, haip bool, legacyAlg string) bool {
	if key == nil || key.Key == nil {
		return false
	}
	if key.Use != "" && key.Use != "enc" {
		return false
	}
	publicKey, ok := key.Key.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	switch publicKey.Curve {
	case elliptic.P256():
	case elliptic.P384(), elliptic.P521():
		if haip {
			return false
		}
	default:
		return false
	}
	algName := key.Algorithm
	if algName == "" {
		// OID4VP 1.0 §8.3 requires alg on every JWK used for encryption. A
		// verifier that still advertises the draft-era
		// authorization_encrypted_response_alg member instead is accepted on the
		// Final profile for interoperability; HAIP keeps the strict rule.
		if haip || legacyAlg == "" {
			return false
		}
		algName = legacyAlg
	}
	if _, err := parseJWEKeyAlgorithm(algName); err != nil {
		return false
	}
	if haip && algName != "ECDH-ES" {
		return false
	}
	return true
}

// verifierEncryptionRequested reports whether client_metadata asks for an
// encrypted authorization response. In the Final flow the direct_post.jwt
// response mode is the only one that carries response-encryption metadata.
func verifierEncryptionRequested(metadata *VerifierMetadata) bool {
	if metadata == nil {
		return false
	}
	return len(metadata.Jwks.Keys) > 0 ||
		len(metadata.EncryptedResponseEncValuesSupported) > 0 ||
		metadata.AuthorizationEncryptedResponseAlg != "" ||
		metadata.AuthorizationEncryptedResponseEnc != ""
}

// createJARMResponse creates the encrypted JWE authorization response for a
// direct_post.jwt request, embedding vp_token and state.
func (p *Oid4vpPresenter) createJARMResponse(vpTokenJSON []byte, state string, metadata *VerifierMetadata) (string, error) {
	// vp_token is embedded as a JSON object.
	payload := map[string]interface{}{
		"vp_token": json.RawMessage(vpTokenJSON),
	}
	if state != "" {
		payload["state"] = state
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal authorization response payload: %w", err)
	}
	return p.encryptAuthorizationResponseJWE(payloadBytes, metadata)
}
func (p *Oid4vpPresenter) encryptJARMPayload(payload map[string]interface{}, encAlg, encEnc string, verifierJWKS *jose.JSONWebKeySet) (string, error) {
	// Marshal payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JARM payload: %w", err)
	}

	encryptionKey, err := selectVerifierEncryptionKey(verifierJWKS)
	if err != nil {
		return "", err
	}

	keyAlg, err := parseJWEKeyAlgorithm(encAlg)
	if err != nil {
		return "", err
	}
	contentEnc, err := parseJWEContentEncryption(encEnc)
	if err != nil {
		return "", err
	}

	// Create encrypter
	encrypter, err := jose.NewEncrypter(
		contentEnc,
		jose.Recipient{
			Algorithm: keyAlg,
			Key:       encryptionKey.Key,
			KeyID:     encryptionKey.KeyID,
		},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	// Encrypt the payload
	jwe, err := encrypter.Encrypt(payloadBytes)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt JARM payload: %w", err)
	}

	// Serialize to compact form
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE: %w", err)
	}

	return serialized, nil
}
func selectVerifierEncryptionKey(verifierJWKS *jose.JSONWebKeySet) (*jose.JSONWebKey, error) {
	if verifierJWKS == nil || len(verifierJWKS.Keys) == 0 {
		return nil, fmt.Errorf("verifier JWKS not available for encryption")
	}

	for i := range verifierJWKS.Keys {
		key := &verifierJWKS.Keys[i]
		if key.Use == "enc" {
			return key, nil
		}
	}

	return &verifierJWKS.Keys[0], nil
}
func parseJWEKeyAlgorithm(alg string) (jose.KeyAlgorithm, error) {
	switch alg {
	case "ECDH-ES":
		return jose.ECDH_ES, nil
	case "ECDH-ES+A128KW":
		return jose.ECDH_ES_A128KW, nil
	case "ECDH-ES+A192KW":
		return jose.ECDH_ES_A192KW, nil
	case "ECDH-ES+A256KW":
		return jose.ECDH_ES_A256KW, nil
	default:
		return "", fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}
func parseJWEContentEncryption(enc string) (jose.ContentEncryption, error) {
	switch enc {
	case "A128GCM":
		return jose.A128GCM, nil
	case "A192GCM":
		return jose.A192GCM, nil
	case "A256GCM":
		return jose.A256GCM, nil
	case "A128CBC-HS256":
		return jose.A128CBC_HS256, nil
	case "A192CBC-HS384":
		return jose.A192CBC_HS384, nil
	case "A256CBC-HS512":
		return jose.A256CBC_HS512, nil
	default:
		return "", fmt.Errorf("unsupported encryption encoding: %s", enc)
	}
}
