package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/profile"
)

// encryptAuthorizationResponseJWE encrypts payload as the encrypted
// authorization response of the request metadata was admitted with: an
// OID4VP 1.0 §8.3 JWE under the rules that request was admitted under, or a
// Draft 24 §8.3 JARM JWE for a Draft 24 request, so a Draft 24 request is not
// held to HAIP after consent. Other metadata follows the presenter's profile.
func (p *Oid4vpPresenter) encryptAuthorizationResponseJWE(payloadBytes []byte, metadata *VerifierMetadata) (string, error) {
	rules := p.Profile.Options().ResponseEncryption
	if metadata != nil && metadata.encryption != nil {
		if metadata.encryption.draft24JARM {
			return encryptDraft24JARMResponse(payloadBytes, metadata)
		}
		rules = metadata.encryption.rules
	}
	return encryptAuthorizationResponse(payloadBytes, metadata, rules)
}

// encryptAuthorizationResponse selects a usable Verifier encryption key and
// encrypts payload as an OID4VP 1.0 §8.3 authorization response JWE under
// rules.
func encryptAuthorizationResponse(payloadBytes []byte, metadata *VerifierMetadata, rules profile.ResponseEncryptionRules) (string, error) {
	selection, err := selectResponseEncryptionForProfile(metadata, rules)
	if err != nil {
		return "", err
	}

	return encryptResponseJWE(payloadBytes, selection, (&jose.EncrypterOptions{}).WithContentType("json"))
}

// encryptResponseJWE encrypts payload to the selected key as a compact JWE,
// naming the key's kid in the JWE header when it has one.
func encryptResponseJWE(payloadBytes []byte, selection *responseEncryption, options *jose.EncrypterOptions) (string, error) {
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
	gcmContentEncryptions = map[string]jose.ContentEncryption{
		"A128GCM": jose.A128GCM,
		"A256GCM": jose.A256GCM,
	}
	// walletContentEncryptionPreference is this wallet's own order of
	// preference for the content encryption of an Authorization Response.
	// HAIP §5, which governs both the redirect profile of §5.1 and the DC API
	// profile of §5.2: "Wallets MUST support `A128GCM` or `A256GCM`, or both.
	// If both are supported, the Wallet SHOULD use `A256GCM` for the JWE
	// `enc`." The strongest AEAD therefore comes first, and the AES-CBC-HMAC
	// variants trail behind the AEADs; under ResponseEncryptionRules.GCMOnly
	// they are filtered out by gcmContentEncryptions.
	walletContentEncryptionPreference = []string{
		"A256GCM", "A192GCM", "A128GCM",
		"A256CBC-HS512", "A192CBC-HS384", "A128CBC-HS256",
	}
)

// selectResponseEncryptionForProfile applies OID4VP 1.0 §8.3 and RFC 7517 §5
// key selection under rules; HAIPOptions sets the HAIP §5 combination:
// ECDH-ES on P-256 with A128GCM or A256GCM. Parsing a request and encrypting
// its response share it. A failure wraps ErrResponseEncryptionKeyUnusable or
// ErrResponseEncryptionEncUnsupported.
func selectResponseEncryptionForProfile(metadata *VerifierMetadata, rules profile.ResponseEncryptionRules) (*responseEncryption, error) {
	if metadata == nil {
		return nil, fmt.Errorf("verifier metadata is required for encrypted authorization response: %w", ErrResponseEncryptionKeyMissing)
	}
	allowedEncryptions := jweContentEncryptions
	if rules.GCMOnly {
		allowedEncryptions = gcmContentEncryptions
	}

	key := selectUsableVerifierEncryptionKey(&metadata.Jwks, rules)
	if key == nil {
		return nil, unusableEncryptionKeysError(&metadata.Jwks, rules)
	}

	// §8.3: "The JWE alg algorithm used MUST be equal to the alg value of the
	// chosen jwk."
	algName := key.Algorithm
	if rules.ECDHESOnly && algName != "ECDH-ES" {
		return nil, fmt.Errorf("%w requires ECDH-ES for response encryption, got %q: %w", profile.Refused("ResponseEncryption.ECDHESOnly"), algName, ErrResponseEncryptionKeyUnusable)
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
			if rules.GCMOnly && slices.ContainsFunc(metadata.EncryptedResponseEncValuesSupported, func(value string) bool {
				_, supported := jweContentEncryptions[value]
				return supported
			}) {
				return nil, fmt.Errorf("%w requires A128GCM or A256GCM, and encrypted_response_enc_values_supported offers neither: %w", profile.Refused("ResponseEncryption.GCMOnly"), ErrResponseEncryptionEncUnsupported)
			}
			return nil, fmt.Errorf("encrypted_response_enc_values_supported has no supported content encryption: %w", ErrResponseEncryptionEncUnsupported)
		}
	} else {
		// §8.3: absent list defaults to A128GCM.
		enc = jose.A128GCM
	}

	return &responseEncryption{key: key, alg: alg, enc: enc}, nil
}

// unusableEncryptionKeysError reports that no key of set is usable under
// rules, naming the profile option that excluded the keys when the set holds
// a key usable without it.
func unusableEncryptionKeysError(set *jose.JSONWebKeySet, rules profile.ResponseEncryptionRules) error {
	without := func(relax func(*profile.ResponseEncryptionRules)) bool {
		loose := rules
		relax(&loose)
		return selectUsableVerifierEncryptionKey(set, loose) != nil
	}
	switch {
	case rules.P256Only && without(func(r *profile.ResponseEncryptionRules) { r.P256Only = false }):
		return fmt.Errorf("%w excludes every verifier encryption key in client_metadata.jwks: %w", profile.Refused("ResponseEncryption.P256Only"), ErrResponseEncryptionKeyUnusable)
	case rules.ECDHESOnly && without(func(r *profile.ResponseEncryptionRules) { r.ECDHESOnly = false }):
		return fmt.Errorf("%w excludes every verifier encryption key in client_metadata.jwks: %w", profile.Refused("ResponseEncryption.ECDHESOnly"), ErrResponseEncryptionKeyUnusable)
	case (rules.P256Only || rules.ECDHESOnly) && without(func(r *profile.ResponseEncryptionRules) { r.P256Only, r.ECDHESOnly = false, false }):
		return fmt.Errorf("%w and %w exclude every verifier encryption key in client_metadata.jwks: %w", profile.Refused("ResponseEncryption.P256Only"), profile.Refused("ResponseEncryption.ECDHESOnly"), ErrResponseEncryptionKeyUnusable)
	}
	return fmt.Errorf("no usable verifier encryption key in client_metadata.jwks: %w", ErrResponseEncryptionKeyUnusable)
}

// selectUsableVerifierEncryptionKey iterates client_metadata.jwks.keys in order
// and returns the first key usable for response encryption, skipping unusable
// keys silently (RFC 7517 §5, "ignore unusable keys").
func selectUsableVerifierEncryptionKey(set *jose.JSONWebKeySet, rules profile.ResponseEncryptionRules) *jose.JSONWebKey {
	if set == nil {
		return nil
	}
	for i := range set.Keys {
		key := &set.Keys[i]
		if usableVerifierEncryptionKey(key, rules) {
			return key
		}
	}
	return nil
}

// usableVerifierEncryptionKey reports whether key supports ECDH-ES response
// encryption. use must be "enc" or empty, the key must be EC (P-256, plus
// P-384/P-521 unless rules.P256Only) and alg must be present (OID4VP 1.0
// §8.3: "The `alg` parameter MUST be present in the JWKs.") and a supported
// key agreement algorithm.
func usableVerifierEncryptionKey(key *jose.JSONWebKey, rules profile.ResponseEncryptionRules) bool {
	if !ecdhEncryptionKey(key, rules.P256Only) {
		return false
	}
	// OID4VP 1.0 §8.3: "The alg parameter MUST be present in the JWKs." The
	// draft-era authorization_encrypted_response_alg never stands in for it.
	if _, err := parseJWEKeyAlgorithm(key.Algorithm); err != nil {
		return false
	}
	if rules.ECDHESOnly && key.Algorithm != "ECDH-ES" {
		return false
	}
	return true
}

// ecdhEncryptionKey reports whether key can be the recipient of an ECDH-ES
// family key agreement: use "enc" or absent, and an EC public key on P-256,
// or on P-384 or P-521 unless p256Only.
func ecdhEncryptionKey(key *jose.JSONWebKey, p256Only bool) bool {
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
		return true
	case elliptic.P384(), elliptic.P521():
		return !p256Only
	default:
		return false
	}
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

// selectDraft24JARMEncryption selects the key agreement, content encryption
// and key of a Draft 24 encrypted Authorization Response. Draft 24 §8.3 has
// the Wallet "use the JWT Secured Authorization Response Mode for OAuth 2.0
// (JARM)", whose client metadata names the algorithms: the JWE alg is
// authorization_encrypted_response_alg, required to encrypt at all, and the
// enc is authorization_encrypted_response_enc, A128CBC-HS256 when absent
// (JARM §3). The key comes from client_metadata.jwks (Draft 24 §8.3): one
// whose use is enc or absent, whose alg, when present, is the requested alg,
// and whose key type the alg can use. A failure wraps
// ErrResponseEncryptionKeyUnusable or ErrResponseEncryptionEncUnsupported.
func selectDraft24JARMEncryption(metadata *VerifierMetadata) (*responseEncryption, error) {
	if metadata == nil {
		return nil, fmt.Errorf("verifier metadata is required for encrypted authorization response: %w", ErrResponseEncryptionKeyMissing)
	}
	if metadata.AuthorizationEncryptedResponseAlg == "" {
		return nil, fmt.Errorf("a Draft 24 encrypted response requires authorization_encrypted_response_alg: %w", ErrResponseEncryptionKeyUnusable)
	}
	alg, err := parseJWEKeyAlgorithm(metadata.AuthorizationEncryptedResponseAlg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", err, ErrResponseEncryptionKeyUnusable)
	}
	encName := metadata.AuthorizationEncryptedResponseEnc
	if encName == "" {
		encName = "A128CBC-HS256"
	}
	enc, err := parseJWEContentEncryption(encName)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", err, ErrResponseEncryptionEncUnsupported)
	}
	for i := range metadata.Jwks.Keys {
		key := &metadata.Jwks.Keys[i]
		if key.Algorithm != "" && key.Algorithm != string(alg) {
			continue
		}
		// Every supported alg is an ECDH-ES key agreement.
		if ecdhEncryptionKey(key, false) {
			return &responseEncryption{key: key, alg: alg, enc: enc}, nil
		}
	}
	return nil, fmt.Errorf("no client_metadata.jwks key can be used with %s: %w", alg, ErrResponseEncryptionKeyUnusable)
}

// encryptDraft24JARMResponse encrypts payload, the JSON Authorization
// Response parameters, as an encrypted-only JARM response (Draft 24 §8.3).
func encryptDraft24JARMResponse(payloadBytes []byte, metadata *VerifierMetadata) (string, error) {
	selection, err := selectDraft24JARMEncryption(metadata)
	if err != nil {
		return "", err
	}
	return encryptResponseJWE(payloadBytes, selection, nil)
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
