package sdjwtvc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	josehelper "github.com/trustknots/vcknots/wallet/internal/common/jose"
	"github.com/trustknots/vcknots/wallet/internal/credential"
	"github.com/trustknots/vcknots/wallet/internal/keystore"
	"github.com/trustknots/vcknots/wallet/internal/serializer/types"
)

// SdJwtVcSerializer implements Serializer for SD-JWT VC format
type SdJwtVcSerializer struct{}

// NewSdJwtVcSerializer creates a new SD-JWT VC serializer
func NewSdJwtVcSerializer() (*SdJwtVcSerializer, error) {
	return &SdJwtVcSerializer{}, nil
}

// SdJwtVcPresentationOptions contains options for SD-JWT VC presentation serialization
type SdJwtVcPresentationOptions struct {
	// SelectedClaims specifies which claims to disclose in the presentation
	SelectedClaims []string
	// RequireKeyBinding indicates whether a Key Binding JWT is required
	RequireKeyBinding bool
	// Audience is the intended audience for the Key Binding JWT (required if RequireKeyBinding is true)
	Audience string
	// Nonce is the nonce value for the Key Binding JWT (required if RequireKeyBinding is true)
	Nonce string
}

// IsSerializePresentationOptions implements the marker interface
func (o *SdJwtVcPresentationOptions) IsSerializePresentationOptions() {}

// CombinedFormatForPresentation represents an SD-JWT in combined format for presentation
// Format: <Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~<optional KB-JWT>
type CombinedFormatForPresentation struct {
	SDJWT         string   // The issuer-signed JWT
	Disclosures   []string // The disclosed claims
	KeyBindingJWT string   // Optional Key Binding JWT
}

// Serialize returns the SD-JWT in combined format
func (cf *CombinedFormatForPresentation) Serialize() string {
	result := cf.SDJWT
	for _, disc := range cf.Disclosures {
		result += "~" + disc
	}
	result += "~"
	if cf.KeyBindingJWT != "" {
		result += cf.KeyBindingJWT
	}
	return result
}

// ParseCombinedFormatForPresentation parses an SD-JWT combined format string
func ParseCombinedFormatForPresentation(input string) *CombinedFormatForPresentation {
	result := &CombinedFormatForPresentation{}

	// Split by ~ separator
	parts := strings.Split(input, "~")
	if len(parts) == 0 {
		return result
	}

	// First part is always the SD-JWT
	result.SDJWT = parts[0]

	// Process remaining parts
	for i := 1; i < len(parts); i++ {
		part := parts[i]
		if part == "" {
			continue
		}
		// Check if this is a JWT (has 2 dots) - could be KB-JWT
		if strings.Count(part, ".") == 2 && i == len(parts)-1 {
			result.KeyBindingJWT = part
		} else {
			result.Disclosures = append(result.Disclosures, part)
		}
	}

	return result
}

// Disclosure represents a parsed SD-JWT disclosure
type Disclosure struct {
	Salt           string      // Random salt
	Name           string      // Claim name (empty for array elements)
	Value          interface{} // Claim value
	EncodedValue   string      // Original base64url encoded disclosure
	Digest         string      // Computed hash of the disclosure
	IsArrayElement bool        // True if this is an array element disclosure
}

// parseDisclosure parses a base64url encoded disclosure
func parseDisclosure(encodedDisclosure string, sdAlg string) (*Disclosure, error) {
	// Decode base64url
	decoded, err := base64.RawURLEncoding.DecodeString(encodedDisclosure)
	if err != nil {
		return nil, types.NewDecodingError("failed to decode disclosure", err)
	}

	// Parse JSON array
	var arr []interface{}
	if err := json.Unmarshal(decoded, &arr); err != nil {
		return nil, types.NewDecodingError("disclosure is not a valid JSON array", err)
	}

	disc := &Disclosure{
		EncodedValue: encodedDisclosure,
	}

	// Array element disclosure:  [salt, value]
	// Object property disclosure: [salt, name, value]
	if len(arr) == 2 {
		disc.IsArrayElement = true
		salt, ok := arr[0].(string)
		if !ok {
			return nil, types.NewDecodingError("disclosure salt must be a string", nil)
		}
		disc.Salt = salt
		disc.Value = arr[1]
	} else if len(arr) == 3 {
		salt, ok := arr[0].(string)
		if !ok {
			return nil, types.NewDecodingError("disclosure salt must be a string", nil)
		}
		name, ok := arr[1].(string)
		if !ok {
			return nil, types.NewDecodingError("disclosure name must be a string", nil)
		}
		disc.Salt = salt
		disc.Name = name
		disc.Value = arr[2]
	} else {
		return nil, types.NewDecodingError("disclosure must have 2 or 3 elements", nil)
	}

	// Compute digest
	digest, err := computeDisclosureHash(encodedDisclosure, sdAlg)
	if err != nil {
		return nil, err
	}
	disc.Digest = digest

	return disc, nil
}

// computeDisclosureHash computes the hash of a disclosure using the specified algorithm
func computeDisclosureHash(disclosure string, algorithm string) (string, error) {
	var h hash.Hash
	switch strings.ToLower(algorithm) {
	case "sha-256":
		h = sha256.New()
	case "sha-384":
		h = sha512.New384()
	case "sha-512":
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	h.Write([]byte(disclosure))
	hashBytes := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hashBytes), nil
}

// KeyBindingJWT represents the structure of a Key Binding JWT
type KeyBindingJWT struct {
	Iat    int64  `json:"iat"`
	Aud    string `json:"aud"`
	Nonce  string `json:"nonce"`
	SdHash string `json:"sd_hash"`
}

// createKeyBindingJWT creates a Key Binding JWT
func createKeyBindingJWT(sdJwtWithDisclosures string, key keystore.KeyEntry, alg jose.SignatureAlgorithm, audience, nonce string, sdAlg string) (string, error) {
	// Compute sd_hash
	var h hash.Hash
	switch strings.ToLower(sdAlg) {
	case "sha-256":
		h = sha256.New()
	case "sha-384":
		h = sha512.New384()
	case "sha-512":
		h = sha512.New()
	default:
		h = sha256.New()
	}
	h.Write([]byte(sdJwtWithDisclosures))
	sdHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Create KB-JWT claims
	kbClaims := KeyBindingJWT{
		Iat:    time.Now().Unix(),
		Aud:    audience,
		Nonce:  nonce,
		SdHash: sdHash,
	}

	// Create KB-JWT header
	kbHeader := map[string]interface{}{
		"typ": "kb+jwt",
		"alg": string(alg),
	}

	// Encode header and claims
	headerBytes, err := json.Marshal(kbHeader)
	if err != nil {
		return "", fmt.Errorf("failed to marshal KB-JWT header: %w", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	claimsBytes, err := json.Marshal(kbClaims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal KB-JWT claims: %w", err)
	}
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)

	// Create signing input
	signingInput := headerEncoded + "." + claimsEncoded

	// Sign
	sigBytes, err := key.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign KB-JWT: %w", err)
	}

	// Convert DER to raw format if needed
	keySize, err := josehelper.GetKeySizeForAlgorithm(alg)
	if err == nil && len(sigBytes) != keySize*2 {
		sigBytes, err = josehelper.ConvertDERToRaw(sigBytes, keySize)
		if err != nil {
			return "", fmt.Errorf("failed to convert signature format: %w", err)
		}
	}

	sigEncoded := base64.RawURLEncoding.EncodeToString(sigBytes)
	return signingInput + "." + sigEncoded, nil
}

// SerializeCredential serializes a credential to SD-JWT VC format
func (s *SdJwtVcSerializer) SerializeCredential(flavor credential.SupportedSerializationFlavor, cred *credential.Credential) ([]byte, error) {
	if flavor != credential.SDJwtVC {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected SD-JWT VC format")
	}

	// SerializeCredential for SD-JWT VC is typically handled by issuers
	// This implementation returns an error as credentials are issued by external systems
	return nil, types.NewFormatError(flavor, errors.New("not implemented"), "SerializeCredential not implemented for SD-JWT VC format - credentials are issued by external systems")
}

// DeserializeCredential deserializes an SD-JWT VC to credential struct
func (s *SdJwtVcSerializer) DeserializeCredential(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.Credential, error) {
	if flavor != credential.SDJwtVC {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected SD-JWT VC format")
	}

	// Parse combined format
	cf := ParseCombinedFormatForPresentation(string(data))
	if cf.SDJWT == "" {
		return nil, types.NewInvalidJWTError("SD-JWT is empty", nil)
	}

	// Parse the issuer-signed JWT
	jwtParts := strings.Split(cf.SDJWT, ".")
	if len(jwtParts) != 3 {
		return nil, types.NewInvalidJWTError("SD-JWT must have exactly 3 parts separated by dots", nil)
	}

	header, payload, signature := jwtParts[0], jwtParts[1], jwtParts[2]

	if header == "" || payload == "" || signature == "" {
		return nil, types.NewInvalidJWTError("SD-JWT parts cannot be empty", nil)
	}

	// Decode header
	headerData, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, types.NewInvalidJWTError("invalid SD-JWT header encoding", err)
	}

	var headerMap map[string]interface{}
	if err := json.Unmarshal(headerData, &headerMap); err != nil {
		return nil, types.NewInvalidJWTError("SD-JWT header is not valid JSON", err)
	}

	// Get algorithm from header
	algStr, ok := headerMap["alg"].(string)
	if !ok {
		return nil, types.NewInvalidJWTError("alg is missing or not a string", nil)
	}

	alg, err := josehelper.ParseAlgorithm(algStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported algorithm %s: %w", algStr, types.ErrUnsupportedAlgorithm)
	}

	// Decode payload
	payloadData, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, types.NewInvalidJWTError("invalid SD-JWT payload encoding", err)
	}

	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payloadData, &payloadMap); err != nil {
		return nil, types.NewInvalidJWTError("SD-JWT payload is not valid JSON", err)
	}

	// Get _sd_alg (default to sha-256 per spec)
	sdAlg := "sha-256"
	if algVal, ok := payloadMap["_sd_alg"].(string); ok {
		sdAlg = algVal
	}

	// Parse disclosures and build disclosed claims map
	disclosedClaims := make(map[string]interface{})
	for _, discStr := range cf.Disclosures {
		disc, err := parseDisclosure(discStr, sdAlg)
		if err != nil {
			return nil, types.NewDecodingError("failed to parse disclosure", err)
		}
		if !disc.IsArrayElement && disc.Name != "" {
			disclosedClaims[disc.Name] = disc.Value
		}
	}

	// Merge disclosed claims with non-selective claims from payload
	allClaims := make(map[string]interface{})
	for k, v := range payloadMap {
		// Skip SD-JWT specific claims
		if k == "_sd" || k == "_sd_alg" || k == "cnf" {
			continue
		}
		allClaims[k] = v
	}
	for k, v := range disclosedClaims {
		allClaims[k] = v
	}

	// Extract credential fields
	cred := &credential.Credential{}

	// Parse vct (verifiable credential type)
	if vct, ok := payloadMap["vct"].(string); ok {
		cred.Types = []string{vct}
	}

	// Parse issuer
	if iss, ok := payloadMap["iss"].(string); ok {
		cred.Issuer = iss
	}

	// Parse subject
	if sub, ok := payloadMap["sub"].(string); ok {
		cred.Subject = sub
	}

	// Parse validity period
	validPeriod := &credential.CredentialValidPeriod{}
	if iat, ok := payloadMap["iat"].(float64); ok {
		t := time.Unix(int64(iat), 0)
		validPeriod.From = &t
	}
	if exp, ok := payloadMap["exp"].(float64); ok {
		t := time.Unix(int64(exp), 0)
		validPeriod.To = &t
	}
	if validPeriod.From != nil || validPeriod.To != nil {
		cred.ValidPeriod = validPeriod
	}

	// Store claims
	claims := credential.CredentialClaim(allClaims)
	cred.Claims = &claims

	// Decode signature
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, types.NewInvalidJWTError("invalid SD-JWT signature encoding", err)
	}

	// Create proof
	cred.Proof = &credential.CredentialProof{
		Algorithm: alg,
		Signature: sig,
		Payload:   []byte(header + "." + payload),
	}

	return cred, nil
}

// SerializePresentation serializes a credential presentation with selective disclosure
func (s *SdJwtVcSerializer) SerializePresentation(
	flavor credential.SupportedSerializationFlavor,
	presentation *credential.CredentialPresentation,
	key keystore.KeyEntry,
	options types.SerializePresentationOptions,
) ([]byte, *credential.CredentialPresentation, error) {
	if flavor != credential.SDJwtVC {
		return nil, nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected SD-JWT VC format")
	}

	if presentation == nil {
		return nil, nil, types.NewInvalidCredentialError("presentation cannot be nil", nil)
	}

	if len(presentation.Credentials) == 0 {
		return nil, nil, types.NewInvalidCredentialError("presentation must contain at least one credential", nil)
	}

	// SD-JWT VC format only supports single credential presentations
	if len(presentation.Credentials) > 1 {
		return nil, nil, types.NewInvalidCredentialError("SD-JWT VC format only supports single credential presentations", nil)
	}

	// Parse options
	var sdOpts *SdJwtVcPresentationOptions
	if options != nil {
		var ok bool
		sdOpts, ok = options.(*SdJwtVcPresentationOptions)
		if !ok {
			return nil, nil, types.NewInvalidCredentialError("invalid presentation options type", nil)
		}
	}

	// Validate key binding requirements
	if sdOpts != nil && sdOpts.RequireKeyBinding {
		if key == nil {
			return nil, nil, types.NewInvalidCredentialError("key is required for key binding", nil)
		}
		if sdOpts.Audience == "" {
			return nil, nil, types.NewInvalidCredentialError("audience is required for key binding", nil)
		}
		if sdOpts.Nonce == "" {
			return nil, nil, types.NewInvalidCredentialError("nonce is required for key binding", nil)
		}
	}

	// Parse the SD-JWT from the credential
	sdJwtData := string(presentation.Credentials[0])
	cf := ParseCombinedFormatForPresentation(sdJwtData)

	if cf.SDJWT == "" {
		return nil, nil, types.NewInvalidJWTError("credential does not contain a valid SD-JWT", nil)
	}

	// Get _sd_alg from the SD-JWT payload
	jwtParts := strings.Split(cf.SDJWT, ".")
	if len(jwtParts) != 3 {
		return nil, nil, types.NewInvalidJWTError("SD-JWT must have 3 parts", nil)
	}

	payloadData, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	if err != nil {
		return nil, nil, types.NewInvalidJWTError("invalid SD-JWT payload encoding", err)
	}

	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payloadData, &payloadMap); err != nil {
		return nil, nil, types.NewInvalidJWTError("SD-JWT payload is not valid JSON", err)
	}

	sdAlg := "sha-256"
	if algVal, ok := payloadMap["_sd_alg"].(string); ok {
		sdAlg = algVal
	}

	// Filter disclosures based on selected claims
	var selectedDisclosures []string
	if sdOpts != nil {
		if len(sdOpts.SelectedClaims) > 0 {
			// Parse all disclosures
			for _, discStr := range cf.Disclosures {
				disc, err := parseDisclosure(discStr, sdAlg)
				if err != nil {
					continue
				}
				// Include if the claim name is in selected claims
				for _, selectedClaim := range sdOpts.SelectedClaims {
					if disc.Name == selectedClaim {
						selectedDisclosures = append(selectedDisclosures, discStr)
						break
					}
				}
			}
			// compare selectedDisclosures and sdOpts.SelectedClaims
			if len(selectedDisclosures) != len(sdOpts.SelectedClaims) {
				return nil, nil, fmt.Errorf("error: Some of the given selected claims don't exist in the credential")
			}
		} else {
			// Include all disclosures if no specific claims selected
			selectedDisclosures = cf.Disclosures
		}
	}

	// Build the presentation SD-JWT with selected disclosures
	presentationCF := &CombinedFormatForPresentation{
		SDJWT:       cf.SDJWT,
		Disclosures: selectedDisclosures,
	}

	// Create Key Binding JWT if required
	if sdOpts != nil && sdOpts.RequireKeyBinding && key != nil {
		// Get algorithm from key
		pubKey := key.PublicKey()
		algStr := pubKey.Algorithm
		if algStr == "" {
			algStr = "ES256"
		}
		alg, err := josehelper.ParseAlgorithm(algStr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse algorithm: %w", err)
		}

		// Create the SD-JWT with disclosures for hashing
		sdJwtWithDisclosures := presentationCF.Serialize()
		// Remove trailing ~ if KB-JWT will be added
		sdJwtWithDisclosures = strings.TrimSuffix(sdJwtWithDisclosures, "~") + "~"

		kbJwt, err := createKeyBindingJWT(sdJwtWithDisclosures, key, alg, sdOpts.Audience, sdOpts.Nonce, sdAlg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create key binding JWT:  %w", err)
		}
		presentationCF.KeyBindingJWT = kbJwt
	}

	// Serialize the presentation
	serialized := presentationCF.Serialize()

	// Create presentation with proof
	presentationWithProof := &credential.CredentialPresentation{
		ID:          presentation.ID,
		Types:       presentation.Types,
		Credentials: [][]byte{[]byte(serialized)},
		Holder:      presentation.Holder,
		Nonce:       presentation.Nonce,
	}

	// Add proof if key binding was used
	if sdOpts != nil && sdOpts.RequireKeyBinding && key != nil && presentationCF.KeyBindingJWT != "" {
		// Parse KB-JWT to get signature
		kbParts := strings.Split(presentationCF.KeyBindingJWT, ".")
		if len(kbParts) == 3 {
			sig, _ := base64.RawURLEncoding.DecodeString(kbParts[2])
			pubKey := key.PublicKey()
			algStr := pubKey.Algorithm
			if algStr == "" {
				algStr = "ES256"
			}
			alg, _ := josehelper.ParseAlgorithm(algStr)
			presentationWithProof.Proof = &credential.CredentialProof{
				Algorithm: alg,
				Signature: sig,
				Payload:   []byte(kbParts[0] + "." + kbParts[1]),
			}
		}
	}

	return []byte(serialized), presentationWithProof, nil
}

// DeserializePresentation deserializes an SD-JWT VC presentation
func (s *SdJwtVcSerializer) DeserializePresentation(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.CredentialPresentation, error) {
	if flavor != credential.SDJwtVC {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected SD-JWT VC format")
	}

	// Parse combined format
	cf := ParseCombinedFormatForPresentation(string(data))
	if cf.SDJWT == "" {
		return nil, types.NewInvalidJWTError("SD-JWT presentation is empty", nil)
	}

	// Create presentation
	presentation := &credential.CredentialPresentation{
		Types:       []string{"VerifiablePresentation"},
		Credentials: [][]byte{data},
	}

	// If Key Binding JWT exists, parse it for proof
	if cf.KeyBindingJWT != "" {
		kbParts := strings.Split(cf.KeyBindingJWT, ".")
		if len(kbParts) != 3 {
			return nil, types.NewInvalidJWTError("Key Binding JWT must have 3 parts", nil)
		}

		// Parse KB-JWT header for algorithm
		kbHeaderData, err := base64.RawURLEncoding.DecodeString(kbParts[0])
		if err != nil {
			return nil, types.NewInvalidJWTError("invalid KB-JWT header encoding", err)
		}

		var kbHeader map[string]interface{}
		if err := json.Unmarshal(kbHeaderData, &kbHeader); err != nil {
			return nil, types.NewInvalidJWTError("KB-JWT header is not valid JSON", err)
		}

		algStr, ok := kbHeader["alg"].(string)
		if !ok {
			return nil, types.NewInvalidJWTError("KB-JWT alg is missing or not a string", nil)
		}

		alg, err := josehelper.ParseAlgorithm(algStr)
		if err != nil {
			return nil, fmt.Errorf("unsupported KB-JWT algorithm: %w", err)
		}

		// Decode signature
		sig, err := base64.RawURLEncoding.DecodeString(kbParts[2])
		if err != nil {
			return nil, types.NewInvalidJWTError("invalid KB-JWT signature encoding", err)
		}

		// Parse KB-JWT body for nonce
		kbBodyData, err := base64.RawURLEncoding.DecodeString(kbParts[1])
		if err != nil {
			return nil, types.NewInvalidJWTError("invalid KB-JWT body encoding", err)
		}

		var kbBody KeyBindingJWT
		if err := json.Unmarshal(kbBodyData, &kbBody); err != nil {
			return nil, types.NewInvalidJWTError("KB-JWT body is not valid JSON", err)
		}

		if kbBody.Nonce != "" {
			presentation.Nonce = &kbBody.Nonce
		}

		presentation.Proof = &credential.CredentialProof{
			Algorithm: alg,
			Signature: sig,
			Payload:   []byte(kbParts[0] + "." + kbParts[1]),
		}
	}

	return presentation, nil
}
