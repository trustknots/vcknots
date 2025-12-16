// Package jwtvc provides JWT Verifiable Credential serialization plugin
package jwtvc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/trustknots/vcknots/wallet/internal/credential"
	"github.com/trustknots/vcknots/wallet/internal/idprof/plugins/did"
	"github.com/trustknots/vcknots/wallet/internal/keystore"
	"github.com/trustknots/vcknots/wallet/internal/serializer/types"
)

// JwtVcSerializer implements Serializer for JWT VC format
type JwtVcSerializer struct{}

// NewJwtVcSerializer creates a new JWT VC serializer
func NewJwtVcSerializer() (*JwtVcSerializer, error) {
	return &JwtVcSerializer{}, nil
}

// SerializeCredential serializes a credential to JWT VC format
func (s *JwtVcSerializer) SerializeCredential(flavor credential.SupportedSerializationFlavor, cred *credential.Credential) ([]byte, error) {
	if flavor != credential.JwtVc {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	// This method is not fully implemented in the original Dart code
	return nil, types.NewFormatError(flavor, errors.New("not implemented"), "SerializeCredential not implemented for JWT VC format")
}

// DeserializeCredential deserializes a JWT VC to credential struct
func (s *JwtVcSerializer) DeserializeCredential(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.Credential, error) {
	if flavor != credential.JwtVc {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	jwtStr := string(data)
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return nil, types.NewInvalidJWTError("JWT must have exactly 3 parts separated by dots", nil)
	}

	header, payload, signature := parts[0], parts[1], parts[2]

	// Basic validation of JWT parts - they should be non-empty and look like base64
	if header == "" || payload == "" || signature == "" {
		return nil, types.NewInvalidJWTError("JWT parts cannot be empty", nil)
	}

	// Decode and parse the credential from payload
	cred, err := s.convertCredentialFromJSON(payload)
	if err != nil {
		// If it's a decoding error, it's likely an invalid JWT format
		if errors.Is(err, types.ErrDecodingFailed) {
			return nil, types.NewInvalidJWTError("invalid JWT payload encoding", err)
		}
		return nil, types.NewInvalidCredentialError("failed to convert credential from JSON", err)
	}

	// Parse header to get algorithm
	headerData, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, types.NewInvalidJWTError("invalid JWT header encoding", err)
	}

	var headerMap map[string]any
	if err := json.Unmarshal(headerData, &headerMap); err != nil {
		return nil, types.NewInvalidJWTError("header is not a valid JSON object", err)
	}

	algStr, ok := headerMap["alg"].(string)
	if !ok {
		return nil, types.NewInvalidJWTError("alg is missing or not a string", nil)
	}

	alg, err := s.parseAlgorithm(algStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported algorithm %s: %w", algStr, types.ErrUnsupportedAlgorithm)
	}

	// Decode signature
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, types.NewInvalidJWTError("invalid JWT signature encoding", err)
	}

	proof := &credential.CredentialProof{
		Algorithm: alg,
		Signature: sig,
		Payload:   []byte(header + "." + payload),
	}

	cred.Proof = proof
	return cred, nil
}

// SerializePresentation serializes a credential presentation to JWT VP format with signature

// derToRaw converts DER-encoded ECDSA signature to raw IEEE P1363 format
// DER format: 0x30 [total-len] 0x02 [R-len] [R] 0x02 [S-len] [S]
// Raw format: [R-bytes][S-bytes] with fixed length (32 bytes each for P-256)
func derToRaw(derSig []byte, keySize int) ([]byte, error) {
	fmt.Printf("DEBUG: derToRaw input size: %d bytes, keySize: %d\n", len(derSig), keySize)

	if len(derSig) < 8 {
		return nil, fmt.Errorf("DER signature too short")
	}

	// Parse DER format manually
	if derSig[0] != 0x30 {
		// Not DER format, assume it's already raw
		fmt.Printf("DEBUG: Not DER format (first byte: 0x%02x), returning as-is\n", derSig[0])
		return derSig, nil
	}

	fmt.Printf("DEBUG: Parsing DER signature, first 8 bytes: %x\n", derSig[:8])

	// Skip sequence tag and length
	offset := 2

	// Parse R
	if derSig[offset] != 0x02 {
		return nil, fmt.Errorf("invalid DER format: expected integer tag for R")
	}
	offset++
	rLen := int(derSig[offset])
	offset++

	if offset+rLen >= len(derSig) {
		return nil, fmt.Errorf("invalid DER format: R length exceeds signature")
	}

	rBytes := derSig[offset : offset+rLen]
	offset += rLen

	fmt.Printf("DEBUG: R length: %d, R bytes: %x\n", rLen, rBytes)

	// Parse S
	if derSig[offset] != 0x02 {
		return nil, fmt.Errorf("invalid DER format: expected integer tag for S")
	}
	offset++
	sLen := int(derSig[offset])
	offset++

	if offset+sLen > len(derSig) {
		return nil, fmt.Errorf("invalid DER format: S length exceeds signature")
	}

	sBytes := derSig[offset : offset+sLen]

	fmt.Printf("DEBUG: S length: %d, S bytes: %x\n", sLen, sBytes)

	// Convert to fixed-length raw format
	// Remove leading zeros and pad to keySize
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	rawSig := make([]byte, keySize*2)

	// Copy R to first half, S to second half
	rRaw := r.Bytes()
	sRaw := s.Bytes()

	fmt.Printf("DEBUG: R raw length: %d, S raw length: %d\n", len(rRaw), len(sRaw))

	// Pad with leading zeros if necessary
	copy(rawSig[keySize-len(rRaw):keySize], rRaw)
	copy(rawSig[keySize*2-len(sRaw):keySize*2], sRaw)

	fmt.Printf("DEBUG: Final raw signature size: %d bytes\n", len(rawSig))

	return rawSig, nil
}

func (s *JwtVcSerializer) SerializePresentation(flavor credential.SupportedSerializationFlavor, presentation *credential.CredentialPresentation, key keystore.KeyEntry) ([]byte, *credential.CredentialPresentation, error) {
	if flavor != credential.JwtVc {
		return nil, nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	// Get algorithm from public key
	keyAlg := s.getAlgorithmFromKey(key)
	kb := key.PublicKey()
	prof, err := did.NewDIDKeyProfile(&did.DIDKeyProfileCreateOptions{
		DIDProfileCreateOptions: did.DIDProfileCreateOptions{Method: "key"},
		PublicKey:               &kb,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create DID from public key: %w", err)
	}

	// Create presentation map for VP claim
	presentationMap := s.convertPresentationToMap(presentation)

	// Create JWT standard claims
	claims := jwt.Claims{}
	if presentation.Holder != "" {
		claims.Issuer = presentation.Holder
	}

	// Create custom claims for VP
	customClaims := map[string]any{
		"vp": presentationMap, // Verifiable Presentation claim
	}

	// Add nonce for replay protection if present
	if presentation.Nonce != nil {
		customClaims["nonce"] = *presentation.Nonce
	}

	// Create JWT header
	header := map[string]any{
		"alg": string(keyAlg),
		"typ": "JWT",
		"kid": prof.ID,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal JWT header: %w", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Create JWT payload combining standard and custom claims
	payload := make(map[string]any)

	// Add standard claims
	if claims.Issuer != "" {
		payload["iss"] = claims.Issuer
	}

	// Add custom claims
	for k, v := range customClaims {
		payload[k] = v
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal JWT payload: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Create signing input (header.payload)
	signingInput := headerEncoded + "." + payloadEncoded
	signingInputBytes := []byte(signingInput)

	// Sign using KeyEntry.Sign method - this returns actual signature bytes
	rawSigBytes, err := key.Sign(signingInputBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	// For ES256, signature should be 64 bytes (32 bytes r + 32 bytes s)
	// If it's not, try DER conversion
	var sigBytes []byte
	if keyAlg == jose.ES256 && len(rawSigBytes) != 64 {
		sigBytes, err = derToRaw(rawSigBytes, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert signature format: %w", err)
		}
	} else {
		sigBytes = rawSigBytes
	}

	// Encode signature using URL-safe base64 without padding
	sigEncoded := base64.RawURLEncoding.EncodeToString(sigBytes)

	// Construct complete JWT token
	jwtString := signingInput + "." + sigEncoded

	// Create presentation with cryptographic proof
	presentationWithProof := &credential.CredentialPresentation{
		ID:          presentation.ID,
		Types:       presentation.Types,
		Credentials: presentation.Credentials,
		Holder:      presentation.Holder,
		Nonce:       presentation.Nonce,
		Proof: &credential.CredentialProof{
			Algorithm: keyAlg,
			Signature: sigBytes,
			Payload:   signingInputBytes,
		},
	}

	return []byte(jwtString), presentationWithProof, nil
}

// DeserializePresentation deserializes a JWT VP to credential presentation struct
func (s *JwtVcSerializer) DeserializePresentation(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.CredentialPresentation, error) {
	if flavor != credential.JwtVc {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	// This method is not fully implemented in the original Dart code
	return nil, types.NewFormatError(flavor, errors.New("not implemented"), "DeserializePresentation not implemented for JWT VC format")
}

// convertCredentialFromJSON converts JSON payload to Credential struct
func (s *JwtVcSerializer) convertCredentialFromJSON(payloadBase64 string) (*credential.Credential, error) {
	// Use RawURLEncoding as per JWT specification (no padding)
	payloadData, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, types.NewDecodingError("failed to decode payload", err)
	}

	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payloadData, &payloadMap); err != nil {
		return nil, types.NewInvalidJWTError("invalid JSON payload", err)
	}

	vcData, ok := payloadMap["vc"].(map[string]interface{})
	if !ok {
		return nil, types.NewInvalidCredentialError("vc field is missing or not an object", nil)
	}

	// Parse ID
	var id *url.URL
	if idStr, ok := vcData["id"].(string); ok && idStr != "" {
		parsedID, err := url.Parse(idStr)
		if err != nil {
			return nil, types.NewInvalidCredentialError("invalid credential ID", err)
		}
		id = parsedID
	}

	// Parse types
	typesList, ok := vcData["type"].([]interface{})
	if !ok {
		return nil, types.NewInvalidCredentialError("type field is missing or not an array", nil)
	}
	credTypes := make([]string, len(typesList))
	for i, t := range typesList {
		if tStr, ok := t.(string); ok {
			credTypes[i] = tStr
		} else {
			return nil, types.NewInvalidCredentialError("type array contains non-string value", nil)
		}
	}

	// Parse name and description
	var name, description string
	if nameStr, ok := vcData["name"].(string); ok {
		name = nameStr
	}
	if descStr, ok := vcData["description"].(string); ok {
		description = descStr
	}

	// Parse issuer
	issuerStr, ok := vcData["issuer"].(string)
	if !ok {
		return nil, types.NewInvalidCredentialError("issuer field is missing or not a string", nil)
	}
	issuer, err := url.Parse(issuerStr)
	if err != nil {
		return nil, types.NewInvalidCredentialError("invalid issuer URL", err)
	}

	// Parse credential subjects
	var sub string
	var claims *credential.CredentialClaim
	if subjData, ok := vcData["credentialSubject"]; ok {
		if subjMap, ok := subjData.(map[string]interface{}); ok {
			subject, subjectClaims, err := s.convertCredentialSubjectFromJSON(subjMap)
			if err != nil {
				return nil, types.NewInvalidCredentialError("failed to convert credential subject", err)
			}
			sub = subject
			claims = subjectClaims
		}
	} else {
		return nil, types.NewInvalidCredentialError("credentialSubject is not a valid object", nil)
	}

	// Parse valid period
	var validPeriod *credential.CredentialValidPeriod
	var validFrom, validUntil *time.Time

	if validFromStr, ok := vcData["validFrom"].(string); ok {
		t, err := time.Parse(time.RFC3339, validFromStr)
		if err != nil {
			return nil, types.NewInvalidCredentialError("invalid validFrom date", err)
		}
		validFrom = &t
	}

	if validUntilStr, ok := vcData["validUntil"].(string); ok {
		t, err := time.Parse(time.RFC3339, validUntilStr)
		if err != nil {
			return nil, types.NewInvalidCredentialError("invalid validUntil date", err)
		}
		validUntil = &t
	}

	if validFrom != nil || validUntil != nil {
		validPeriod = &credential.CredentialValidPeriod{
			From: validFrom,
			To:   validUntil,
		}
	}

	return &credential.Credential{
		ID:          id.String(),
		Types:       credTypes,
		Name:        name,
		Description: description,
		Issuer:      issuer.String(),
		Subject:     sub,
		Claims:      claims,
		ValidPeriod: validPeriod,
	}, nil
}

// convertCredentialSubjectFromJSON converts JSON map to CredentialSubject
func (s *JwtVcSerializer) convertCredentialSubjectFromJSON(subjMap map[string]interface{}) (string, *credential.CredentialClaim, error) {
	var idStr string
	if id, ok := subjMap["id"].(string); ok && id != "" {
		parsedID, err := url.Parse(id)
		if err != nil {
			return "", nil, types.NewInvalidCredentialError("invalid subject ID", err)
		}
		idStr = parsedID.String()
	}

	// Extract claims (everything except id)
	claims := make(credential.CredentialClaim)
	for key, value := range subjMap {
		if key != "id" {
			claims[key] = value
		}
	}

	return idStr, &claims, nil
}

// convertPresentationToMap converts CredentialPresentation to map for JSON serialization
func (s *JwtVcSerializer) convertPresentationToMap(presentation *credential.CredentialPresentation) map[string]interface{} {
	result := map[string]interface{}{
		"type": presentation.Types,
	}

	// Add ID if present
	if presentation.ID != "" {
		result["id"] = presentation.ID
	}

	// Add holder if present
	if presentation.Holder != "" {
		result["holder"] = presentation.Holder
	}

	// Convert credentials to string array (assuming they are JWT strings)
	credStrings := make([]string, len(presentation.Credentials))
	for i, cred := range presentation.Credentials {
		credStrings[i] = string(cred)
	}
	result["verifiableCredential"] = credStrings

	return result
}

// parseAlgorithm converts string algorithm to jose.SignatureAlgorithm
func (s *JwtVcSerializer) parseAlgorithm(algStr string) (jose.SignatureAlgorithm, error) {
	switch algStr {
	case "ES256":
		return jose.ES256, nil
	case "ES384":
		return jose.ES384, nil
	case "ES512":
		return jose.ES512, nil
	case "EdDSA":
		return jose.EdDSA, nil
	case "RS256":
		return jose.RS256, nil
	default:
		return "", fmt.Errorf("unsupported algorithm %s: %w", algStr, types.ErrUnsupportedAlgorithm)
	}
}

// getHashAlgorithm returns the appropriate hash algorithm for the signature algorithm
func (s *JwtVcSerializer) getHashAlgorithm(alg jose.SignatureAlgorithm) hash.Hash {
	switch alg {
	case jose.ES256, jose.RS256:
		return sha256.New()
	case jose.ES384:
		return sha512.New384() // Use SHA-384 from crypto/sha512
	case jose.ES512:
		return sha512.New()
	case jose.EdDSA:
		return sha512.New() // Ed25519 uses SHA-512 internally
	default:
		return sha256.New() // Default fallback
	}
}

// getAlgorithmFromKey extracts the signature algorithm from a key entry
func (s *JwtVcSerializer) getAlgorithmFromKey(key keystore.KeyEntry) jose.SignatureAlgorithm {
	// Get the algorithm from the public key
	pubKey := key.PublicKey()
	if pubKey.Algorithm != "" {
		if alg, err := s.parseAlgorithm(string(pubKey.Algorithm)); err == nil {
			return alg
		}
	}

	// Fallback: determine algorithm based on key type and curve
	switch pubKey.Key.(type) {
	case *jose.JSONWebKey:
		jwk := pubKey.Key.(*jose.JSONWebKey)
		switch jwk.Algorithm {
		case "ES256":
			return jose.ES256
		case "ES384":
			return jose.ES384
		case "ES512":
			return jose.ES512
		case "EdDSA":
			return jose.EdDSA
		case "RS256":
			return jose.RS256
		}
	}

	return jose.ES256 // Default to ES256
}
