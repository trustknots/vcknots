// Package jwtvc provides JWT Verifiable Credential serialization plugin
package jwtvc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	joseutil "github.com/trustknots/vcknots/wallet/internal/common/jose"
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

	// Parse JWT using go-jose (automatic structure validation)
	jws, err := jose.ParseSigned(string(data), []jose.SignatureAlgorithm{
		jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256,
	})
	if err != nil {
		return nil, types.NewInvalidJWTError("failed to parse JWT", err)
	}

	// Validate structure (must have exactly 1 signature)
	if len(jws.Signatures) != 1 {
		return nil, types.NewInvalidJWTError(fmt.Sprintf("expected exactly 1 signature, got %d", len(jws.Signatures)), nil)
	}

	// Extract and validate algorithm
	algStr := jws.Signatures[0].Header.Algorithm
	if algStr == "" {
		return nil, types.NewInvalidJWTError("alg header is missing", nil)
	}

	alg, err := joseutil.ParseAlgorithm(algStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported algorithm %s: %w", algStr, types.ErrUnsupportedAlgorithm)
	}

	// Extract payload
	payloadBytes := jws.UnsafePayloadWithoutVerification()

	// Parse payload JSON
	var payloadMap map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadMap); err != nil {
		return nil, types.NewInvalidJWTError("invalid JSON payload", err)
	}

	// Extract VC claim
	vcData, ok := payloadMap["vc"].(map[string]any)
	if !ok {
		return nil, types.NewInvalidCredentialError("vc field is missing or not an object", nil)
	}

	// Convert VC claim to Credential struct
	cred, err := s.convertVCDataToCredential(vcData)
	if err != nil {
		return nil, err
	}

	// Create signing input for proof (header.payload)
	// We need to reconstruct this from the original JWT string
	jwtStr := string(data)
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return nil, types.NewInvalidJWTError("JWT must have exactly 3 parts", nil)
	}
	signingInput := []byte(parts[0] + "." + parts[1])

	// Attach proof
	cred.Proof = &credential.CredentialProof{
		Algorithm: alg,
		Signature: jws.Signatures[0].Signature,
		Payload:   signingInput,
	}

	return cred, nil
}

// SerializePresentation serializes a credential presentation to JWT VP format with signature
// options parameter is ignored for JWT VC (no selective disclosure support)
func (s *JwtVcSerializer) SerializePresentation(flavor credential.SupportedSerializationFlavor, presentation *credential.CredentialPresentation, key keystore.KeyEntry, options types.SerializePresentationOptions) ([]byte, *credential.CredentialPresentation, error) {
	if flavor != credential.JwtVc {
		return nil, nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	// Get algorithm from public key
	keyAlg := s.getAlgorithmFromKey(key)

	// Create DID from public key for kid header
	kb := key.PublicKey()
	prof, err := did.NewDIDKeyProfile(&did.DIDKeyProfileCreateOptions{
		DIDProfileCreateOptions: did.DIDProfileCreateOptions{Method: "key"},
		PublicKey:               &kb,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create DID from public key: %w", err)
	}

	// Create JWKSigner adapter
	signerAdapter, err := joseutil.NewJWKSigner(key, keyAlg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create JWKSigner: %w", err)
	}

	// Configure jose.Signer with kid and typ headers
	signingKey := jose.SigningKey{
		Algorithm: keyAlg,
		Key:       signerAdapter,
	}

	signerOpts := &jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", prof.ID)

	signer, err := jose.NewSigner(signingKey, signerOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create signer: %w", err)
	}

	presentationMap := s.convertPresentationToMap(presentation)

	claims := jwt.Claims{}
	if presentation.Holder != "" {
		claims.Issuer = presentation.Holder
	}

	customClaims := map[string]any{
		"vp": presentationMap,
	}

	if presentation.Nonce != nil {
		customClaims["nonce"] = *presentation.Nonce
	}

	// Merge claims into a single map
	allClaims := make(map[string]any)
	if claims.Issuer != "" {
		allClaims["iss"] = claims.Issuer
	}

	maps.Copy(allClaims, customClaims)

	// Sign and serialize JWT
	jwtBuilder := jwt.Signed(signer).Claims(allClaims)
	jwtString, err := jwtBuilder.Serialize()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize JWT: %w", err)
	}

	// Parse the JWT to extract proof information
	jws, err := jose.ParseSigned(jwtString, []jose.SignatureAlgorithm{keyAlg})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse signed JWT: %w", err)
	}

	// Extract signature and payload for CredentialProof
	if len(jws.Signatures) != 1 {
		return nil, nil, fmt.Errorf("expected exactly 1 signature, got %d", len(jws.Signatures))
	}

	// Create presentation with cryptographic proof
	presentationWithProof := &credential.CredentialPresentation{
		ID:          presentation.ID,
		Types:       presentation.Types,
		Credentials: presentation.Credentials,
		Holder:      presentation.Holder,
		Nonce:       presentation.Nonce,
		Proof: &credential.CredentialProof{
			Algorithm: keyAlg,
			Signature: jws.Signatures[0].Signature,
			Payload:   jws.UnsafePayloadWithoutVerification(),
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

	var payloadMap map[string]any
	if err := json.Unmarshal(payloadData, &payloadMap); err != nil {
		return nil, types.NewInvalidJWTError("invalid JSON payload", err)
	}

	vcData, ok := payloadMap["vc"].(map[string]any)
	if !ok {
		return nil, types.NewInvalidCredentialError("vc field is missing or not an object", nil)
	}

	return s.convertVCDataToCredential(vcData)
}

// convertVCDataToCredential converts VC data map to Credential struct
func (s *JwtVcSerializer) convertVCDataToCredential(vcData map[string]any) (*credential.Credential, error) {

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
	typesList, ok := vcData["type"].([]any)
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
		if subjMap, ok := subjData.(map[string]any); ok {
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
func (s *JwtVcSerializer) convertCredentialSubjectFromJSON(subjMap map[string]any) (string, *credential.CredentialClaim, error) {
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
func (s *JwtVcSerializer) convertPresentationToMap(presentation *credential.CredentialPresentation) map[string]any {
	result := map[string]any{
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

// getAlgorithmFromKey extracts the signature algorithm from a key entry
func (s *JwtVcSerializer) getAlgorithmFromKey(key keystore.KeyEntry) jose.SignatureAlgorithm {
	// Get the algorithm from the public key
	pubKey := key.PublicKey()
	if pubKey.Algorithm != "" {
		if alg, err := joseutil.ParseAlgorithm(pubKey.Algorithm); err == nil {
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
