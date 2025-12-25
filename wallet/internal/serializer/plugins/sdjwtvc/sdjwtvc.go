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
	joseutil "github.com/trustknots/vcknots/wallet/internal/common/jose"
	"github.com/trustknots/vcknots/wallet/internal/credential"
	"github.com/trustknots/vcknots/wallet/internal/keystore"
	"github.com/trustknots/vcknots/wallet/internal/serializer/types"
)

type SdJwtVcSerializer struct{}

func NewSdJwtVcSerializer() *SdJwtVcSerializer {
	return &SdJwtVcSerializer{}
}

// SdJwtVcPresentationOptions contains options for SD-JWT VC presentation serialization
type SdJwtVcPresentationOptions struct {
	// SelectedClaims specifies which claims to disclose
	// If nil or empty, all claims are disclosed
	SelectedClaims []string
}

// IsSerializePresentationOptions implements types.SerializePresentationOptions
func (o *SdJwtVcPresentationOptions) IsSerializePresentationOptions() {}

// disclosure represents a parsed SD-JWT disclosure
type disclosure struct {
	Salt       string
	ClaimName  string
	ClaimValue any
	Hash       string
}

// getHashAlgorithm extracts the hash algorithm from the JWT payload
// Returns "sha-256" as default if _sd_alg is not specified
func getHashAlgorithm(payloadMap map[string]any) string {
	if sdAlg, ok := payloadMap["_sd_alg"].(string); ok {
		return sdAlg
	}
	return "sha-256" // Default per RFC 9901
}

// computeDisclosureHash computes the hash of a disclosure string using the specified algorithm
func computeDisclosureHash(disclosureStr string, algorithm string) (string, error) {
	var hasher hash.Hash
	switch algorithm {
	case "sha-256":
		hasher = sha256.New()
	case "sha-384":
		hasher = sha512.New384()
	case "sha-512":
		hasher = sha512.New()
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	hasher.Write([]byte(disclosureStr))
	hashBytes := hasher.Sum(nil)

	// Return base64url encoded hash
	return base64.RawURLEncoding.EncodeToString(hashBytes), nil
}

// extractSdArray extracts the _sd array from a map
func extractSdArray(m map[string]any) []string {
	if sd, ok := m["_sd"].([]any); ok {
		result := make([]string, 0, len(sd))
		for _, item := range sd {
			if hashStr, ok := item.(string); ok {
				result = append(result, hashStr)
			}
		}
		return result
	}
	return nil
}

// contains checks if a string is in a slice
func contains(arr []string, val string) bool {
	for _, item := range arr {
		if item == val {
			return true
		}
	}
	return false
}

// parseDisclosure parses a base64url-encoded disclosure string
// Returns a disclosure struct with the parsed salt, claim name, claim value, and computed hash
func parseDisclosure(disclosureStr string, sdAlg string) (disclosure, error) {
	// Base64URL decode
	decoded, err := base64.RawURLEncoding.DecodeString(disclosureStr)
	if err != nil {
		return disclosure{}, fmt.Errorf("invalid base64 encoding: %w", err)
	}

	// Parse JSON array: [salt, claim_name, claim_value]
	var discArray []any
	if err := json.Unmarshal(decoded, &discArray); err != nil {
		return disclosure{}, fmt.Errorf("invalid JSON in disclosure: %w", err)
	}

	if len(discArray) != 3 {
		return disclosure{}, fmt.Errorf("disclosure must have exactly 3 elements, got %d", len(discArray))
	}

	salt, ok := discArray[0].(string)
	if !ok {
		return disclosure{}, fmt.Errorf("salt must be a string")
	}

	claimName, ok := discArray[1].(string)
	if !ok {
		return disclosure{}, fmt.Errorf("claim name must be a string")
	}

	claimValue := discArray[2]

	// Compute hash
	hash, err := computeDisclosureHash(disclosureStr, sdAlg)
	if err != nil {
		return disclosure{}, fmt.Errorf("failed to compute disclosure hash: %w", err)
	}

	return disclosure{
		Salt:       salt,
		ClaimName:  claimName,
		ClaimValue: claimValue,
		Hash:       hash,
	}, nil
}

// SerializeCredential serializes a credential to JWT VC format
func (s *SdJwtVcSerializer) SerializeCredential(flavor credential.SupportedSerializationFlavor, cred *credential.Credential) ([]byte, error) {
	if flavor != credential.SDJwtVC {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	// This method is not fully implemented in the original Dart code
	return nil, types.NewFormatError(flavor, errors.New("not implemented"), "SerializeCredential not implemented for SD JWT VC format")
}

// DeserializeCredential deserializes an SD-JWT VC formatted credential
func (s *SdJwtVcSerializer) DeserializeCredential(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.Credential, error) {
	if flavor != credential.SDJwtVC {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected SD-JWT VC format")
	}

	// Step 1: Parse SD-JWT format (split on ~)
	str := string(data)
	parts := strings.Split(str, "~")
	if len(parts) < 2 {
		return nil, types.NewFormatError(flavor, types.ErrDecodingFailed, "invalid SD-JWT VC format")
	}

	jwtStr := parts[0]
	// Filter out empty strings from trailing ~
	disclosureStrings := make([]string, 0)
	for _, disc := range parts[1:] {
		if disc != "" {
			disclosureStrings = append(disclosureStrings, disc)
		}
	}

	// Step 2: Parse JWT using jose.ParseSigned
	jws, err := jose.ParseSigned(jwtStr, []jose.SignatureAlgorithm{
		jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256,
	})
	if err != nil {
		return nil, types.NewInvalidJWTError("failed to parse SD-JWT", err)
	}

	// Step 3: Validate structure
	if len(jws.Signatures) != 1 {
		return nil, types.NewInvalidJWTError(fmt.Sprintf("expected exactly 1 signature, got %d", len(jws.Signatures)), nil)
	}

	// Extract algorithm
	algStr := jws.Signatures[0].Header.Algorithm
	if algStr == "" {
		return nil, types.NewInvalidJWTError("alg header is missing", nil)
	}
	alg, err := joseutil.ParseAlgorithm(algStr)
	if err != nil {
		return nil, fmt.Errorf("unsupported algorithm %s: %w", algStr, types.ErrUnsupportedAlgorithm)
	}

	// Step 4: Extract payload WITHOUT verification
	payloadBytes := jws.UnsafePayloadWithoutVerification()

	// Parse payload as JSON
	var payloadMap map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadMap); err != nil {
		return nil, types.NewInvalidJWTError("invalid JSON payload", err)
	}

	// Step 5: Get hash algorithm and parse disclosures
	sdAlg := getHashAlgorithm(payloadMap)
	disclosures := make([]disclosure, 0, len(disclosureStrings))
	for _, discStr := range disclosureStrings {
		disc, err := parseDisclosure(discStr, sdAlg)
		if err != nil {
			return nil, types.NewDecodingError(fmt.Sprintf("failed to parse disclosure: %s", discStr), err)
		}
		disclosures = append(disclosures, disc)
	}

	// Step 6: Extract top-level _sd array
	topLevelSd := extractSdArray(payloadMap)

	// Step 7: Build reconstructed claims map
	reconstructed := make(map[string]any)
	for k, v := range payloadMap {
		reconstructed[k] = v
	}

	// Remove metadata fields
	delete(reconstructed, "_sd")
	delete(reconstructed, "_sd_alg")

	// Step 8: Verify and merge disclosures into claims
	for _, disc := range disclosures {
		// Check if this disclosure is for top-level or nested in credentialSubject
		isTopLevel := contains(topLevelSd, disc.Hash)

		if isTopLevel {
			// Add to top-level reconstructed claims
			reconstructed[disc.ClaimName] = disc.ClaimValue
		} else if credSubj, ok := reconstructed["credentialSubject"].(map[string]any); ok {
			// Check if it belongs to credentialSubject
			nestedSd := extractSdArray(credSubj)
			if contains(nestedSd, disc.Hash) {
				credSubj[disc.ClaimName] = disc.ClaimValue
			} else {
				// Hash not found in either _sd array
				return nil, types.NewInvalidCredentialError(
					fmt.Sprintf("disclosure hash not found in _sd array: %s", disc.Hash), nil)
			}
		} else {
			return nil, types.NewInvalidCredentialError(
				fmt.Sprintf("disclosure hash not found in _sd array: %s", disc.Hash), nil)
		}
	}

	// Clean up credentialSubject metadata
	if credSubj, ok := reconstructed["credentialSubject"].(map[string]any); ok {
		delete(credSubj, "_sd")
	}

	// Step 9: Map SD-JWT VC claims to Credential struct
	// Extract credential type from vct claim
	vct, ok := reconstructed["vct"].(string)
	if !ok {
		return nil, types.NewInvalidCredentialError("vct claim is missing or invalid", nil)
	}
	credTypes := []string{"VerifiableCredential", vct}

	// Extract issuer (required)
	issuerStr, ok := reconstructed["iss"].(string)
	if !ok {
		return nil, types.NewInvalidCredentialError("iss claim is missing or invalid", nil)
	}

	// Extract ID (jti claim, optional)
	var credID string
	if jti, ok := reconstructed["jti"].(string); ok {
		credID = jti
	}

	// Extract and convert credentialSubject
	var subject string
	claims := make(credential.CredentialClaim)

	if credSubj, ok := reconstructed["credentialSubject"].(map[string]any); ok {
		if id, ok := credSubj["id"].(string); ok {
			subject = id
		}

		// Copy all claims except id
		for k, v := range credSubj {
			if k != "id" {
				claims[k] = v
			}
		}
	}

	// Add cnf to claims if present
	if cnf, ok := reconstructed["cnf"]; ok {
		claims["cnf"] = cnf
	}

	// Extract valid period from JWT claims
	var validPeriod *credential.CredentialValidPeriod
	if iat, ok := reconstructed["iat"].(float64); ok {
		from := time.Unix(int64(iat), 0)
		validPeriod = &credential.CredentialValidPeriod{From: &from}
	}
	if exp, ok := reconstructed["exp"].(float64); ok {
		to := time.Unix(int64(exp), 0)
		if validPeriod == nil {
			validPeriod = &credential.CredentialValidPeriod{To: &to}
		} else {
			validPeriod.To = &to
		}
	}

	// Step 10: Attach proof
	// Reconstruct signing input (header.payload)
	jwtParts := strings.Split(jwtStr, ".")
	if len(jwtParts) != 3 {
		return nil, types.NewInvalidJWTError("JWT must have exactly 3 parts", nil)
	}
	signingInput := []byte(jwtParts[0] + "." + jwtParts[1])

	cred := &credential.Credential{
		ID:          credID,
		Types:       credTypes,
		Issuer:      issuerStr,
		Subject:     subject,
		Claims:      &claims,
		ValidPeriod: validPeriod,
		Proof: &credential.CredentialProof{
			Algorithm: alg,
			Signature: jws.Signatures[0].Signature,
			Payload:   signingInput,
		},
	}

	return cred, nil
}

// SerializePresentation serializes a credential presentation with selective disclosure
// options: SdJwtVcPresentationOptions for specifying which claims to disclose (can be nil for all claims)
// Note: Key parameter is accepted for future KB-JWT support but not currently used
func (s *SdJwtVcSerializer) SerializePresentation(flavor credential.SupportedSerializationFlavor, presentation *credential.CredentialPresentation, key keystore.KeyEntry, options types.SerializePresentationOptions) ([]byte, *credential.CredentialPresentation, error) {
	if flavor != credential.SDJwtVC {
		return nil, nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected SD-JWT VC format")
	}

	// Step 1: Validate input
	if presentation == nil {
		return nil, nil, types.NewFormatError(flavor, types.ErrInvalidPresentation, "presentation cannot be nil")
	}

	if len(presentation.Credentials) == 0 {
		return nil, nil, types.NewFormatError(flavor, types.ErrInvalidPresentation, "no credentials in presentation")
	}

	// MVP: Support only single credential presentations
	if len(presentation.Credentials) > 1 {
		return nil, nil, types.NewFormatError(flavor,
			errors.New("multiple credentials not supported"),
			"SD-JWT VP currently supports only single credential presentations")
	}

	credentialData := presentation.Credentials[0]

	// Step 2: Validate credential is SD-JWT format
	str := string(credentialData)
	parts := strings.Split(str, "~")
	if len(parts) < 2 {
		return nil, nil, types.NewFormatError(flavor, types.ErrInvalidCredential,
			"credential is not in SD-JWT format")
	}

	jwtStr := parts[0]
	allDisclosureStrings := make([]string, 0)
	for _, disc := range parts[1:] {
		if disc != "" {
			allDisclosureStrings = append(allDisclosureStrings, disc)
		}
	}

	// Step 3: Parse the credential to extract its proof
	cred, err := s.DeserializeCredential(flavor, credentialData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse credential for presentation: %w", err)
	}

	// Step 4: Determine selective disclosure based on options
	var filteredDisclosures []string

	if opts, ok := options.(*SdJwtVcPresentationOptions); ok && opts != nil && len(opts.SelectedClaims) > 0 {
		// Selective disclosure: filter based on SelectedClaims
		// Parse JWT to get hash algorithm
		jws, err := jose.ParseSigned(jwtStr, []jose.SignatureAlgorithm{
			jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256,
		})
		if err != nil {
			return nil, nil, types.NewInvalidJWTError("failed to parse SD-JWT for filtering", err)
		}

		payloadBytes := jws.UnsafePayloadWithoutVerification()
		var payloadMap map[string]any
		if err := json.Unmarshal(payloadBytes, &payloadMap); err != nil {
			return nil, nil, types.NewInvalidJWTError("invalid JSON payload", err)
		}

		sdAlg := getHashAlgorithm(payloadMap)

		// Create a set of selected claims for fast lookup
		selectedSet := make(map[string]bool)
		for _, claim := range opts.SelectedClaims {
			selectedSet[claim] = true
		}

		// Filter disclosures
		for _, discStr := range allDisclosureStrings {
			disc, err := parseDisclosure(discStr, sdAlg)
			if err != nil {
				// Skip invalid disclosures
				continue
			}

			// Check if this claim should be disclosed
			if selectedSet[disc.ClaimName] {
				filteredDisclosures = append(filteredDisclosures, discStr)
			}
		}
	} else {
		// No options or no selected claims specified: include all disclosures
		filteredDisclosures = allDisclosureStrings
	}

	// Step 5: Rebuild SD-JWT with filtered disclosures
	result := jwtStr
	for _, disc := range filteredDisclosures {
		result += "~" + disc
	}
	result += "~" // Trailing separator

	// Step 6: Create presentation with proof (reuse credential's proof)
	presentationWithProof := &credential.CredentialPresentation{
		ID:          presentation.ID,
		Types:       presentation.Types,
		Credentials: [][]byte{[]byte(result)},
		Holder:      presentation.Holder,
		Nonce:       presentation.Nonce,
		Proof:       cred.Proof, // Reuse credential proof since no KB-JWT
	}

	return []byte(result), presentationWithProof, nil
}

// DeserializePresentation deserializes a JWT VC formatted credential presentation
func (s *SdJwtVcSerializer) DeserializePresentation(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.CredentialPresentation, error) {
	if flavor != credential.SDJwtVC {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected JWT VC format")
	}

	// This method is not fully implemented in the original Dart code
	return nil, types.NewFormatError(flavor, errors.New("not implemented"), "DeserializePresentation not implemented for SD JWT VC format")
}
