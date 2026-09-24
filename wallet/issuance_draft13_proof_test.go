package wallet

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
)

func TestController_generateJWTProof_AnonymousPreAuthorizedFlow_OmitsIss(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}
	nonce := "test-nonce"

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)
	if err != nil {
		t.Errorf("generateJWTProof returned error: %v", err)
	}

	if proof == "" {
		t.Error("expected non-empty proof")
	}

	// Validate JWT structure (3 parts separated by dots)
	parts := 0
	for _, char := range proof {
		if char == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("expected JWT to have 2 dots (3 parts), got %d dots", parts)
	}

	proofParts := strings.Split(proof, ".")
	if len(proofParts) != 3 {
		t.Fatalf("expected JWT to have 3 parts, got %d", len(proofParts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(proofParts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if _, exists := payload["iss"]; exists {
		t.Fatalf("expected iss claim to be omitted in anonymous pre-authorized flow, got %v", payload["iss"])
	}
}

func TestController_generateJWTProof_RejectsInvalidES256SignatureEncoding(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := &invalidSignatureKeyEntry{mockKeyEntry: newMockKeyEntry()}
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}

	proof, err := controller.generateJWTProof(
		key,
		did,
		nil,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)
	require.Error(t, err)
	assert.Empty(t, proof)
	assert.Contains(t, err.Error(), "failed to serialize JWT proof")
}

func TestController_generateJWTProof_NonAnonymousFlow_IncludesIssAsClientID(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}
	nonce := "test-nonce"
	clientID := "test-client-id"

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		&clientID,
		credentialRequestProofBindingMethodKID,
	)
	if err != nil {
		t.Fatalf("generateJWTProof returned error: %v", err)
	}

	proofParts := strings.Split(proof, ".")
	if len(proofParts) != 3 {
		t.Fatalf("expected JWT to have 3 parts, got %d", len(proofParts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(proofParts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	iss, ok := payload["iss"].(string)
	if !ok {
		t.Fatalf("expected iss claim to be present as string in non-anonymous flow")
	}
	if iss != clientID {
		t.Fatalf("expected iss %q, got %q", clientID, iss)
	}
}

func TestController_generateJWTProof_NonAnonymousFlow_EmptyClientIDReturnsError(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}
	nonce := "test-nonce"
	emptyClientID := ""

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		&emptyClientID,
		credentialRequestProofBindingMethodKID,
	)
	if err == nil {
		t.Fatalf("expected error when clientID is empty, got nil")
	}
	if !strings.Contains(err.Error(), "clientID must be non-empty when provided") {
		t.Fatalf("unexpected error: %v", err)
	}
	if proof != "" {
		t.Fatalf("expected empty proof on error, got %q", proof)
	}
}

func TestController_generateJWTProof_NonAnonymousFlow_BlankClientIDReturnsError(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}
	nonce := "test-nonce"
	blankClientID := "   "

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		&blankClientID,
		credentialRequestProofBindingMethodKID,
	)
	if err == nil {
		t.Fatalf("expected error when clientID is blank, got nil")
	}
	if !strings.Contains(err.Error(), "clientID must be non-empty when provided") {
		t.Fatalf("unexpected error: %v", err)
	}
	if proof != "" {
		t.Fatalf("expected empty proof on error, got %q", proof)
	}
}

func TestController_generateJWTProof_WithoutNonce_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}

	proof, err := controller.generateJWTProof(
		key,
		did,
		nil,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)
	if err != nil {
		t.Errorf("generateJWTProof returned error: %v", err)
	}

	if proof == "" {
		t.Error("expected non-empty proof")
	}
}

func TestController_generateJWTProof_WithoutIssuer_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := newMockKeyEntry()
	did := &idprofTypes.IdentityProfile{
		ID:     "did:key:test123",
		TypeID: "did:key",
	}
	nonce := "test-nonce"

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)
	if err != nil {
		t.Fatalf("generateJWTProof returned error: %v", err)
	}

	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT to have 3 parts, got %d", len(parts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode JWT payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("failed to parse JWT payload: %v", err)
	}

	if _, exists := payload["iss"]; exists {
		t.Fatal("iss claim must be omitted")
	}
}

func TestController_generateJWTProof_KIDBinding_NilDIDReturnsError(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	key := newMockKeyEntry()
	nonce := "test-nonce"

	proof, err := controller.generateJWTProof(
		key,
		nil,
		&nonce,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "did is required for kid proof binding")
	assert.Empty(t, proof)
}

func TestController_generateJWTProof_KIDBinding_BlankDIDReturnsError(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	key := newMockKeyEntry()
	nonce := "test-nonce"
	did := &idprofTypes.IdentityProfile{ID: "  ", TypeID: "did:key"}

	proof, err := controller.generateJWTProof(
		key,
		did,
		&nonce,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodKID,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "did.ID is required for kid proof binding")
	assert.Empty(t, proof)
}

func TestController_generateJWTProof_JWKBinding_AllowsNilDID(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	key := newMockKeyEntry()
	nonce := "test-nonce"

	proof, err := controller.generateJWTProof(
		key,
		nil,
		&nonce,
		"test-aud",
		nil,
		credentialRequestProofBindingMethodJWK,
	)

	require.NoError(t, err)
	require.NotEmpty(t, proof)

	proofParts := strings.Split(proof, ".")
	require.Len(t, proofParts, 3)

	headerBytes, decodeErr := base64.RawURLEncoding.DecodeString(proofParts[0])
	require.NoError(t, decodeErr)

	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	_, hasJWK := header["jwk"]
	_, hasKID := header["kid"]
	assert.True(t, hasJWK)
	assert.False(t, hasKID)
}
