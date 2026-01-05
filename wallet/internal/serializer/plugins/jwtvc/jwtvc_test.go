package jwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/internal/credential"
	"github.com/trustknots/vcknots/wallet/internal/keystore"
)

func TestNewJwtVcSerializer(t *testing.T) {
	serializer, err := NewJwtVcSerializer()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if serializer == nil {
		t.Fatal("expected serializer to be non-nil")
	}
}

func TestSerializeCredential_NotImplemented(t *testing.T) {
	serializer, err := NewJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	cred := &credential.Credential{}
	_, err = serializer.SerializeCredential(credential.JwtVc, cred)

	if err == nil {
		t.Fatal("expected error for not implemented")
	}
}

func TestDeserializeCredential_InvalidJWT(t *testing.T) {
	serializer, err := NewJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	// Test with invalid JWT (not enough parts)
	_, err = serializer.DeserializeCredential(credential.JwtVc, []byte("invalid.jwt"))

	if err == nil {
		t.Fatal("expected error for invalid JWT")
	}
}

func TestDeserializeCredential_EmptyParts(t *testing.T) {
	serializer, err := NewJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	// Test with empty JWT parts
	_, err = serializer.DeserializeCredential(credential.JwtVc, []byte(".."))

	if err == nil {
		t.Fatal("expected error for empty JWT parts")
	}
}

func TestConvertCredentialSubjectFromJSON(t *testing.T) {
	serializer := &JwtVcSerializer{}

	t.Run("valid subject with id", func(t *testing.T) {
		input := map[string]interface{}{
			"id":   "http://example.com/subject",
			"name": "John Doe",
			"age":  30,
		}

		subjectID, claims, err := serializer.convertCredentialSubjectFromJSON(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims == nil {
			t.Fatal("expected claims to be non-nil")
		}
		if subjectID == "" {
			t.Fatal("expected subject ID to be non-empty")
		}
		if subjectID != "http://example.com/subject" {
			t.Errorf("expected subject ID to be http://example.com/subject, got %s", subjectID)
		}
	})

	t.Run("valid subject without id", func(t *testing.T) {
		input := map[string]interface{}{
			"name": "Jane Doe",
			"age":  25,
		}

		subjectID, claims, err := serializer.convertCredentialSubjectFromJSON(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims == nil {
			t.Fatal("expected claims to be non-nil")
		}
		if subjectID != "" {
			t.Error("expected subject ID to be empty")
		}
	})
}

func TestConvertPresentationToMap(t *testing.T) {
	serializer := &JwtVcSerializer{}

	// Create test URLs
	presentationID := "http://example.com/presentation/1"
	holderID := "http://example.com/holder"

	presentation := &credential.CredentialPresentation{
		ID:     presentationID,
		Types:  []string{"VerifiablePresentation"},
		Holder: holderID,
		Credentials: [][]byte{
			[]byte("jwt.credential.1"),
			[]byte("jwt.credential.2"),
		},
	}

	result := serializer.convertPresentationToMap(presentation)

	if result["id"] != presentation.ID {
		t.Errorf("expected ID %s, got %v", presentation.ID, result["id"])
	}
	if result["holder"] != presentation.Holder {
		t.Errorf("expected holder %s, got %v", presentation.Holder, result["holder"])
	}
}

// mockKeyEntry implements keystore.KeyEntry for testing
type mockKeyEntry struct {
	keyID      string
	publicKey  jose.JSONWebKey
	privateKey *ecdsa.PrivateKey
}

func (m *mockKeyEntry) ID() string {
	return m.keyID
}

func (m *mockKeyEntry) PublicKey() jose.JSONWebKey {
	return m.publicKey
}

func (m *mockKeyEntry) Sign(data []byte) ([]byte, error) {
	// Hash the data using SHA-256
	hash := sha256.Sum256(data)

	// Sign using ECDSA and return DER-encoded signature
	return ecdsa.SignASN1(rand.Reader, m.privateKey, hash[:])
}

func createMockKeyEntry() keystore.KeyEntry {
	// Generate a real ECDSA key for testing
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwk := jose.JSONWebKey{
		Algorithm: string(jose.ES256),
		KeyID:     "test-key-id",
		Use:       "sig",
		Key:       &privateKey.PublicKey,
	}

	return &mockKeyEntry{
		keyID:      "test-key-id",
		publicKey:  jwk,
		privateKey: privateKey,
	}
}

func TestSerializePresentation(t *testing.T) {
	serializer, err := NewJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	// Test with unsupported format
	presentation := &credential.CredentialPresentation{}
	key := createMockKeyEntry()
	_, _, err = serializer.SerializePresentation(credential.MockFormat, presentation, key, nil)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}

	// Test with valid JWT VC format
	presentationID := "http://example.com/presentation/1"
	holderID := "http://example.com/holder"
	nonce := "test-nonce"

	presentation = &credential.CredentialPresentation{
		ID:     presentationID,
		Types:  []string{"VerifiablePresentation"},
		Holder: holderID,
		Nonce:  &nonce,
		Credentials: [][]byte{
			[]byte("credential1"),
			[]byte("credential2"),
		},
	}

	jwtBytes, presentationWithProof, err := serializer.SerializePresentation(credential.JwtVc, presentation, key, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(jwtBytes) == 0 {
		t.Fatalf("expected non-empty JWT bytes")
	}

	if presentationWithProof == nil {
		t.Fatalf("expected presentation with proof to be non-nil")
	}

	if presentationWithProof.Proof == nil {
		t.Fatalf("expected proof to be non-nil")
	}
}

func TestDeserializePresentation(t *testing.T) {
	serializer, err := NewJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	// Test with unsupported format
	_, err = serializer.DeserializePresentation(credential.MockFormat, []byte("test"))
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}

	// Test with JWT VC format (should return not implemented error)
	_, err = serializer.DeserializePresentation(credential.JwtVc, []byte("test.jwt.token"))
	if err == nil {
		t.Fatal("expected error for not implemented")
	}
}

func TestGetAlgorithmFromKey(t *testing.T) {
	serializer := &JwtVcSerializer{}

	// Test with ES256 key
	key := createMockKeyEntry()
	alg := serializer.getAlgorithmFromKey(key)
	if alg != jose.ES256 {
		t.Errorf("expected ES256, got %v", alg)
	}

	// Test with key without algorithm specified
	keyWithoutAlg := &mockKeyEntry{
		keyID: "test-key-2",
		publicKey: jose.JSONWebKey{
			KeyID: "test-key-2",
			Use:   "sig",
		},
		privateKey: nil,
	}

	alg = serializer.getAlgorithmFromKey(keyWithoutAlg)
	// Should default to ES256 when algorithm is not specified
	if alg != jose.ES256 {
		t.Errorf("expected ES256 as default, got %v", alg)
	}

	// Test with different algorithm types
	testKeys := []struct {
		name      string
		algorithm string
		expected  jose.SignatureAlgorithm
	}{
		{"ES384", "ES384", jose.ES384},
		{"ES512", "ES512", jose.ES512},
		{"EdDSA", "EdDSA", jose.EdDSA},
		{"RS256", "RS256", jose.RS256},
	}

	for _, tt := range testKeys {
		t.Run(tt.name, func(t *testing.T) {
			key := &mockKeyEntry{
				keyID: "test-key-" + tt.name,
				publicKey: jose.JSONWebKey{
					Algorithm: tt.algorithm,
					KeyID:     "test-key-" + tt.name,
					Use:       "sig",
				},
				privateKey: nil,
			}

			alg := serializer.getAlgorithmFromKey(key)
			if alg != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, alg)
			}
		})
	}
}

func TestSerializeCredential_AdditionalCases(t *testing.T) {
	serializer, err := NewJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	// Test with unsupported format
	cred := &credential.Credential{}
	_, err = serializer.SerializeCredential(credential.MockFormat, cred)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}

	// Test with nil credential
	_, err = serializer.SerializeCredential(credential.JwtVc, nil)
	if err == nil {
		t.Fatal("expected error for nil credential")
	}
}

func TestDeserializeCredential_AdditionalCases(t *testing.T) {
	serializer, err := NewJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to create serializer: %v", err)
	}

	// Test with unsupported format
	_, err = serializer.DeserializeCredential(credential.MockFormat, []byte("test"))
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}

	// Test with nil data
	_, err = serializer.DeserializeCredential(credential.JwtVc, nil)
	if err == nil {
		t.Fatal("expected error for nil data")
	}

	// Test with empty data
	_, err = serializer.DeserializeCredential(credential.JwtVc, []byte(""))
	if err == nil {
		t.Fatal("expected error for empty data")
	}

	// Test with valid JWT format but empty payload
	_, err = serializer.DeserializeCredential(credential.JwtVc, []byte("header.payload.signature"))
	if err == nil {
		t.Fatal("expected error for invalid JWT structure")
	}

	// Test with valid base64 JWT structure but invalid algorithm header
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"INVALID"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"vc":{"id":"test"}}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	jwt := header + "." + payload + "." + signature

	_, err = serializer.DeserializeCredential(credential.JwtVc, []byte(jwt))
	if err == nil {
		t.Fatal("expected error for invalid algorithm")
	}

	// Test with valid JWT structure but invalid credential data
	validHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	invalidPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"vc":{}}`))
	validJWT := validHeader + "." + invalidPayload + "." + signature

	_, err = serializer.DeserializeCredential(credential.JwtVc, []byte(validJWT))
	if err == nil {
		t.Fatal("expected error for invalid credential structure")
	}
}

func TestConvertCredentialFromJSON(t *testing.T) {
	serializer := &JwtVcSerializer{}

	t.Run("valid credential", func(t *testing.T) {
		// Test with valid credential JSON
		credMap := map[string]interface{}{
			"@context": []interface{}{
				"https://www.w3.org/2018/credentials/v1",
			},
			"id":           "http://example.com/credential/1",
			"type":         []interface{}{"VerifiableCredential", "UniversityDegreeCredential"},
			"issuer":       "http://example.com/issuer",
			"issuanceDate": "2023-01-01T00:00:00Z",
			"credentialSubject": map[string]interface{}{
				"id":     "http://example.com/subject",
				"name":   "John Doe",
				"degree": "Bachelor of Science",
			},
		}

		// Create a base64 encoded JSON payload containing the credential
		payload := map[string]interface{}{"vc": credMap}
		jsonBytes, _ := json.Marshal(payload)
		payloadBase64 := base64.RawURLEncoding.EncodeToString(jsonBytes)
		cred, err := serializer.convertCredentialFromJSON(payloadBase64)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cred == nil {
			t.Fatal("expected credential to be non-nil")
		}

		if cred.ID == "" {
			t.Error("expected credential ID to be non-empty")
		}

		if len(cred.Types) == 0 {
			t.Error("expected credential types to be non-empty")
		}

		// Issuer is a string
		if cred.Issuer == "" {
			t.Error("expected credential issuer to be non-empty")
		}

		if cred.Subject == "" && cred.Claims == nil {
			t.Error("expected credential subject or claims to be non-empty")
		}
	})

	t.Run("missing vc field", func(t *testing.T) {
		payload := map[string]interface{}{"other": "data"}
		jsonBytes, _ := json.Marshal(payload)
		payloadBase64 := base64.RawURLEncoding.EncodeToString(jsonBytes)
		_, err := serializer.convertCredentialFromJSON(payloadBase64)
		if err == nil {
			t.Fatal("expected error for missing vc field")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := serializer.convertCredentialFromJSON("invalid-base64")
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
	})

	t.Run("invalid JSON payload", func(t *testing.T) {
		invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("{invalid-json"))
		_, err := serializer.convertCredentialFromJSON(invalidJSON)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("credential with valid period", func(t *testing.T) {
		// Create a smaller, simpler credential to avoid base64 encoding issues
		credMap := map[string]interface{}{
			"id":         "http://example.com/credential/1",
			"type":       []interface{}{"VerifiableCredential"},
			"issuer":     "http://example.com/issuer",
			"validFrom":  "2023-01-01T00:00:00Z",
			"validUntil": "2024-01-01T00:00:00Z",
			"credentialSubject": map[string]interface{}{
				"name": "John",
			},
		}

		payload := map[string]interface{}{"vc": credMap}
		jsonBytes, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("failed to marshal JSON: %v", err)
		}
		// Use RawURLEncoding as expected by the function
		payloadBase64 := base64.RawURLEncoding.EncodeToString(jsonBytes)
		cred, err := serializer.convertCredentialFromJSON(payloadBase64)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cred.ValidPeriod == nil {
			t.Error("expected valid period to be non-nil")
		} else {
			if cred.ValidPeriod.From == nil {
				t.Error("expected valid from to be non-nil")
			}
			if cred.ValidPeriod.To == nil {
				t.Error("expected valid until to be non-nil")
			}
		}
	})
}
