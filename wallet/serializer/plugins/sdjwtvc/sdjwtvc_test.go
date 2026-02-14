package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

type mockKeyEntry struct {
	keyID      string
	privateKey *ecdsa.PrivateKey
	publicJWK  jose.JSONWebKey
}

func newMockKeyEntry() (*mockKeyEntry, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &mockKeyEntry{
		keyID:      "test-key-id",
		privateKey: privateKey,
		publicJWK: jose.JSONWebKey{
			Key:       &privateKey.PublicKey,
			Algorithm: "ES256",
			KeyID:     "test-key-id",
		},
	}, nil
}

func (m *mockKeyEntry) ID() string {
	return m.keyID
}

func (m *mockKeyEntry) PublicKey() jose.JSONWebKey {
	return m.publicJWK
}

func (m *mockKeyEntry) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	hash := h.Sum(nil)
	return ecdsa.SignASN1(rand.Reader, m.privateKey, hash)
}

func createTestSDJWT() string {
	// Create a sample SD-JWT for testing based on the spec example
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"vc+sd-jwt"}`))

	payload := map[string]interface{}{
		"_sd": []string{
			"TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
			"JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE",
			"jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4",
		},
		"iss":     "https://example.com/issuer",
		"iat":     1683000000,
		"exp":     1883000000,
		"vct":     "https://credentials.example.com/identity_credential",
		"_sd_alg": "sha-256",
		"cnf": map[string]interface{}{
			"jwk": map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
				"y":   "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ",
			},
		},
	}

	payloadBytes, _ := json.Marshal(payload)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Create a dummy signature for testing
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	jwt := header + "." + payloadEncoded + "." + sig

	// Add disclosures
	disclosures := []string{
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ",
		"WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
	}

	result := jwt
	for _, disc := range disclosures {
		result += "~" + disc
	}
	result += "~"

	return result
}

func TestNewSdJwtVcSerializer(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatal("failed to initialize sd-jwt vc serializer")
	}
	if serializer == nil {
		t.Fatal("expected serializer to be non-nil")
	}
}

func TestParseCombinedFormatForPresentation(t *testing.T) {
	tests := []struct {
		name                string
		input               string
		expectedSDJWT       string
		expectedDisclosures int
		expectedHasKBJWT    bool
	}{
		{
			name:                "SD-JWT with disclosures and trailing separator",
			input:               "header.payload.sig~disc1~disc2~",
			expectedSDJWT:       "header.payload.sig",
			expectedDisclosures: 2,
			expectedHasKBJWT:    false,
		},
		{
			name:                "SD-JWT with disclosures and KB-JWT",
			input:               "header.payload.sig~disc1~disc2~kb.header.sig",
			expectedSDJWT:       "header.payload.sig",
			expectedDisclosures: 2,
			expectedHasKBJWT:    true,
		},
		{
			name:                "SD-JWT without disclosures",
			input:               "header.payload.sig~",
			expectedSDJWT:       "header.payload.sig",
			expectedDisclosures: 0,
			expectedHasKBJWT:    false,
		},
		{
			name:                "Just JWT",
			input:               "header.payload.sig",
			expectedSDJWT:       "header.payload.sig",
			expectedDisclosures: 0,
			expectedHasKBJWT:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseCombinedFormatForPresentation(tt.input)

			if result.SDJWT != tt.expectedSDJWT {
				t.Errorf("expected SDJWT %q, got %q", tt.expectedSDJWT, result.SDJWT)
			}

			if len(result.Disclosures) != tt.expectedDisclosures {
				t.Errorf("expected %d disclosures, got %d", tt.expectedDisclosures, len(result.Disclosures))
			}

			hasKBJWT := result.KeyBindingJWT != ""
			if hasKBJWT != tt.expectedHasKBJWT {
				t.Errorf("expected hasKBJWT=%v, got %v", tt.expectedHasKBJWT, hasKBJWT)
			}
		})
	}
}

func TestCombinedFormatForPresentation_Serialize(t *testing.T) {
	tests := []struct {
		name     string
		cf       CombinedFormatForPresentation
		expected string
	}{
		{
			name: "With disclosures only",
			cf: CombinedFormatForPresentation{
				SDJWT:       "header.payload.sig",
				Disclosures: []string{"disc1", "disc2"},
			},
			expected: "header.payload.sig~disc1~disc2~",
		},
		{
			name: "With disclosures and KB-JWT",
			cf: CombinedFormatForPresentation{
				SDJWT:         "header.payload.sig",
				Disclosures:   []string{"disc1", "disc2"},
				KeyBindingJWT: "kb.header.sig",
			},
			expected: "header.payload.sig~disc1~disc2~kb.header.sig",
		},
		{
			name: "Without disclosures",
			cf: CombinedFormatForPresentation{
				SDJWT:       "header.payload.sig",
				Disclosures: []string{},
			},
			expected: "header.payload.sig~",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.cf.Serialize()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestParseDisclosure(t *testing.T) {
	tests := []struct {
		name           string
		disclosure     string
		sdAlg          string
		expectedName   string
		expectedErr    bool
		isArrayElement bool
	}{
		{
			name:         "Object property disclosure",
			disclosure:   "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
			sdAlg:        "sha-256",
			expectedName: "given_name",
			expectedErr:  false,
		},
		{
			name:           "Array element disclosure",
			disclosure:     "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkRFIl0",
			sdAlg:          "sha-256",
			expectedName:   "",
			expectedErr:    false,
			isArrayElement: true,
		},
		{
			name:        "Invalid base64",
			disclosure:  "not-valid-base64!!! ",
			sdAlg:       "sha-256",
			expectedErr: true,
		},
		{
			name:        "Invalid JSON",
			disclosure:  base64.RawURLEncoding.EncodeToString([]byte("not json")),
			sdAlg:       "sha-256",
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDisclosure(tt.disclosure, tt.sdAlg)

			if tt.expectedErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error:  %v", err)
			}

			if result.Name != tt.expectedName {
				t.Errorf("expected name %q, got %q", tt.expectedName, result.Name)
			}

			if result.IsArrayElement != tt.isArrayElement {
				t.Errorf("expected isArrayElement=%v, got %v", tt.isArrayElement, result.IsArrayElement)
			}

			if result.Digest == "" {
				t.Error("expected non-empty digest")
			}
		})
	}
}

func TestComputeDisclosureHash(t *testing.T) {
	tests := []struct {
		name        string
		disclosure  string
		algorithm   string
		expectedErr bool
	}{
		{
			name:        "SHA-256",
			disclosure:  "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
			algorithm:   "sha-256",
			expectedErr: false,
		},
		{
			name:        "SHA-384",
			disclosure:  "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
			algorithm:   "sha-384",
			expectedErr: false,
		},
		{
			name:        "SHA-512",
			disclosure:  "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
			algorithm:   "sha-512",
			expectedErr: false,
		},
		{
			name:        "Unsupported algorithm",
			disclosure:  "test",
			algorithm:   "sha-1",
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := computeDisclosureHash(tt.disclosure, tt.algorithm)

			if tt.expectedErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if hash == "" {
				t.Error("expected non-empty hash")
			}
		})
	}
}

func TestSdJwtVcPresentationOptions_IsSerializePresentationOptions(t *testing.T) {
	opts := &SdJwtVcPresentationOptions{
		SelectedClaims:    []string{"given_name"},
		RequireKeyBinding: true,
		Audience:          "https://verifier.example. com",
		Nonce:             "test-nonce",
	}

	// This should compile without error, confirming the interface is implemented
	var _ types.SerializePresentationOptions = opts
}

func TestSerializePresentation_UnsupportedFormat(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}

	presentation := &credential.CredentialPresentation{
		Types:       []string{"VerifiablePresentation"},
		Credentials: [][]byte{[]byte("test")},
	}

	_, _, err = serializer.SerializePresentation(credential.JwtVc, presentation, nil, nil)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestSerializePresentation_NilPresentation(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}

	_, _, err = serializer.SerializePresentation(credential.SDJwtVC, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil presentation")
	}
}

func TestSerializePresentation_NoCredentials(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}

	presentation := &credential.CredentialPresentation{
		Types:       []string{"VerifiablePresentation"},
		Credentials: [][]byte{},
	}

	_, _, err = serializer.SerializePresentation(credential.SDJwtVC, presentation, nil, nil)
	if err == nil {
		t.Fatal("expected error for no credentials")
	}
}

func TestSerializePresentation_MultipleCredentials(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}

	presentation := &credential.CredentialPresentation{
		Types:       []string{"VerifiablePresentation"},
		Credentials: [][]byte{[]byte("cred1"), []byte("cred2")},
	}

	_, _, err = serializer.SerializePresentation(credential.SDJwtVC, presentation, nil, nil)
	if err == nil {
		t.Fatal("expected error for multiple credentials")
	}
}

func TestSerializePresentation_KeyBindingValidation(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}
	testSDJWT := createTestSDJWT()

	presentation := &credential.CredentialPresentation{
		Types:       []string{"VerifiablePresentation"},
		Credentials: [][]byte{[]byte(testSDJWT)},
	}

	// Test:  RequireKeyBinding=true but no key provided
	opts := &SdJwtVcPresentationOptions{
		RequireKeyBinding: true,
		Audience:          "https://verifier.example.com",
		Nonce:             "test-nonce",
	}

	_, _, err = serializer.SerializePresentation(credential.SDJwtVC, presentation, nil, opts)
	if err == nil {
		t.Fatal("expected error when key is nil but RequireKeyBinding is true")
	}

	// Test: RequireKeyBinding=true but no audience
	key, _ := newMockKeyEntry()
	opts = &SdJwtVcPresentationOptions{
		RequireKeyBinding: true,
		Nonce:             "test-nonce",
	}

	_, _, err = serializer.SerializePresentation(credential.SDJwtVC, presentation, key, opts)
	if err == nil {
		t.Fatal("expected error when audience is empty but RequireKeyBinding is true")
	}

	// Test: RequireKeyBinding=true but no nonce
	opts = &SdJwtVcPresentationOptions{
		RequireKeyBinding: true,
		Audience:          "https://verifier.example.com",
	}

	_, _, err = serializer.SerializePresentation(credential.SDJwtVC, presentation, key, opts)
	if err == nil {
		t.Fatal("expected error when nonce is empty but RequireKeyBinding is true")
	}
}

func TestSerializePresentation_WithKeyBinding(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}
	testSDJWT := createTestSDJWT()

	key, err := newMockKeyEntry()
	if err != nil {
		t.Fatalf("failed to create mock key: %v", err)
	}

	presentation := &credential.CredentialPresentation{
		Types:       []string{"VerifiablePresentation"},
		Credentials: [][]byte{[]byte(testSDJWT)},
	}

	opts := &SdJwtVcPresentationOptions{
		RequireKeyBinding: true,
		Audience:          "https://verifier.example.com",
		Nonce:             "test-nonce-12345",
	}

	serialized, presentationWithProof, err := serializer.SerializePresentation(credential.SDJwtVC, presentation, key, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(serialized) == 0 {
		t.Fatal("expected non-empty serialized output")
	}

	if presentationWithProof == nil {
		t.Fatal("expected non-nil presentation with proof")
	}

	// Verify KB-JWT is present
	serializedStr := string(serialized)
	parts := strings.Split(serializedStr, "~")
	lastPart := parts[len(parts)-1]
	if lastPart == "" || strings.Count(lastPart, ".") != 2 {
		t.Error("expected KB-JWT at the end of serialized presentation")
	}

	if presentationWithProof.Proof == nil {
		t.Fatal("expected proof to be non-nil")
	}
}

func TestSerializePresentation_WithoutKeyBinding(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}
	testSDJWT := createTestSDJWT()

	presentation := &credential.CredentialPresentation{
		Types:       []string{"VerifiablePresentation"},
		Credentials: [][]byte{[]byte(testSDJWT)},
	}

	// No options - should include all disclosures without KB-JWT
	serialized, presentationWithProof, err := serializer.SerializePresentation(credential.SDJwtVC, presentation, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(serialized) == 0 {
		t.Fatal("expected non-empty serialized output")
	}

	if presentationWithProof == nil {
		t.Fatal("expected non-nil presentation with proof")
	}

	// Parse and verify no KB-JWT
	cf := ParseCombinedFormatForPresentation(string(serialized))
	if cf.KeyBindingJWT != "" {
		t.Error("expected no KB-JWT when RequireKeyBinding is false")
	}
}

func TestSerializePresentation_SelectiveDisclosure(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}
	testSDJWT := createTestSDJWT()

	presentation := &credential.CredentialPresentation{
		Types:       []string{"VerifiablePresentation"},
		Credentials: [][]byte{[]byte(testSDJWT)},
	}

	// Only select given_name
	opts := &SdJwtVcPresentationOptions{
		SelectedClaims:    []string{"given_name"},
		RequireKeyBinding: false,
	}

	serialized, _, err := serializer.SerializePresentation(credential.SDJwtVC, presentation, nil, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the result
	cf := ParseCombinedFormatForPresentation(string(serialized))

	// Should have only 1 disclosure (given_name)
	if len(cf.Disclosures) != 1 {
		t.Errorf("expected 1 disclosure, got %d", len(cf.Disclosures))
	}
}

func TestSerializePresentation_SelectiveDisclosure_InvalidSelectedClaims(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}
	testSDJWT := createTestSDJWT()

	presentation := &credential.CredentialPresentation{
		Types:       []string{"VerifiablePresentation"},
		Credentials: [][]byte{[]byte(testSDJWT)},
	}

	// Only select given_name
	opts := &SdJwtVcPresentationOptions{
		SelectedClaims:    []string{"given_name", "no_exist_field"},
		RequireKeyBinding: false,
	}

	_, _, err = serializer.SerializePresentation(credential.SDJwtVC, presentation, nil, opts)
	if err == nil {
		t.Fatalf("If given SelectedClaims doesn't exist in the credential, should be error.")
	}
}

func TestDeserializeCredential(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}

	t.Run("Unsupported format", func(t *testing.T) {
		_, err := serializer.DeserializeCredential(credential.JwtVc, []byte("test"))
		if err == nil {
			t.Fatal("expected error for unsupported format")
		}
	})

	t.Run("Empty SD-JWT", func(t *testing.T) {
		_, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(""))
		if err == nil {
			t.Fatal("expected error for empty SD-JWT")
		}
	})

	t.Run("Invalid JWT format", func(t *testing.T) {
		_, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte("invalid"))
		if err == nil {
			t.Fatal("expected error for invalid JWT format")
		}
	})

	t.Run("Valid SD-JWT VC", func(t *testing.T) {
		testSDJWT := createTestSDJWT()
		cred, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(testSDJWT))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cred == nil {
			t.Fatal("expected non-nil credential")
		}

		if cred.Issuer != "https://example.com/issuer" {
			t.Errorf("expected issuer 'https://example.com/issuer', got '%s'", cred.Issuer)
		}

		if cred.Proof == nil {
			t.Fatal("expected proof to be non-nil")
		}

		if cred.Proof.Algorithm != jose.ES256 {
			t.Errorf("expected algorithm ES256, got %v", cred.Proof.Algorithm)
		}

		// Verify disclosed claims are parsed
		if cred.Claims == nil {
			t.Fatal("expected claims to be non-nil")
		}
	})
}

func TestDeserializePresentation(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}

	t.Run("Unsupported format", func(t *testing.T) {
		_, err := serializer.DeserializePresentation(credential.JwtVc, []byte("test"))
		if err == nil {
			t.Fatal("expected error for unsupported format")
		}
	})

	t.Run("Empty presentation", func(t *testing.T) {
		_, err := serializer.DeserializePresentation(credential.SDJwtVC, []byte(""))
		if err == nil {
			t.Fatal("expected error for empty presentation")
		}
	})

	t.Run("Valid presentation without KB-JWT", func(t *testing.T) {
		testSDJWT := createTestSDJWT()
		presentation, err := serializer.DeserializePresentation(credential.SDJwtVC, []byte(testSDJWT))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if presentation == nil {
			t.Fatal("expected non-nil presentation")
		}

		if len(presentation.Credentials) != 1 {
			t.Errorf("expected 1 credential, got %d", len(presentation.Credentials))
		}

		// No KB-JWT, so proof should be nil
		if presentation.Proof != nil {
			t.Error("expected nil proof when no KB-JWT present")
		}
	})

	t.Run("Valid presentation with KB-JWT", func(t *testing.T) {
		// Create a presentation with KB-JWT
		testSDJWT := createTestSDJWT()

		// Add a mock KB-JWT
		kbHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"kb+jwt"}`))
		kbPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iat":1683000000,"aud":"https://verifier.example.com","nonce":"test-nonce","sd_hash":"test-hash"}`))
		kbSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		kbJwt := kbHeader + "." + kbPayload + "." + kbSig

		presentationData := strings.TrimSuffix(testSDJWT, "~") + "~" + kbJwt

		presentation, err := serializer.DeserializePresentation(credential.SDJwtVC, []byte(presentationData))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if presentation == nil {
			t.Fatal("expected non-nil presentation")
		}

		if presentation.Proof == nil {
			t.Fatal("expected non-nil proof when KB-JWT present")
		}

		if presentation.Proof.Algorithm != jose.ES256 {
			t.Errorf("expected algorithm ES256, got %v", presentation.Proof.Algorithm)
		}

		if presentation.Nonce == nil || *presentation.Nonce != "test-nonce" {
			t.Error("expected nonce to be 'test-nonce'")
		}
	})
}

func TestSerializeCredential(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}

	t.Run("Unsupported format", func(t *testing.T) {
		_, err := serializer.SerializeCredential(credential.JwtVc, &credential.Credential{})
		if err == nil {
			t.Fatal("expected error for unsupported format")
		}
	})

	t.Run("Not implemented for SD-JWT VC", func(t *testing.T) {
		_, err := serializer.SerializeCredential(credential.SDJwtVC, &credential.Credential{})
		if err == nil {
			t.Fatal("expected error for not implemented")
		}
	})
}

func TestSerializeDeserializeRoundTrip(t *testing.T) {
	serializer, err := NewSdJwtVcSerializer()
	if err != nil {
		t.Fatalf("failed to initialize sd-jwt serializer")
	}
	testSDJWT := createTestSDJWT()

	// First, deserialize
	cred, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(testSDJWT))
	if err != nil {
		t.Fatalf("failed to deserialize: %v", err)
	}

	// Verify key fields
	if cred.Issuer != "https://example.com/issuer" {
		t.Errorf("issuer mismatch")
	}

	if len(cred.Types) == 0 || cred.Types[0] != "https://credentials.example.com/identity_credential" {
		t.Errorf("types mismatch")
	}

	// Now create a presentation
	presentation := &credential.CredentialPresentation{
		Types:       []string{"VerifiablePresentation"},
		Credentials: [][]byte{[]byte(testSDJWT)},
	}

	// Serialize the presentation
	serialized, _, err := serializer.SerializePresentation(credential.SDJwtVC, presentation, nil, nil)
	if err != nil {
		t.Fatalf("failed to serialize presentation: %v", err)
	}

	// Deserialize the presentation
	deserializedPres, err := serializer.DeserializePresentation(credential.SDJwtVC, serialized)
	if err != nil {
		t.Fatalf("failed to deserialize presentation: %v", err)
	}

	if len(deserializedPres.Credentials) != 1 {
		t.Errorf("expected 1 credential in deserialized presentation")
	}
}
