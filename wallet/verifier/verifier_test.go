package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/es256"
	"github.com/trustknots/vcknots/wallet/verifier/types"
)

func TestNewVerificationDispatcher(t *testing.T) {
	// Test empty dispatcher
	dispatcher, err := NewVerificationDispatcher()
	if err != nil {
		t.Fatalf("NewVerificationDispatcher() should not return error: %v", err)
	}

	if dispatcher == nil {
		t.Fatal("NewVerificationDispatcher() should not return nil")
	}

	// Empty dispatcher should have no components
	if len(dispatcher.plugins) != 0 {
		t.Error("NewVerificationDispatcher() should create empty dispatcher")
	}

	// Test dispatcher with default config
	dispatcherWithDefaults, err := NewVerificationDispatcher(
		WithDefaultConfig(),
	)
	if err != nil {
		t.Fatalf("NewVerificationDispatcher() should not return error: %v", err)
	}

	// Check that ES256 component is registered
	component := dispatcherWithDefaults.plugins[jose.ES256]
	if component == nil {
		t.Error("ES256 component should be registered with WithDefaultConfig()")
	}

	// Verify it's the correct type
	if _, ok := component.(*es256.ES256Verifier); !ok {
		t.Error("ES256 component should be of type *es256.ES256Verifier")
	}
}

func TestVerificationDispatcher_RegisterPlugin(t *testing.T) {
	dispatcher, err := NewVerificationDispatcher()
	if err != nil {
		t.Fatalf("NewVerificationDispatcher() should not return error: %v", err)
	}

	// Create a mock component
	mockComponent := &MockVerificationComponent{}

	err = dispatcher.RegisterPlugin(jose.ES384, mockComponent)
	if err != nil {
		t.Errorf("RegisterPlugin() should not return error: %v", err)
	}

	// Check that component was registered
	component := dispatcher.plugins[jose.ES384]
	if component != mockComponent {
		t.Error("Component should be registered correctly")
	}

	// Test registering over existing component
	newMockComponent := &MockVerificationComponent{}
	err = dispatcher.RegisterPlugin(jose.ES256, newMockComponent)
	if err != nil {
		t.Errorf("RegisterPlugin() should allow overriding existing component: %v", err)
	}

	// Verify component was replaced
	component = dispatcher.plugins[jose.ES256]
	if component != newMockComponent {
		t.Error("Component should be replaced when registering over existing")
	}

	// Test registering nil component
	err = dispatcher.RegisterPlugin(jose.ES512, nil)
	if err == nil {
		t.Error("RegisterPlugin() should return error for nil component")
	}
}

func TestVerificationDispatcher_Verify(t *testing.T) {
	dispatcher, err := NewVerificationDispatcher(
		WithDefaultConfig(),
	)
	if err != nil {
		t.Fatalf("NewVerificationDispatcher() should not return error: %v", err)
	}

	// Generate test key pair for ES256
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyJWK := &jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "test-key-1",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	// Create test payload and signature
	payload := []byte("test message for dispatcher")
	hash := sha256.Sum256(payload)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign test data: %v", err)
	}

	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	// Test valid verification
	proof := credential.CredentialProof{
		Algorithm: jose.ES256,
		Signature: signature,
		Payload:   payload,
	}

	valid, err := dispatcher.Verify(&proof, publicKeyJWK)
	if err != nil {
		t.Errorf("Verify() should not return error: %v", err)
	}
	if !valid {
		t.Error("Verify() should return true for valid signature")
	}

	// Test with unsupported algorithm. HS256 is a MAC rather than a digital
	// signature and "none" is the unsigned JWS of RFC 7515 Section 3.6;
	// WithDefaultConfig() registers neither, so both reach no plugin.
	for _, algorithm := range []jose.SignatureAlgorithm{jose.HS256, jose.SignatureAlgorithm("none")} {
		unsupportedProof := credential.CredentialProof{
			Algorithm: algorithm,
			Signature: signature,
			Payload:   payload,
		}

		_, err = dispatcher.Verify(&unsupportedProof, publicKeyJWK)
		if err == nil {
			t.Errorf("Verify() should return error for unsupported algorithm %s", algorithm)
			continue
		}
		expectedErr := fmt.Sprintf("verification error (algorithm: %s): plugin not found: verifier plugin not found", algorithm)
		if err.Error() != expectedErr {
			t.Errorf("Expected error message '%s', got '%s'", expectedErr, err.Error())
		}
		if !errors.Is(err, types.ErrPluginNotFound) {
			t.Errorf("Verify() should report ErrPluginNotFound for %s", algorithm)
		}
	}
}

// TestWithDefaultConfig_RegistersEveryBundledAlgorithm pins the algorithms a
// default dispatcher can verify, so a plugin that stops being registered is
// caught here rather than in a credential acceptance failure.
func TestWithDefaultConfig_RegistersEveryBundledAlgorithm(t *testing.T) {
	dispatcher, err := NewVerificationDispatcher(WithDefaultConfig())
	if err != nil {
		t.Fatalf("NewVerificationDispatcher() should not return error: %v", err)
	}

	expected := []jose.SignatureAlgorithm{
		jose.ES256, jose.ES384, jose.ES512,
		jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.EdDSA,
	}
	supported := dispatcher.GetSupportedAlgorithms()
	if len(supported) != len(expected) {
		t.Errorf("GetSupportedAlgorithms() returned %v, want the %d bundled algorithms", supported, len(expected))
	}
	for _, algorithm := range expected {
		if !slices.Contains(supported, algorithm) {
			t.Errorf("GetSupportedAlgorithms() should include %s", algorithm)
		}
	}
	for _, algorithm := range []jose.SignatureAlgorithm{jose.HS256, jose.HS384, jose.HS512, jose.SignatureAlgorithm("none")} {
		if slices.Contains(supported, algorithm) {
			t.Errorf("GetSupportedAlgorithms() must not include %s", algorithm)
		}
	}
}

// TestWithDefaultConfig_WiresEachAlgorithmToItsPlugin signs with go-jose under
// every bundled algorithm and verifies through the default dispatcher, and
// checks that each plugin refuses a proof naming another algorithm. The
// signature rules themselves are tested in plugins/internal/signature.
func TestWithDefaultConfig_WiresEachAlgorithmToItsPlugin(t *testing.T) {
	dispatcher, err := NewVerificationDispatcher(WithDefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey := func(curve elliptic.Curve) crypto.Signer {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[jose.SignatureAlgorithm]crypto.Signer{
		jose.ES256: ecKey(elliptic.P256()), jose.ES384: ecKey(elliptic.P384()), jose.ES512: ecKey(elliptic.P521()),
		jose.RS256: rsaKey, jose.RS384: rsaKey, jose.RS512: rsaKey,
		jose.PS256: rsaKey, jose.PS384: rsaKey, jose.PS512: rsaKey,
		jose.EdDSA: edKey,
	}
	for _, algorithm := range commonJOSE.AcceptedSignatureAlgorithms() {
		t.Run(string(algorithm), func(t *testing.T) {
			key, ok := keys[algorithm]
			if !ok {
				t.Fatalf("no test key for %s", algorithm)
			}
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, nil)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signer.Sign([]byte(`{"iss":"https://issuer.example"}`))
			if err != nil {
				t.Fatal(err)
			}
			compact, err := signed.CompactSerialize()
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(compact, ".")
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			proof := credential.CredentialProof{Algorithm: algorithm, Signature: signature, Payload: []byte(parts[0] + "." + parts[1])}
			publicKey := &jose.JSONWebKey{Key: key.Public()}

			valid, err := dispatcher.Verify(&proof, publicKey)
			if err != nil || !valid {
				t.Fatalf("Verify() = %v, %v; want true", valid, err)
			}

			mislabelled := proof
			mislabelled.Algorithm = jose.ES256
			if algorithm == jose.ES256 {
				mislabelled.Algorithm = jose.ES384
			}
			if _, err := bundledVerifier(algorithm).Verify(&mislabelled, publicKey); !errors.Is(err, types.ErrUnsupportedAlgorithm) {
				t.Fatalf("plugin accepted a proof naming %s: %v", mislabelled.Algorithm, err)
			}
		})
	}
}

func TestVerificationDispatcher_VerifyWithMockComponent(t *testing.T) {
	dispatcher, err := NewVerificationDispatcher()
	if err != nil {
		t.Fatalf("NewVerificationDispatcher() should not return error: %v", err)
	}

	// Register mock component
	mockComponent := &MockVerificationComponent{
		shouldReturnValid: true,
		shouldReturnError: false,
	}

	err = dispatcher.RegisterPlugin(jose.ES384, mockComponent)
	if err != nil {
		t.Fatalf("Failed to register mock component: %v", err)
	}

	// Create test proof
	proof := credential.CredentialProof{
		Algorithm: jose.ES384,
		Signature: []byte("mock-signature"),
		Payload:   []byte("mock-payload"),
	}

	publicKey := &jose.JSONWebKey{
		KeyID: "mock-key",
	}

	// Test successful verification
	valid, err := dispatcher.Verify(&proof, publicKey)
	if err != nil {
		t.Errorf("Verify() should not return error: %v", err)
	}
	if !valid {
		t.Error("Verify() should return true when mock component returns true")
	}

	// Verify mock was called with correct parameters
	if !mockComponent.verifyWasCalled {
		t.Error("Mock component Verify() should have been called")
	}
	if mockComponent.lastProof.Algorithm != jose.ES384 {
		t.Error("Mock component should receive correct proof")
	}
	if mockComponent.lastPublicKey != publicKey {
		t.Error("Mock component should receive correct public key")
	}

	// Test with mock returning error
	mockComponent.shouldReturnError = true
	mockComponent.shouldReturnValid = false
	mockComponent.verifyWasCalled = false

	_, err = dispatcher.Verify(&proof, publicKey)
	if err == nil {
		t.Error("Verify() should return error when component returns error")
	}
}

func TestVerificationDispatcher_GetSupportedAlgorithms(t *testing.T) {
	// Test empty dispatcher
	emptyDispatcher, err := NewVerificationDispatcher()
	if err != nil {
		t.Fatalf("NewVerificationDispatcher() should not return error: %v", err)
	}
	emptyAlgorithms := emptyDispatcher.GetSupportedAlgorithms()
	if len(emptyAlgorithms) != 0 {
		t.Error("Empty dispatcher should return no algorithms")
	}

	// Test dispatcher with default config
	dispatcher, err := NewVerificationDispatcher(
		WithDefaultConfig(),
	)
	if err != nil {
		t.Fatalf("NewVerificationDispatcher() should not return error: %v", err)
	}

	algorithms := dispatcher.GetSupportedAlgorithms()

	// Should have at least ES256 with default config
	if len(algorithms) == 0 {
		t.Error("GetSupportedAlgorithms() should return at least one algorithm")
	}

	found := false
	for _, alg := range algorithms {
		if alg == jose.ES256 {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetSupportedAlgorithms() should include ES256")
	}

	// Register another component and check
	mockComponent := &MockVerificationComponent{}
	err = dispatcher.RegisterPlugin(jose.ES384, mockComponent)
	if err != nil {
		t.Fatalf("Failed to register mock component: %v", err)
	}

	algorithms = dispatcher.GetSupportedAlgorithms()
	if len(algorithms) < 2 {
		t.Error("GetSupportedAlgorithms() should return more algorithms after registration")
	}

	// Check both algorithms are present
	hasES256 := false
	hasES384 := false
	for _, alg := range algorithms {
		if alg == jose.ES256 {
			hasES256 = true
		}
		if alg == jose.ES384 {
			hasES384 = true
		}
	}

	if !hasES256 {
		t.Error("GetSupportedAlgorithms() should include ES256")
	}
	if !hasES384 {
		t.Error("GetSupportedAlgorithms() should include ES384")
	}
}

// MockVerificationComponent is a test helper
type MockVerificationComponent struct {
	shouldReturnValid bool
	shouldReturnError bool
	verifyWasCalled   bool
	lastProof         *credential.CredentialProof
	lastPublicKey     *jose.JSONWebKey
}

func (m *MockVerificationComponent) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	m.verifyWasCalled = true
	m.lastProof = proof
	m.lastPublicKey = publicKey

	if m.shouldReturnError {
		return false, &types.VerificationError{
			Algorithm: proof.Algorithm,
			Message:   "mock error",
		}
	}

	return m.shouldReturnValid, nil
}

func BenchmarkVerificationDispatcher_Verify(b *testing.B) {
	dispatcher, err := NewVerificationDispatcher(
		WithDefaultConfig(),
	)
	if err != nil {
		b.Fatalf("NewVerificationDispatcher() should not return error: %v", err)
	}

	// Generate test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyJWK := &jose.JSONWebKey{
		Key: &privateKey.PublicKey,
	}

	payload := []byte("benchmark test message")
	hash := sha256.Sum256(payload)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		b.Fatalf("Failed to sign test data: %v", err)
	}

	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	proof := credential.CredentialProof{
		Algorithm: jose.ES256,
		Signature: signature,
		Payload:   payload,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		valid, err := dispatcher.Verify(&proof, publicKeyJWK)
		if err != nil {
			b.Fatalf("Verify() failed: %v", err)
		}
		if !valid {
			b.Fatal("Verify() should return true")
		}
	}
}
