package es256

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
)

func TestNewES256Verifier(t *testing.T) {
	verifier := NewES256Verifier()

	if verifier == nil {
		t.Fatal("NewES256Verifier() should not return nil")
	}
}

func TestES256Verifier_Verify(t *testing.T) {
	verifier := NewES256Verifier()

	// Generate a test key pair
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

	// Create test payload
	payload := []byte("test message for signature")
	hash := sha256.Sum256(payload)

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign test data: %v", err)
	}

	// Create signature in r||s format
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Pad to 32 bytes if needed
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	// Test valid verification
	proof := credential.CredentialProof{
		Algorithm: jose.ES256,
		Signature: signature,
		Payload:   payload,
	}

	valid, err := verifier.Verify(&proof, publicKeyJWK)
	if err != nil {
		t.Errorf("Verify() should not return error: %v", err)
	}
	if !valid {
		t.Error("Verify() should return true for valid signature")
	}

	// Test with wrong algorithm
	wrongAlgProof := credential.CredentialProof{
		Algorithm: jose.ES384,
		Signature: signature,
		Payload:   payload,
	}

	_, err = verifier.Verify(&wrongAlgProof, publicKeyJWK)
	if err == nil {
		t.Error("Verify() should return error for wrong algorithm")
	}

	// Test with nil public key
	_, err = verifier.Verify(&proof, nil)
	if err == nil {
		t.Error("Verify() should return error for nil public key")
	}

	// Test with invalid key type
	invalidKeyJWK := &jose.JSONWebKey{
		Key:       "not-an-ecdsa-key",
		KeyID:     "invalid-key",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	_, err = verifier.Verify(&proof, invalidKeyJWK)
	if err == nil {
		t.Error("Verify() should return error for invalid key type")
	}

	// Test with invalid signature length
	invalidSigProof := credential.CredentialProof{
		Algorithm: jose.ES256,
		Signature: []byte("invalid-signature"),
		Payload:   payload,
	}

	_, err = verifier.Verify(&invalidSigProof, publicKeyJWK)
	if err == nil {
		t.Error("Verify() should return error for invalid signature length")
	}

	// Test with tampered payload
	tamperedProof := credential.CredentialProof{
		Algorithm: jose.ES256,
		Signature: signature,
		Payload:   []byte("tampered message"),
	}

	valid, err = verifier.Verify(&tamperedProof, publicKeyJWK)
	if err == nil && valid {
		t.Errorf("Verify() should fail (return error or false) for tampered payload")
	}
}

func TestES256Verifier_VerifyWithDifferentKeySizes(t *testing.T) {
	verifier := NewES256Verifier()

	// Test with different signature component sizes
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	publicKeyJWK := &jose.JSONWebKey{
		Key: &privateKey.PublicKey,
	}

	payload := []byte("test payload")
	hash := sha256.Sum256(payload)

	// Create a signature where r and s have different byte lengths
	for i := 0; i < 10; i++ {
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
		if err != nil {
			t.Fatalf("Failed to sign test data: %v", err)
		}

		// Create properly formatted signature
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

		valid, err := verifier.Verify(&proof, publicKeyJWK)
		if err != nil {
			t.Errorf("Verify() should not return error: %v", err)
		}
		if !valid {
			t.Error("Verify() should return true for valid signature")
		}
	}
}

func BenchmarkES256Verifier_Verify(b *testing.B) {
	verifier := NewES256Verifier()

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
		valid, err := verifier.Verify(&proof, publicKeyJWK)
		if err != nil {
			b.Fatalf("Verify() failed: %v", err)
		}
		if !valid {
			b.Fatal("Verify() should return true")
		}
	}
}
