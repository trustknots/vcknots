package keystore

import (
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// mockCreateKeyPairOptions is a test implementation of CreateKeyPairOptions
type mockCreateKeyPairOptions struct {
	algorithm jose.KeyAlgorithm
}

func (m *mockCreateKeyPairOptions) Algorithm() jose.KeyAlgorithm {
	return m.algorithm
}

// mockKeyEntry is a test implementation of KeyEntry
type mockKeyEntry struct {
	id        string
	publicKey jose.JSONWebKey
}

func (m *mockKeyEntry) ID() string {
	return m.id
}

func (m *mockKeyEntry) PublicKey() jose.JSONWebKey {
	return m.publicKey
}

func (m *mockKeyEntry) Sign(data []byte) ([]byte, error) {
	return []byte("mock-signature"), nil
}

// mockKeyStorageComponent is a test implementation of KeyStorageComponent
type mockKeyStorageComponent struct {
	keys  map[string]KeyEntry
	nextID int
}

func newMockKeyStorageComponent() *mockKeyStorageComponent {
	return &mockKeyStorageComponent{
		keys:   make(map[string]KeyEntry),
		nextID: 1,
	}
}

func (m *mockKeyStorageComponent) GenerateKeyPair(opts CreateKeyPairOptions) (string, error) {
	if opts == nil {
		return "", ErrInvalidOptions
	}

	algorithm := opts.Algorithm()
	if algorithm == "" {
		return "", ErrUnsupportedAlgorithm
	}

	// Create mock key entry
	keyID := fmt.Sprintf("key-%d", m.nextID)
	m.nextID++

	publicKey := jose.JSONWebKey{
		Algorithm: string(algorithm),
		KeyID:     keyID,
		Use:       "sig",
	}

	keyEntry := &mockKeyEntry{
		id:        keyID,
		publicKey: publicKey,
	}

	m.keys[keyID] = keyEntry
	return keyID, nil
}

func (m *mockKeyStorageComponent) GetKeyEntry(id string) (KeyEntry, error) {
	if id == "" {
		return nil, ErrInvalidKeyID
	}

	keyEntry, exists := m.keys[id]
	if !exists {
		return nil, ErrKeyNotFound
	}

	return keyEntry, nil
}

func (m *mockKeyStorageComponent) GetKeyEntries() ([]KeyEntry, error) {
	entries := make([]KeyEntry, 0, len(m.keys))
	for _, entry := range m.keys {
		entries = append(entries, entry)
	}
	return entries, nil
}

func (m *mockKeyStorageComponent) DeleteKeyEntry(id string) error {
	if id == "" {
		return ErrInvalidKeyID
	}

	if _, exists := m.keys[id]; !exists {
		return ErrKeyNotFound
	}

	delete(m.keys, id)
	return nil
}

func TestMockCreateKeyPairOptions_Algorithm(t *testing.T) {
	algorithm := jose.KeyAlgorithm(jose.ES256)
	opts := &mockCreateKeyPairOptions{algorithm: algorithm}

	result := opts.Algorithm()
	if result != algorithm {
		t.Errorf("Algorithm() = %v, want %v", result, algorithm)
	}
}

func TestMockKeyEntry_ID(t *testing.T) {
	id := "test-key-id"
	entry := &mockKeyEntry{id: id}

	result := entry.ID()
	if result != id {
		t.Errorf("ID() = %v, want %v", result, id)
	}
}

func TestMockKeyEntry_PublicKey(t *testing.T) {
	publicKey := jose.JSONWebKey{
		Algorithm: "ES256",
		KeyID:     "test-key",
	}
	entry := &mockKeyEntry{publicKey: publicKey}

	result := entry.PublicKey()
	if result.Algorithm != publicKey.Algorithm {
		t.Errorf("PublicKey().Algorithm = %v, want %v", result.Algorithm, publicKey.Algorithm)
	}
	if result.KeyID != publicKey.KeyID {
		t.Errorf("PublicKey().KeyID = %v, want %v", result.KeyID, publicKey.KeyID)
	}
}

func TestMockKeyEntry_Sign(t *testing.T) {
	entry := &mockKeyEntry{}
	data := []byte("test data")

	signature, err := entry.Sign(data)
	if err != nil {
		t.Errorf("Sign() error = %v", err)
	}
	if len(signature) == 0 {
		t.Error("Sign() returned empty signature")
	}
}

func TestMockKeyStorageComponent_GenerateKeyPair(t *testing.T) {
	storage := newMockKeyStorageComponent()
	opts := &mockCreateKeyPairOptions{algorithm: jose.KeyAlgorithm(jose.ES256)}

	keyID, err := storage.GenerateKeyPair(opts)
	if err != nil {
		t.Errorf("GenerateKeyPair() error = %v", err)
	}
	if keyID == "" {
		t.Error("GenerateKeyPair() returned empty key ID")
	}

	// Check that generated key can be retrieved
	entry, err := storage.GetKeyEntry(keyID)
	if err != nil {
		t.Errorf("GetKeyEntry() error = %v", err)
	}
	if entry == nil {
		t.Error("GetKeyEntry() returned nil entry")
	}
}

func TestMockKeyStorageComponent_GenerateKeyPair_InvalidOptions(t *testing.T) {
	storage := newMockKeyStorageComponent()

	// Test with nil options
	_, err := storage.GenerateKeyPair(nil)
	if err != ErrInvalidOptions {
		t.Errorf("GenerateKeyPair(nil) error = %v, want %v", err, ErrInvalidOptions)
	}

	// Test with empty algorithm
	opts := &mockCreateKeyPairOptions{algorithm: ""}
	_, err = storage.GenerateKeyPair(opts)
	if err != ErrUnsupportedAlgorithm {
		t.Errorf("GenerateKeyPair(empty algorithm) error = %v, want %v", err, ErrUnsupportedAlgorithm)
	}
}

func TestMockKeyStorageComponent_GetKeyEntry(t *testing.T) {
	storage := newMockKeyStorageComponent()
	opts := &mockCreateKeyPairOptions{algorithm: jose.KeyAlgorithm(jose.ES256)}

	// Generate a key
	keyID, err := storage.GenerateKeyPair(opts)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Retrieve the key
	entry, err := storage.GetKeyEntry(keyID)
	if err != nil {
		t.Errorf("GetKeyEntry() error = %v", err)
	}
	if entry.ID() != keyID {
		t.Errorf("GetKeyEntry().ID() = %v, want %v", entry.ID(), keyID)
	}
}

func TestMockKeyStorageComponent_GetKeyEntry_NotFound(t *testing.T) {
	storage := newMockKeyStorageComponent()

	// Try to get non-existent key
	_, err := storage.GetKeyEntry("non-existent")
	if err != ErrKeyNotFound {
		t.Errorf("GetKeyEntry(non-existent) error = %v, want %v", err, ErrKeyNotFound)
	}

	// Try with empty key ID
	_, err = storage.GetKeyEntry("")
	if err != ErrInvalidKeyID {
		t.Errorf("GetKeyEntry(\"\") error = %v, want %v", err, ErrInvalidKeyID)
	}
}

func TestMockKeyStorageComponent_GetKeyEntries(t *testing.T) {
	storage := newMockKeyStorageComponent()
	opts := &mockCreateKeyPairOptions{algorithm: jose.KeyAlgorithm(jose.ES256)}

	// Generate multiple keys
	keyID1, _ := storage.GenerateKeyPair(opts)
	keyID2, _ := storage.GenerateKeyPair(opts)

	entries, err := storage.GetKeyEntries()
	if err != nil {
		t.Errorf("GetKeyEntries() error = %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("GetKeyEntries() length = %v, want 2", len(entries))
	}

	// Check if generated key IDs are included
	ids := make(map[string]bool)
	for _, entry := range entries {
		ids[entry.ID()] = true
	}
	if !ids[keyID1] {
		t.Errorf("GetKeyEntries() missing key %v", keyID1)
	}
	if !ids[keyID2] {
		t.Errorf("GetKeyEntries() missing key %v", keyID2)
	}
}

func TestMockKeyStorageComponent_DeleteKeyEntry(t *testing.T) {
	storage := newMockKeyStorageComponent()
	opts := &mockCreateKeyPairOptions{algorithm: jose.KeyAlgorithm(jose.ES256)}

	// Generate a key
	keyID, err := storage.GenerateKeyPair(opts)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Delete the key
	err = storage.DeleteKeyEntry(keyID)
	if err != nil {
		t.Errorf("DeleteKeyEntry() error = %v", err)
	}

	// Confirm that deleted key cannot be retrieved
	_, err = storage.GetKeyEntry(keyID)
	if err != ErrKeyNotFound {
		t.Errorf("GetKeyEntry(deleted key) error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestMockKeyStorageComponent_DeleteKeyEntry_NotFound(t *testing.T) {
	storage := newMockKeyStorageComponent()

	// Try to delete non-existent key
	err := storage.DeleteKeyEntry("non-existent")
	if err != ErrKeyNotFound {
		t.Errorf("DeleteKeyEntry(non-existent) error = %v, want %v", err, ErrKeyNotFound)
	}

	// Try with empty key ID
	err = storage.DeleteKeyEntry("")
	if err != ErrInvalidKeyID {
		t.Errorf("DeleteKeyEntry(\"\") error = %v, want %v", err, ErrInvalidKeyID)
	}
}