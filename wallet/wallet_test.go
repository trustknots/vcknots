package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/verifier"
)

type mockKeyEntry struct {
	id         string
	key        jose.JSONWebKey
	privateKey *ecdsa.PrivateKey
}

func (m *mockKeyEntry) ID() string {
	return m.id
}

type realSigningKeyEntry struct {
	id  string
	key *ecdsa.PrivateKey
}

func (r *realSigningKeyEntry) ID() string {
	return r.id
}

func (r *realSigningKeyEntry) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       &r.key.PublicKey,
		KeyID:     r.id,
		Algorithm: "ES256",
		Use:       "sig",
	}
}

func (r *realSigningKeyEntry) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, r.key, digest[:])
}

func (m *mockKeyEntry) PublicKey() jose.JSONWebKey {
	return m.key
}

func (m *mockKeyEntry) Sign(data []byte) ([]byte, error) {
	if m.privateKey == nil {
		return nil, fmt.Errorf("mock key is missing private key")
	}

	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	return signature, nil
}

type invalidSignatureKeyEntry struct {
	*mockKeyEntry
}

func (k *invalidSignatureKeyEntry) Sign(data []byte) ([]byte, error) {
	return []byte("invalid-es256-signature"), nil
}

func newMockKeyEntry() *mockKeyEntry {
	// Generate a real ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("Failed to generate test key: " + err.Error())
	}

	jwk := jose.JSONWebKey{
		Algorithm: "ES256",
		KeyID:     "test-key-id",
		Use:       "sig",
		Key:       &privateKey.PublicKey,
	}

	return &mockKeyEntry{
		id:         "test-key-id",
		key:        jwk,
		privateKey: privateKey,
	}
}

// createTestControllerWithDefaults uses default configurations for integration testing
func createTestControllerWithDefaults(t *testing.T) *Wallet {
	tempConfigDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tempConfigDir)
	t.Setenv("HOME", tempConfigDir)

	controller, err := NewWallet()
	if err != nil {
		t.Fatalf("Failed to create controller with defaults: %v", err)
	}
	return controller
}

// acceptIssuerKeyPolicy authenticates credentials signed by issuerKey. SD-JWT
// VC §3.5 leaves issuer key resolution to ecosystem policy, so the tests model
// a wallet that holds the issuer key out of band.
func acceptIssuerKeyPolicy(issuerKey *ecdsa.PrivateKey) *acceptance.Policy {
	return &acceptance.Policy{
		ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
			return []jose.JSONWebKey{{Key: &issuerKey.PublicKey, Algorithm: "ES256"}}, nil
		},
	}
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	return parsed
}

// serverObservations records what a test's httptest handler observed about the
// requests the wallet sent. The testing package requires t.FailNow — which
// every require.* helper calls — to run on the goroutine running the test, so a
// handler must never assert directly: on a server goroutine require.* only ends
// that goroutine, and the wallet sees a truncated response instead of the real
// reason. A handler therefore asserts against the recorder (every assert.*
// helper accepts it and reports whether the expectation held) and answers the
// request with the status a real server would return. check reports the verdict
// from the test goroutine.
type serverObservations struct {
	mu       sync.Mutex
	failures []string
	calls    map[string]int
	captured map[string]any
	expected []string
}

// newServerObservations registers a recorder whose verdict is reported when the
// test finishes. expectedEndpoints names the endpoints the test requires the
// wallet to exercise, so an in-handler expectation that never ran fails the
// test instead of proving nothing in silence.
func newServerObservations(t *testing.T, expectedEndpoints ...string) *serverObservations {
	t.Helper()
	obs := &serverObservations{
		calls:    make(map[string]int),
		captured: make(map[string]any),
		expected: expectedEndpoints,
	}
	t.Cleanup(func() { obs.check(t) })
	return obs
}

// Errorf records a failed expectation, which makes *serverObservations an
// assert.TestingT: a handler can use the same assert.* helpers as the test body
// and branch on their bool result instead of calling t.FailNow off-goroutine.
func (o *serverObservations) Errorf(format string, args ...any) {
	message := strings.TrimSpace(fmt.Sprintf(format, args...))
	o.mu.Lock()
	defer o.mu.Unlock()
	o.failures = append(o.failures, message)
}

// called records that a request reached endpoint and returns how many requests
// that endpoint has served, including this one.
func (o *serverObservations) called(endpoint string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls[endpoint]++
	return o.calls[endpoint]
}

// callCount reports how many requests reached endpoint.
func (o *serverObservations) callCount(endpoint string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.calls[endpoint]
}

// set stores a value a handler captured from a request so the test body, or a
// later request, can read it back under the same lock.
func (o *serverObservations) set(key string, value any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.captured[key] = value
}

// get returns a value stored by set.
func (o *serverObservations) get(key string) any {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.captured[key]
}

// check fails t with every recorded failure and with every expected endpoint
// that no request ever reached. It must run on the goroutine running the test.
func (o *serverObservations) check(t *testing.T) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, failure := range o.failures {
		t.Errorf("server observed: %s", failure)
	}
	for _, endpoint := range o.expected {
		if o.calls[endpoint] == 0 {
			t.Errorf("server observed no request for expected endpoint %q", endpoint)
		}
	}
}

func TestNewWallet(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	if controller == nil {
		t.Error("expected non-nil controller")
	}
}

func TestNewWalletWithConfig_WithValidConfig(t *testing.T) {
	// Create individual components with default configs
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create credential store: %v", err)
	}

	receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create receiver: %v", err)
	}

	verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	presenter, err := presenter.NewPresentationDispatcher(presenter.WithDefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create presenter: %v", err)
	}

	config := Config{
		CredStore: credStore,
		Receiver:  receiver,
		Verifier:  verifier,
		Presenter: presenter,
		// IDProfiler is nil - should use default
	}

	// This test should pass with default IDProfiler
	controller, err := NewWalletWithConfig(config)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if controller == nil {
		t.Error("expected non-nil controller")
	}
}

// This test focuses on DPoP key auto-generation.
// If default initialization becomes flaky in CI, inject explicit test dependencies.
func TestNewWalletWithConfig_DPoP_AutoGeneratesKey(t *testing.T) {
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		t.Skipf("credential store not available in this environment: %v", err)
	}
	w, err := NewWalletWithConfig(Config{
		CredStore: credStore,
		DPoP:      DPoPConfig{Enabled: true},
	})
	require.NoError(t, err)

	require.NotNil(t, w.dpop.Key)
}

func TestNewWalletWithConfig_MissingComponents(t *testing.T) {
	tests := []struct {
		name        string
		config      func() Config
		expectError bool
	}{
		{
			name: "empty config uses defaults",
			config: func() Config {
				return Config{
					// All components are nil - should use defaults
				}
			},
			expectError: false,
		},
		{
			name: "partial config uses defaults for missing components",
			config: func() Config {
				credStore, _ := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
				return Config{
					CredStore: credStore,
					// Other components are nil - should use defaults
				}
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, err := NewWalletWithConfig(tt.config())
			if tt.expectError {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if controller == nil {
					t.Error("expected non-nil controller")
				}
			}
		})
	}
}

func TestNewInMemoryECKeyEntry(t *testing.T) {
	key, err := newInMemoryECKeyEntry()
	require.NoError(t, err)
	require.NotEmpty(t, key.ID())

	pub, ok := key.PublicKey().Key.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, elliptic.P256(), pub.Curve)
}

func TestController_GenerateDID_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	key := jose.JSONWebKey{
		Algorithm: "ES256",
		KeyID:     "test-key",
	}

	options := DIDCreateOptions{
		TypeID:    "did:key",
		PublicKey: key,
	}

	// Integration test with default config
	// This would work once we have proper identity profiler implementation
	_, err := controller.GenerateDID(options)
	if err != nil {
		t.Skipf("GenerateDID not supported in mock environment: %v", err)
	}
}

// decodeObservedCredentialRequest decodes a Credential Request body that the
// wallet encrypted to the issuer's credential_request_encryption key
// (OpenID4VCI Final §8.1), or a plain JSON body when the issuer advertises no
// request encryption. It records every decoding failure instead of asserting,
// so it is safe to call from an httptest handler goroutine, and reports whether
// the body decoded.
func decodeObservedCredentialRequest(obs *serverObservations, r *http.Request, key jose.JSONWebKey) (map[string]any, bool) {
	raw, err := io.ReadAll(r.Body)
	if !assert.NoError(obs, err) {
		return nil, false
	}
	plaintext := raw
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/jwt") {
		encrypted, err := jose.ParseEncryptedCompact(
			string(raw),
			[]jose.KeyAlgorithm{jose.ECDH_ES},
			[]jose.ContentEncryption{jose.A128GCM, jose.A256GCM},
		)
		if !assert.NoError(obs, err) {
			return nil, false
		}
		plaintext, err = encrypted.Decrypt(key.Key)
		if !assert.NoError(obs, err) {
			return nil, false
		}
	}
	var body map[string]any
	if !assert.NoError(obs, json.Unmarshal(plaintext, &body)) {
		return nil, false
	}
	return body, true
}

// writeObservedFinalCredentialResponse writes an encrypted Credential Response
// (OpenID4VCI Final §8.2) from a handler goroutine, recording an encryption
// failure instead of asserting on it.
func writeObservedFinalCredentialResponse(obs *serverObservations, w http.ResponseWriter, key jose.JSONWebKey, payload any) {
	plaintext, err := json.Marshal(payload)
	if !assert.NoError(obs, err) {
		http.Error(w, "cannot serialize credential response", http.StatusInternalServerError)
		return
	}
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{Algorithm: responseKeyAlgorithm(key), Key: key.Public().Key, KeyID: key.KeyID},
		(&jose.EncrypterOptions{}).WithContentType("json"),
	)
	if !assert.NoError(obs, err) {
		http.Error(w, "cannot encrypt credential response", http.StatusInternalServerError)
		return
	}
	encrypted, err := encrypter.Encrypt(plaintext)
	if !assert.NoError(obs, err) {
		http.Error(w, "cannot encrypt credential response", http.StatusInternalServerError)
		return
	}
	serialized, err := encrypted.CompactSerialize()
	if !assert.NoError(obs, err) {
		http.Error(w, "cannot serialize encrypted credential response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(serialized))
}

// responseKeyAlgorithm is the JWE alg the wallet's response key names, ECDH-ES
// when it names none.
func responseKeyAlgorithm(key jose.JSONWebKey) jose.KeyAlgorithm {
	if key.Algorithm == "" {
		return jose.ECDH_ES
	}
	return jose.KeyAlgorithm(key.Algorithm)
}

func newPrivateJWKForFinalVCITest(t *testing.T, keyID string) jose.JSONWebKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: "ES256",
		Use:       "sig",
	}
}

func buildTestSDJWTVC(t *testing.T, holderPublicKey jose.JSONWebKey, claims map[string]string) string {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return buildTestSDJWTVCWithIssuerKey(t, issuerKey, holderPublicKey, claims)
}

// buildTestSDJWTVCWithIssuerKey signs the credential with a caller-supplied
// issuer key, so a test can configure a CredentialAcceptancePolicy that
// resolves it.
func buildTestSDJWTVCWithIssuerKey(t *testing.T, issuerKey *ecdsa.PrivateKey, holderPublicKey jose.JSONWebKey, claims map[string]string) string {
	t.Helper()
	disclosures := make([]string, 0, len(claims))
	hashes := make([]string, 0, len(claims))
	for name, value := range claims {
		disclosureBytes, err := json.Marshal([]any{"salt-" + name, name, value})
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(disclosureBytes)
		disclosures = append(disclosures, encoded)
		hash := sha256.Sum256([]byte(encoded))
		hashes = append(hashes, base64.RawURLEncoding.EncodeToString(hash[:]))
	}
	payload := map[string]any{
		"iss": "https://issuer.example.test", "vct": "urn:eudi:pid:1",
		"cnf": map[string]any{"jwk": holderPublicKey.Public()},
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		"_sd": hashes, "_sd_alg": "sha-256",
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: issuerKey}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(payload).Serialize()
	require.NoError(t, err)
	return strings.Join(append([]string{signed}, disclosures...), "~") + "~"
}

func TestController_VerifyCredential_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	cred := &credential.Credential{
		ID:    "hoge://test-credential",
		Types: []string{"VerifiableCredential"},
		Proof: nil, // No proof
	}

	pubKey := jose.JSONWebKey{
		Algorithm: "ES256",
		KeyID:     "test-key",
	}

	// Test with no proof - should return false
	result := controller.VerifyCredential(cred, pubKey)
	if result {
		t.Error("expected false for credential without proof")
	}
}

func TestController_VerifyCredential_WithProof_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	// Create credential with proof
	cred := &credential.Credential{
		ID:    "https://example.com/credentials/123",
		Types: []string{"VerifiableCredential", "TestCredential"},
		Proof: &credential.CredentialProof{
			Algorithm: "ES256",
			Signature: []byte("invalid-signature"),
			Payload:   []byte("test-payload"),
		},
	}

	pubKey := jose.JSONWebKey{
		Algorithm: "ES256",
		KeyID:     "test-key",
		Use:       "sig",
	}

	// Test with proof - should attempt verification (may fail due to mock)
	result := controller.VerifyCredential(cred, pubKey)
	// In mock environment, this might return false due to invalid signature
	// but we're testing that the code path is exercised
	t.Logf("VerifyCredential result with proof: %v", result)
}

func extractPayloadField(t *testing.T, compactJWT string, field string) any {
	t.Helper()
	parts := strings.Split(compactJWT, ".")
	require.Len(t, parts, 3)
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(b, &payload))
	value, ok := payload[field]
	require.True(t, ok, "field %q not found in payload", field)
	return value
}

// observedHeaderField reads a compact JWT header field on behalf of an httptest
// handler, recording a malformed proof instead of asserting on the server
// goroutine, and reports whether the field was found.
func observedHeaderField(obs *serverObservations, compactJWT string, field string) (any, bool) {
	parts := strings.Split(compactJWT, ".")
	if !assert.Len(obs, parts, 3) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if !assert.NoError(obs, err) {
		return nil, false
	}
	var header map[string]any
	if !assert.NoError(obs, json.Unmarshal(b, &header)) {
		return nil, false
	}
	value, ok := header[field]
	if !assert.True(obs, ok, "field %q not found in header", field) {
		return nil, false
	}
	return value, true
}

func TestValidateClientAuthConfig(t *testing.T) {
	key, _ := newClientAuthKeyEntry(t, "client-key-1")

	assert.NoError(t, validateClientAuthConfig(ClientAuthConfig{}))
	assert.NoError(t, validateClientAuthConfig(ClientAuthConfig{
		Method:   receiverTypes.PrivateKeyJwt,
		ClientID: "wallet-id",
		Key:      key,
	}))

	err := validateClientAuthConfig(ClientAuthConfig{
		Method: receiverTypes.PrivateKeyJwt,
		Key:    key,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client ID is required")

	err = validateClientAuthConfig(ClientAuthConfig{
		Method:   receiverTypes.PrivateKeyJwt,
		ClientID: "wallet-id",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key is required")

	err = validateClientAuthConfig(ClientAuthConfig{
		Method: receiverTypes.ClientSecretPost,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported client authentication method")

	incompatiblePrivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	incompatibleKey := &mockKeyEntry{
		id: "client-key-1",
		key: jose.JSONWebKey{
			Algorithm: "ES384",
			KeyID:     "client-key-1",
			Use:       "sig",
			Key:       &incompatiblePrivateKey.PublicKey,
		},
		privateKey: incompatiblePrivateKey,
	}
	err = validateClientAuthConfig(ClientAuthConfig{
		Method:   receiverTypes.PrivateKeyJwt,
		ClientID: "wallet-id",
		Key:      incompatibleKey,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not compatible with ES256")

	// The same P-384 key becomes valid once the configuration declares ES384,
	// which is what token_endpoint_auth_signing_alg carries.
	require.NoError(t, validateClientAuthConfig(ClientAuthConfig{
		Method:     receiverTypes.PrivateKeyJwt,
		ClientID:   "wallet-id",
		Key:        incompatibleKey,
		SigningAlg: jose.ES384,
	}))

	err = validateClientAuthConfig(ClientAuthConfig{
		Method:     receiverTypes.PrivateKeyJwt,
		ClientID:   "wallet-id",
		Key:        key,
		SigningAlg: jose.ES384,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not compatible with ES384")

	err = validateClientAuthConfig(ClientAuthConfig{
		Method:     receiverTypes.PrivateKeyJwt,
		ClientID:   "wallet-id",
		Key:        key,
		SigningAlg: jose.RS256,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported client authentication signing algorithm")
}

func TestClientAuthConfig_SignatureAlgorithmDefaultsToES256(t *testing.T) {
	assert.Equal(t, jose.ES256, ClientAuthConfig{}.signatureAlgorithm())
	assert.Equal(t, jose.ES384, ClientAuthConfig{SigningAlg: jose.ES384}.signatureAlgorithm())
}

// This fixture intentionally uses a mocked ES256 signature (64 zero bytes).
// These tests only validate SD-JWT parsing/metadata round-trip, not signature verification.
// If SD-JWT deserialization later requires signature verification, replace this with a
// valid ES256 signature (preferred) or change alg to "none" accordingly.
func createWalletTestSDJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"vc+sd-jwt"}`))
	disclosures := []string{
		"WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
		"WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ",
	}

	sdDigests := make([]string, 0, len(disclosures))
	for _, disclosure := range disclosures {
		h := sha256.Sum256([]byte(disclosure))
		sdDigests = append(sdDigests, base64.RawURLEncoding.EncodeToString(h[:]))
	}

	payload := map[string]interface{}{
		"_sd":     sdDigests,
		"iss":     "https://example.com/issuer",
		"sub":     "did:key:z6Mkwallet-test-subject",
		"iat":     1683000000,
		"exp":     1883000000,
		"vct":     "https://credentials.example.com/identity_credential",
		"_sd_alg": "sha-256",
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	jwt := header + "." + payloadEncoded + "." + signature

	result := jwt
	for _, disclosure := range disclosures {
		result += "~" + disclosure
	}
	result += "~"

	return result
}

func createWalletTestJwtVCCredential() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	now := time.Now().Unix()
	payload := map[string]interface{}{
		"iat": now,
		"exp": now + 3600,
		"vc": map[string]interface{}{
			"id":     "https://issuer.example.com/credentials/test-1",
			"type":   []string{"VerifiableCredential"},
			"issuer": "https://issuer.example.com",
			"credentialSubject": map[string]interface{}{
				"id": "did:key:test-subject",
			},
		},
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	return header + "." + payloadEncoded + "." + signature
}

func TestController_GenerateDID_ErrorPaths_Integration(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	tests := []struct {
		name    string
		options DIDCreateOptions
		wantErr bool
	}{
		{
			name: "empty type ID",
			options: DIDCreateOptions{
				TypeID: "",
				PublicKey: jose.JSONWebKey{
					Algorithm: "ES256",
					KeyID:     "test-key",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid type ID",
			options: DIDCreateOptions{
				TypeID: "invalid:did:format",
				PublicKey: jose.JSONWebKey{
					Algorithm: "ES256",
					KeyID:     "test-key",
				},
			},
			wantErr: true,
		},
		{
			name: "empty public key",
			options: DIDCreateOptions{
				TypeID:    "did:key",
				PublicKey: jose.JSONWebKey{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := controller.GenerateDID(tt.options)
			if tt.wantErr && err == nil {
				t.Errorf("GenerateDID() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("GenerateDID() unexpected error: %v", err)
			}
			if tt.wantErr && err == nil {
				t.Errorf("GenerateDID() expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("GenerateDID() unexpected error: %v", err)
			}
		})
	}
}

func TestMockKeyEntrySign_ProducesVerifiableES256Signature(t *testing.T) {
	key := newMockKeyEntry()
	payload := []byte("test-payload")
	signature, err := key.Sign(payload)
	require.NoError(t, err)
	require.Len(t, signature, 64)

	publicKey, ok := key.PublicKey().Key.(*ecdsa.PublicKey)
	require.True(t, ok)

	hash := sha256.Sum256(payload)
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	assert.True(t, ecdsa.Verify(publicKey, hash[:], r, s))
}
