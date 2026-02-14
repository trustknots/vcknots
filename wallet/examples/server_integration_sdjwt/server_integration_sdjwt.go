package main

// Server Integration and Conformance Test Example
//
// This example supports two modes of operation:
//
// Mode 1: Server Integration Test (no arguments)
//   - Tests integration with local vcknots server
//   - Server Setup:
//     1. Start the server: pnpm -F @trustknots/server start
//     2. Server runs on: http://localhost:8080
//   - Usage: go run examples/server_integration_sdjwt/server_integration_sdjwt.go
//
// Mode 2: Conformance Test (with OID4VP URI argument)
//   - Tests against external conformance test services
//   - Uses relaxed certificate verification for test environments
//   - Usage: go run examples/server_integration_sdjwt/server_integration_sdjwt.go "<OID4VP_URI>"
//   - Example: go run examples/server_integration_sdjwt/server_integration_sdjwt.go "openid4vp://authorize?client_id=...&request_uri=..."
//
// Available Endpoints (for Mode 1):
// - Offer Endpoint: http://localhost:8080/configurations/:configurationId/offer
// - Token Endpoint: http://localhost:8080/token
// - Credential Endpoint: http://localhost:8080/credentials
// - Authorization Request (no JAR): http://localhost:8080/request
// - Authorization Request (JAR): http://localhost:8080/request-object
// - Callback: http://localhost:8080/callback
// - /.well-known/openid-credential-issuer
// - /.well-known/oauth-authorization-server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/idprof"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// Default certificate path relative to server_integration_sdjwt/ directory
const defaultCertPath = "../../../server/samples/certificate-openid-test/certificate_openid.pem"

// MockKeyEntry implements IKeyEntry interface for demo purposes
type MockKeyEntry struct {
	id         string
	privateKey *ecdsa.PrivateKey
}

func NewMockKeyEntry() *MockKeyEntry {
	// Use the specified JWK key coordinates
	// {
	//   "kty": "EC",
	//   "crv": "P-256",
	//   "x": "ezZgKwMueAyZLHUgSpzNkbOWDgjJXTAOJn8MftOnayQ",
	//   "y": "Fy_U4KyZQf-9jKpFJtH6OFFRXmwAcveyfuoDp1hSOFo",
	//   "d": "jAfOh_53IRxqpEsFojZK8iHP--L8ol3ePEo3DnwiIyM"
	// }

	// Decode base64url coordinates
	xBytes, _ := base64.RawURLEncoding.DecodeString("ezZgKwMueAyZLHUgSpzNkbOWDgjJXTAOJn8MftOnayQ")
	yBytes, _ := base64.RawURLEncoding.DecodeString("Fy_U4KyZQf-9jKpFJtH6OFFRXmwAcveyfuoDp1hSOFo")
	dBytes, _ := base64.RawURLEncoding.DecodeString("jAfOh_53IRxqpEsFojZK8iHP--L8ol3ePEo3DnwiIyM")

	// Convert to big.Int
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	d := new(big.Int).SetBytes(dBytes)

	// Create ECDSA private key
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: d,
	}

	return &MockKeyEntry{
		id:         "test-key-id", // Fixed ID for consistency
		privateKey: privateKey,
	}
}

func (m *MockKeyEntry) ID() string {
	return m.id
}

func (m *MockKeyEntry) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       &m.privateKey.PublicKey,
		Algorithm: "ES256",
		Use:       "sig",
	}
}

func (m *MockKeyEntry) Sign(payload []byte) ([]byte, error) {
	// Perform actual ECDSA signing using the private key
	hash := sha256.Sum256(payload)

	// Sign the hash using ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ECDSA: %w", err)
	}

	// Convert to IEEE P1363 format (64 bytes for P-256: 32 bytes r + 32 bytes s)
	signature := make([]byte, 64)

	// Pad r and s to 32 bytes each
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Copy r to first 32 bytes (with leading zeros if needed)
	copy(signature[32-len(rBytes):32], rBytes)
	// Copy s to last 32 bytes (with leading zeros if needed)
	copy(signature[64-len(sBytes):64], sBytes)

	return signature, nil
}


func presentation(w *wallet.Wallet, key *MockKeyEntry, receivedCredential *wallet.SavedCredential, options *sdjwtvc.SdJwtVcPresentationOptions, logger *slog.Logger) {
	// Example verifier details
	verifierURL := "http://localhost:8080"

	// Print the verifier details
	logger.Info("Verifier Details", "URL", verifierURL)

	// Verify that the received credential is available in the store
	logger.Info("Using received credential for presentation", "credential_id", receivedCredential.Entry.Id)

	// For SD-JWT format, extract claims directly from deserialized credential
	logger.Info("Decoding received credential")

	// Extract available claims from the credential
	var subjectFields []string
	if receivedCredential.Credential.Claims != nil {
		for field := range *receivedCredential.Credential.Claims {
			// Skip system fields and metadata
			if field != "iss" && field != "iat" && field != "exp" && field != "vct" && 
			   field != "cnf" && field != "_sd" && field != "_sd_alg" {
				subjectFields = append(subjectFields, field)
			}
		}
	}

	// Extract vct from claims
	var vctValue string
	if receivedCredential.Credential.Claims != nil {
		if vct, ok := (*receivedCredential.Credential.Claims)["vct"]; ok {
			if vctStr, ok := vct.(string); ok {
				vctValue = vctStr
			}
		}
	}

	logger.Info("Credential analysis",
		"issuer", receivedCredential.Credential.Issuer,
		"vct", vctValue,
		"available_fields", subjectFields)

	// Use vct as the type for SD-JWT
	specificType := vctValue
	if specificType == "" {
		specificType = "urn:eudi:pid:1"
	}

	// Build field constraints dynamically for SD-JWT format
	type Field struct {
		Path           []string               `json:"path"`
		Filter         map[string]interface{} `json:"filter,omitempty"`
		IntentToRetain *bool                  `json:"intent_to_retain,omitempty"`
	}

	fields := []Field{
		{
			Path: []string{"$.vct"},
			Filter: map[string]interface{}{
				"type":  "string",
				"const": specificType,
			},
		},
	}

	for _, field := range subjectFields {
		falseVal := false
		fields = append(fields, Field{
			Path:           []string{"$." + field},
			IntentToRetain: &falseVal,
		})
	}

	// Create presentation definition structure
	requestBody := map[string]interface{}{
		"query": map[string]interface{}{
			"presentation_definition": map[string]interface{}{
				"id": "dynamic-presentation-sdjwt",
				"input_descriptors": []map[string]interface{}{
					{
						"id":      "credential-request",
						"name":    "SD-JWT Credential",
						"purpose": "Verify credential",
						"format": map[string]interface{}{
							"dc+sd-jwt": map[string]interface{}{
								"alg": []string{"ES256"},
							},
						},
						"constraints": map[string]interface{}{
							"fields": fields,
						},
					},
				},
			},
		},
		"state":           "example-state",
		"base_url":        "http://localhost:8080",
		"is_request_uri":  true,
		"response_uri":    "http://localhost:8080/callback",
		"client_id":       "x509_san_dns:localhost",
	}

	// Marshal to formatted JSON for logging
	formattedJSON, err := json.MarshalIndent(requestBody, "", "  ")
	if err != nil {
		panic(err)
	}
	logger.Info("Generated presentation definition:")
	fmt.Println(string(formattedJSON))

	// Marshal to compact JSON for the request
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		panic(err)
	}
	reqBody := io.NopCloser(strings.NewReader(string(jsonBody)))
	req, err := http.NewRequest("POST", verifierURL+"/request-object", reqBody)
	if err != nil {
		panic(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	logger.Info("Authorization RequestURI", "status", resp.Status, "body", string(body))

	// Check if the response is an error (non-2xx status code)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error("Server returned error response", "status", resp.StatusCode, "body", string(body))
		panic(fmt.Sprintf("server error: %s - %s", resp.Status, string(body)))
	}

	// check if the body is the OID4VP request URI
	urlParsed, err := url.Parse(string(body))
	if err != nil {
		logger.Error("Failed to parse response as URL", "error", err, "body", string(body))
		panic(err)
	}

	if urlParsed.Scheme != "openid4vp" {
		panic("invalid request URI scheme")
	}

	logger.Info("Request URI is valid", "scheme", urlParsed.Scheme)

	// Present demo credential to the verifier
	err = w.PresentCredential(string(body), key, options)
	if err != nil {
		logger.Error("Failed to present credential", "error", err)
		panic(err)
	}
	logger.Info("Credential presented successfully")
}


func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Check if OID4VP URI is provided as command-line argument
	if len(os.Args) >= 2 {
		// Conformance Test Mode: Use external URL with relaxed certificate verification
		conformanceTestMode(os.Args[1], logger)
	} else {
		// Server Integration Test Mode: Use local server
		serverIntegrationMode(logger)
	}
}

// conformanceTestMode runs the wallet against an external conformance test service
// This mode uses relaxed certificate verification suitable for test environments
func conformanceTestMode(oid4vpURI string, logger *slog.Logger) {
	logger.Info("=== Conformance Test Mode ===")
	logger.Info("Testing OID4VP URI", "uri", oid4vpURI)

	// Clean up existing credentials to avoid conflicts
	appDir, _ := os.UserConfigDir()
	credStorePath := fmt.Sprintf("%s/vcknots/wallet/.local_credstore.db", appDir)
	os.Remove(credStorePath)

	// Create credential store
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		logger.Error("Failed to create credential store", "error", err)
		panic(err)
	}

	// Load test credential
	sdJwtCredFile, err := os.ReadFile("examples/server_integration_sdjwt/example_sd_jwt.txt")
	if err != nil {
		logger.Error("Failed to read credential file", "error", err)
		logger.Info("Please ensure example_sd_jwt.txt exists in server_integration_sdjwt directory")
		os.Exit(1)
	}

	err = credStore.SaveCredentialEntry(credstore.CredentialEntry{
		Id:         "conformance-test-cred",
		ReceivedAt: time.Now(),
		Raw:        sdJwtCredFile,
		MimeType:   string(credential.SDJwtVC),
	}, credstore.SupportedCredStoreTypes(0))
	if err != nil {
		logger.Error("Failed to save credential", "error", err)
		panic(err)
	}

	logger.Info("Test credential loaded")

	// Create receiver
	receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		logger.Error("Failed to create receiver", "error", err)
		panic(err)
	}

	// Create serializer
	serializer, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	if err != nil {
		logger.Error("Failed to create serializer", "error", err)
		panic(err)
	}

	// Create verifier
	verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		logger.Error("Failed to create verifier", "error", err)
		panic(err)
	}

	// Create presenter with OID4VP plugin
	// Initialize system root CA pool for x509 certificate verification
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		logger.Warn("Failed to load system cert pool, creating empty pool", "error", err)
		systemRoots = x509.NewCertPool()
	}
	
	p := &oid4vp.Oid4vpPresenter{
		X509TrustChainRoots:    systemRoots,
		InsecureSkipX509Verify: true, // Enable for conformance testing with non-standard certificates
	}
	presenter, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, p))
	if err != nil {
		logger.Error("Failed to create presenter", "error", err)
		panic(err)
	}

	// Create identity profiler
	idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
	if err != nil {
		logger.Error("Failed to create identity profiler", "error", err)
		panic(err)
	}

	// Create controller
	config := vcknots_wallet.ControllerConfig{
		CredStore:  credStore,
		IDProfiler: idProf,
		Receiver:   receiver,
		Serializer: serializer,
		Verifier:   verifier,
		Presenter:  presenter,
	}

	controller, err := vcknots_wallet.NewController(config)
	if err != nil {
		logger.Error("Failed to create controller", "error", err)
		panic(err)
	}

	// Create mock key
	mockKey := NewMockKeyEntry()

	// Parse the request to get nonce and audience (client_id)
	req, err := presenter.ParseRequestURI(oid4vpURI)
	if err != nil {
		logger.Error("Failed to parse OID4VP request", "error", err)
		os.Exit(1)
	}
	logger.Info("Parsed OID4VP request", "nonce", req.Nonce, "client_id", req.ClientID)

	// Attempt to present credential
	logger.Info("Attempting to present credential to conformance test...")
	
	// For SD-JWT VC with Key Binding, we need to provide:
	// - RequireKeyBinding: true
	// - Audience: the client_id from the authorization request
	// - Nonce: the nonce from the authorization request
	options := sdjwtvc.SdJwtVcPresentationOptions{
		SelectedClaims:    []string{"given_name", "family_name"},
		RequireKeyBinding: true,
		Audience:          req.ClientID,
		Nonce:             req.Nonce,
	}

	err = controller.PresentCredential(oid4vpURI, mockKey, &options)
	if err != nil {
		logger.Error("PresentCredential failed", "error", err)
		os.Exit(1)
	}

	logger.Info("Credential presented successfully!")
	os.Exit(0)
}

// serverIntegrationMode runs the wallet against a local vcknots server
// This mode uses strict certificate verification with a specific certificate file
func serverIntegrationMode(logger *slog.Logger) {
	logger.Info("=== Server Integration Test Mode ===")
	logger.Info("Make sure the server is running on http://localhost:8080")


	// Clean up existing credentials to avoid conflicts with old test data
	// Note: This removes ALL existing credentials. In production, use proper credential selection.
	appDir, _ := os.UserConfigDir()
	credStorePath := fmt.Sprintf("%s/vcknots/wallet/.local_credstore.db", appDir)
	os.Remove(credStorePath)
	logger.Info("Cleaned up existing credential store", "path", credStorePath)

	// Create credential store with default config
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

	// Save example sd-jwt credential
	sdJwtCredFile, err := os.ReadFile("example_sd_jwt.txt")
	if err != nil {
		panic(err)
	}
	err = credStore.SaveCredentialEntry(credstore.CredentialEntry{
		Id:         "sample-sdjwt",
		ReceivedAt: time.Now(),
		Raw:        sdJwtCredFile,
		MimeType:   string(credential.SDJwtVC),
	}, credstore.SupportedCredStoreTypes(0))
	if err != nil {
		panic(err)
	}

	savedSdJwtCredEntry, err := credStore.GetCredentialEntry("sample-sdjwt", credstore.SupportedCredStoreTypes(0))
	if err != nil {
		panic(err)
	}
	logger.Info("Retrieved credential entry", "mime_type", savedSdJwtCredEntry.MimeType)

	// Create receiver with default config
	receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

	serializer, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

	// Create verifier with default config
	verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

	// Create presenter with default config
	// Load the server's certificate for TLS verification
	certPath := os.Getenv("VCKNOTS_CERT_PATH")
	if certPath == "" {
		certPath = defaultCertPath
	}
	certFile, err := os.ReadFile(certPath)
	if err != nil {
		panic(err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certFile) {
		panic("Failed to parse certificate")
	}
	p := &oid4vp.Oid4vpPresenter{
		X509TrustChainRoots: certPool,
	}
	presenter, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, p))
	if err != nil {
		panic(err)
	}

	// Create identity profiler dispatcher with default config
	idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

	config := wallet.Config{
		CredStore:  credStore,
		IDProfiler: idProf,
		Receiver:   receiver,
		Serializer: serializer,
		Verifier:   verifier,
		Presenter:  presenter,
	}

	w, err := wallet.NewWalletWithConfig(config)
	if err != nil {
		panic(err)
	}

	logger.Info("Starting server integration check...")

	mockKey := NewMockKeyEntry()

	// deserialized
	deserializedSdJwtCred, err := serializer.DeserializeCredential(credential.SDJwtVC, savedSdJwtCredEntry.Raw)
	if err != nil {
		panic(err)
	}
	savedSdJwtCred := wallet.SavedCredential{
		Credential: deserializedSdJwtCred,
		Entry:      savedSdJwtCredEntry,
	}
	logger.Info("Deserialized credential", "credential.issuer", deserializedSdJwtCred.Issuer, "credential.claims", deserializedSdJwtCred.Claims)

	options := sdjwtvc.SdJwtVcPresentationOptions{
		SelectedClaims:    []string{"given_name"},
		RequireKeyBinding: false,
	}
	presentation(w, mockKey, &savedSdJwtCred, &options, logger)
}
