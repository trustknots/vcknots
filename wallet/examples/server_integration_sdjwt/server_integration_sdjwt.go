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
//   - Usage: go run server_integration_sdjwt.go
//
// Mode 2: Conformance Test (with OID4VP URI argument)
//   - Tests against external conformance test services
//   - Usage: go run server_integration_sdjwt.go "<OID4VP_URI>"
//   - Example: go run server_integration_sdjwt.go "openid4vp://authorize?client_id=...&request_uri=..."
//
// Both modes follow the same flow: seed credential → build wallet → get OID4VP request URI → present.
// The only differences are runtime inputs (request URI source, certificate pool, selected claims).
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


// fetchOID4VPURIFromServer constructs a presentation definition from the credential,
// sends it to the local server, and returns the OID4VP authorization request URI.
func fetchOID4VPURIFromServer(receivedCredential *wallet.SavedCredential, logger *slog.Logger) string {
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
		"state":          "example-state",
		"base_url":       verifierURL,
		"is_request_uri": true,
		"response_uri":   verifierURL + "/callback",
		"client_id":      "x509_san_dns:localhost",
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
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	bodyStr := strings.TrimSpace(string(body))
	logger.Info("Authorization RequestURI", "status", resp.Status, "body", bodyStr)

	// Check if the response is an error (non-2xx status code)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error("Server returned error response", "status", resp.StatusCode, "body", bodyStr)
		panic(fmt.Sprintf("server error: %s - %s", resp.Status, bodyStr))
	}

	// check if the body is the OID4VP request URI
	urlParsed, err := url.Parse(bodyStr)
	if err != nil {
		logger.Error("Failed to parse response as URL", "error", err, "body", bodyStr)
		panic(err)
	}

	if urlParsed.Scheme != "openid4vp" {
		panic("invalid request URI scheme")
	}

	logger.Info("Request URI is valid", "scheme", urlParsed.Scheme)
	return bodyStr
}

// buildCertPool creates the appropriate certificate pool based on the mode.
// For conformance testing, it uses the system root certificate pool.
// For server integration, it loads the server's specific certificate.
func buildCertPool(isConformanceMode bool, logger *slog.Logger) *x509.CertPool {
	if isConformanceMode {
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			panic(fmt.Sprintf("failed to load system cert pool: %v", err))
		}
		return systemRoots
	}

	certPath := os.Getenv("VCKNOTS_CERT_PATH")
	if certPath == "" {
		certPath = defaultCertPath
	}
	certFile, err := os.ReadFile(certPath)
	if err != nil {
		panic(fmt.Sprintf("failed to read certificate file: %v", err))
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certFile) {
		panic("failed to parse certificate")
	}
	return certPool
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	isConformanceMode := len(os.Args) >= 2

	if isConformanceMode {
		logger.Info("=== Conformance Test Mode ===")
	} else {
		logger.Info("=== Server Integration Test Mode ===")
		logger.Info("Make sure the server is running on http://localhost:8080")
	}

	// Step 1: Clean up existing credential store
	appDir, err := os.UserConfigDir()
	if err != nil {
		logger.Error("Failed to resolve user config dir", "error", err)
		os.Exit(1)
	}
	credStorePath := fmt.Sprintf("%s/vcknots/wallet/.local_credstore.db", appDir)
	if err := os.Remove(credStorePath); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to remove credential store", "path", credStorePath, "error", err)
	} else {
		logger.Info("Cleaned up existing credential store", "path", credStorePath)
	}

	// Step 2: Create credential store and seed credential
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

	// Save example sd-jwt credential
	sdJwtCredFile, err := os.ReadFile("example_sd_jwt.txt")
	if err != nil {
		panic(err)
	}

	credID := "sample-sdjwt"
	err = credStore.SaveCredentialEntry(credstore.CredentialEntry{
		Id:         credID,
		ReceivedAt: time.Now(),
		Raw:        sdJwtCredFile,
		MimeType:   string(credential.SDJwtVC),
	}, credstore.SupportedCredStoreTypes(0))
	if err != nil {
		panic(err)
	}

	savedSdJwtCredEntry, err := credStore.GetCredentialEntry(credID, credstore.SupportedCredStoreTypes(0))
	if err != nil {
		panic(err)
	}
	logger.Info("Retrieved credential entry", "mime_type", savedSdJwtCredEntry.MimeType)

	// Step 3: Build presenter with appropriate certificate pool
	certPool := buildCertPool(isConformanceMode, logger)
	p := &oid4vp.Oid4vpPresenter{
		X509TrustChainRoots:    certPool,
		InsecureSkipX509Verify: isConformanceMode,
	}
	presenterDisp, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, p))
	if err != nil {
		panic(err)
	}

	// Step 4: Create remaining dispatchers and wallet
	receiverDisp, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

	serializerDisp, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

	verifierDisp, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

	// Create identity profiler dispatcher with default config
	idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

	w, err := wallet.NewWalletWithConfig(wallet.Config{
		CredStore:  credStore,
		IDProfiler: idProf,
		Receiver:   receiverDisp,
		Serializer: serializerDisp,
		Verifier:   verifierDisp,
		Presenter:  presenterDisp,
	})
	if err != nil {
		panic(err)
	}

	logger.Info("Starting server integration check...")

	mockKey := NewMockKeyEntry()

	// Step 5: Deserialize credential for analysis
	deserializedCred, err := serializerDisp.DeserializeCredential(credential.SDJwtVC, savedSdJwtCredEntry.Raw)
	if err != nil {
		panic(err)
	}
	savedCred := &wallet.SavedCredential{
		Credential: deserializedCred,
		Entry:      savedSdJwtCredEntry,
	}
	logger.Info("Deserialized credential", "issuer", deserializedCred.Issuer, "claims", deserializedCred.Claims)

	// Step 6: Get OID4VP URI and build presentation options
	var oid4vpURI string
	var options *sdjwtvc.SdJwtVcPresentationOptions

	if isConformanceMode {
		oid4vpURI = os.Args[1]
		logger.Info("Using OID4VP URI from command line", "uri", oid4vpURI)

		// Parse the request to extract nonce and audience for key binding
		req, err := presenterDisp.ParseRequestURI(oid4vpURI)
		if err != nil {
			logger.Error("Failed to parse OID4VP request", "error", err)
			os.Exit(1)
		}
		logger.Info("Parsed OID4VP request", "nonce", req.Nonce, "client_id", req.ClientID)

		options = &sdjwtvc.SdJwtVcPresentationOptions{
			SelectedClaims:    []string{"given_name", "family_name"},
			RequireKeyBinding: true,
			Audience:          req.ClientID,
			Nonce:             req.Nonce,
		}
	} else {
		oid4vpURI = fetchOID4VPURIFromServer(savedCred, logger)

		options = &sdjwtvc.SdJwtVcPresentationOptions{
			SelectedClaims:    []string{"given_name"},
			RequireKeyBinding: false,
		}
	}

	// Step 7: Present credential
	logger.Info("Presenting credential...")
	err = w.PresentCredential(oid4vpURI, mockKey, options)
	if err != nil {
		logger.Error("Failed to present credential", "error", err)
		os.Exit(1)
	}
	logger.Info("Credential presented successfully!")
}
