package main

// Server Integration Example
//
// This example demonstrates how to integrate the wallet with the vcknots server.
//
// Server Setup:
// 1. Start the server: pnpm -F @trustknots/server start
// 2. Server runs on: http://localhost:8080
//
// Available Endpoints:
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
	"github.com/trustknots/vcknots/wallet/internal/credential"
	"github.com/trustknots/vcknots/wallet/internal/credstore"
	"github.com/trustknots/vcknots/wallet/internal/idprof"
	"github.com/trustknots/vcknots/wallet/internal/presenter"
	"github.com/trustknots/vcknots/wallet/internal/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/internal/receiver"
	"github.com/trustknots/vcknots/wallet/internal/serializer"
	"github.com/trustknots/vcknots/wallet/internal/serializer/plugins/sdjwtvc"
	"github.com/trustknots/vcknots/wallet/internal/verifier"
	"github.com/trustknots/vcknots/wallet/pkg/vcknots_wallet"
)

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


func presentation(controller *vcknots_wallet.Controller, key *MockKeyEntry, receivedCredential *vcknots_wallet.SavedCredential, options *sdjwtvc.SdJwtVcPresentationOptions, logger *slog.Logger) {
	// Example verifier details
	verifierURL := "http://localhost:8080"

	// Print the verifier details
	logger.Info("Verifier Details", "URL", verifierURL)

	// Verify that the received credential is available in the store
	logger.Info("Using received credential for presentation", "credential_id", receivedCredential.Entry.Id)

	// Decode the JWT to inspect the credential
	jwtString := string(receivedCredential.Entry.Raw)
	logger.Info("Decoding received credential JWT")

	// Parse JWT (format: header.payload.signature)
	parts := strings.Split(jwtString, ".")
	if len(parts) != 3 {
		logger.Error("Invalid JWT format", "parts", len(parts))
		panic(fmt.Errorf("invalid JWT format"))
	}

	// Decode the payload (second part)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		logger.Error("Failed to decode JWT payload", "error", err)
		panic(err)
	}

	// Parse the credential payload
	var credential map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &credential); err != nil {
		logger.Error("Failed to parse credential payload", "error", err)
		panic(err)
	}

	logger.Info("Decoded credential", "credential", credential)

	// Extract credential type
	var credentialTypes []string
	if vc, ok := credential["vc"].(map[string]interface{}); ok {
		if types, ok := vc["type"].([]interface{}); ok {
			for _, t := range types {
				if typeStr, ok := t.(string); ok {
					credentialTypes = append(credentialTypes, typeStr)
				}
			}
		}
	}

	// Extract credentialSubject fields
	var subjectFields []string
	if vc, ok := credential["vc"].(map[string]interface{}); ok {
		if credentialSubject, ok := vc["credentialSubject"].(map[string]interface{}); ok {
			for field := range credentialSubject {
				subjectFields = append(subjectFields, field)
			}
		}
	}

	logger.Info("Credential analysis",
		"types", credentialTypes,
		"subject_fields", subjectFields)

	specificType := "Hoge"

	// Build field constraints dynamically
	fieldsJSON := `[
		{
			"path": ["$.type"],
			"filter": {
				"type": "array",
				"contains": {"const": "` + specificType + `"}
			}
		}`

	for _, field := range subjectFields {
		if field != "id" { // Skip id field
			fieldsJSON += `,
		{
			"path": ["$.credentialSubject.` + field + `"],
			"intent_to_retain": false
		}`
		}
	}
	fieldsJSON += `
	]`

	// Create presentation definition based on the decoded credential
	jsonBody := `{
		"query": {
			"presentation_definition": {
			"id": "dynamic-presentation-` + specificType + `",
			"input_descriptors": [
			{
				"id": "credential-request",
				"name": "` + specificType + `",
				"purpose": "Verify credential",
				"format": {
				"jwt_vc_json": {
					"alg": ["ES256"]
				}
				},
				"constraints": {
				"fields": ` + fieldsJSON + `
				}
			}
			]
		}
		},
		"state": "example-state",
		"base_url": "http://localhost:8080",
		"is_request_uri": true,
		"response_uri": "http://localhost:8080/callback",
		"client_id": "x509_san_dns:localhost"
	}`

	logger.Info("Generated presentation definition", "json", jsonBody)
	reqBody := io.NopCloser(strings.NewReader(jsonBody))
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

	// check if the body is the OID4VP request URI
	urlParsed, err := url.Parse(string(body))
	if err != nil {
		panic(err)
	}

	if urlParsed.Scheme != "openid4vp" {
		panic("invalid request URI scheme")
	}

	logger.Info("Request URI is valid", "scheme", urlParsed.Scheme)

	// Present demo credential to the verifier
	err = controller.PresentCredential(string(body), key, options)
	if err != nil {
		logger.Error("Failed to present credential", "error", err)
		panic(err)
	}
	logger.Info("Credential presented successfully")
}


func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create credential store with default config
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		panic(err)
	}
	// Save example sd-jwt credential
	sdJwtCredFile, err := os.ReadFile("./examples/server_integration_sdjwt/example_sd_jwt.txt")
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
	certFile, err := os.ReadFile("../server/samples/certificate-openid-test/certificate_openid.pem")
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
		panic(err)
	}

	logger.Info("Starting server integration check...")

	mockKey := NewMockKeyEntry()

	// deserialized
	deserializedSdJwtCred, err := serializer.DeserializeCredential(credential.SDJwtVC, savedSdJwtCredEntry.Raw)
	if err != nil {
		panic(err)
	}
	savedSdJwtCred := vcknots_wallet.SavedCredential{
		Credential: deserializedSdJwtCred,
		Entry:      savedSdJwtCredEntry,
	}
	logger.Info("Deserialized credential", "credential.issuer", deserializedSdJwtCred.Issuer, "credential.claims", deserializedSdJwtCred.Claims)

	options := sdjwtvc.SdJwtVcPresentationOptions{
		SelectedClaims:    []string{"given_name"},
		RequireKeyBinding: false,
	}
	presentation(controller, mockKey, &savedSdJwtCred, &options, logger)
}
