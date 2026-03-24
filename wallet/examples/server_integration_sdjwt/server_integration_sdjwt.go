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
// Both modes follow the same flow: seed credential -> build wallet -> get OID4VP request URI -> present.
// The only differences are runtime inputs (request URI source, certificate pool, selected claims).

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/examples/common"
	"github.com/trustknots/vcknots/wallet/idprof"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// fetchOID4VPURIFromServer constructs a presentation definition from the credential,
// sends it to the local server, and returns the OID4VP authorization request URI.
func fetchOID4VPURIFromServer(receivedCredential *wallet.SavedCredential, logger *slog.Logger) string {
	verifierURL := "http://localhost:8080"

	logger.Info("Verifier Details", "URL", verifierURL)
	logger.Info("Using received credential for presentation", "credential_id", receivedCredential.Entry.Id)
	logger.Info("Decoding received credential")

	var subjectFields []string
	if receivedCredential.Credential.Claims != nil {
		for field := range *receivedCredential.Credential.Claims {
			if field != "iss" && field != "iat" && field != "exp" && field != "vct" &&
				field != "cnf" && field != "_sd" && field != "_sd_alg" {
				subjectFields = append(subjectFields, field)
			}
		}
	}

	var vctValue string
	if receivedCredential.Credential.Claims != nil {
		if vct, ok := (*receivedCredential.Credential.Claims)["vct"]; ok {
			if vctStr, ok := vct.(string); ok {
				vctValue = vctStr
			}
		}
	}

	logger.Info(
		"Credential analysis",
		"issuer", receivedCredential.Credential.Issuer,
		"vct", vctValue,
		"available_fields", subjectFields,
	)

	specificType := vctValue
	if specificType == "" {
		specificType = "urn:eudi:pid:1"
	}

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

	formattedJSON, err := json.MarshalIndent(requestBody, "", "  ")
	if err != nil {
		panic(err)
	}
	logger.Info("Generated presentation definition:")
	fmt.Println(string(formattedJSON))

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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error("Server returned error response", "status", resp.StatusCode, "body", bodyStr)
		panic(fmt.Sprintf("server error: %s - %s", resp.Status, bodyStr))
	}

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
func buildCertPool(isConformanceMode bool) *x509.CertPool {
	if isConformanceMode {
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			panic(fmt.Sprintf("failed to load system cert pool: %v", err))
		}
		return systemRoots
	}

	certPath := os.Getenv("VCKNOTS_CERT_PATH")
	if certPath == "" {
		certPath = common.DefaultCertPath
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

	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		panic(err)
	}

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

	certPool := buildCertPool(isConformanceMode)
	p := &oid4vp.Oid4vpPresenter{
		X509TrustChainRoots:    certPool,
		InsecureSkipX509Verify: isConformanceMode,
	}
	presenterDisp, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, p))
	if err != nil {
		panic(err)
	}

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

	mockKey := common.NewMockKeyEntry()

	deserializedCred, err := serializerDisp.DeserializeCredential(credential.SDJwtVC, savedSdJwtCredEntry.Raw)
	if err != nil {
		panic(err)
	}
	savedCred := &wallet.SavedCredential{
		Credential: deserializedCred,
		Entry:      savedSdJwtCredEntry,
	}
	logger.Info("Deserialized credential", "issuer", deserializedCred.Issuer, "claims", deserializedCred.Claims)

	var oid4vpURI string
	var options *sdjwtvc.SdJwtVcPresentationOptions

	if isConformanceMode {
		oid4vpURI = os.Args[1]
		logger.Info("Using OID4VP URI from command line", "uri", oid4vpURI)

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

	logger.Info("Presenting credential...")
	err = w.PresentCredential(oid4vpURI, mockKey, options)
	if err != nil {
		logger.Error("Failed to present credential", "error", err)
		os.Exit(1)
	}
	logger.Info("Credential presented successfully!")
}
