package main

// Server Integration Example with Key Binding JWT
//
// This example demonstrates how to present an SD-JWT with KB-JWT to the
// vcknots sample server.
//
// Server Setup:
// 1. Start the server: pnpm -F @trustknots/server start
// 2. Server runs on: http://localhost:8080
//
// Available Endpoints used by this sample:
// - Authorization Request (JAR): http://localhost:8080/request-object
// - Key Binding Callback: http://localhost:8080/callback-kbjwt

import (
	"encoding/base64"
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
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

const (
	verifierURL = "http://localhost:8080"
	responseURI = verifierURL + "/callback-kbjwt"
	clientID    = "x509_san_dns:localhost"
)

func parseSDJWTPayload(raw []byte) (map[string]any, error) {
	cf := sdjwtvc.ParseCombinedFormatForPresentation(string(raw))
	if cf.SDJWT == "" {
		return nil, fmt.Errorf("credential does not contain a valid SD-JWT")
	}

	parts := strings.Split(cf.SDJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid SD-JWT format: expected 3 JWT parts, got %d", len(parts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode SD-JWT payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse SD-JWT payload: %w", err)
	}

	return payload, nil
}

func extractDisclosureNames(raw []byte) []string {
	cf := sdjwtvc.ParseCombinedFormatForPresentation(string(raw))
	names := make([]string, 0, len(cf.Disclosures))

	for _, disclosure := range cf.Disclosures {
		decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
		if err != nil {
			continue
		}

		var item []any
		if err := json.Unmarshal(decoded, &item); err != nil {
			continue
		}
		if len(item) < 2 {
			continue
		}

		name, ok := item[1].(string)
		if !ok || name == "" {
			continue
		}
		names = append(names, name)
	}

	return names
}

func buildRequestObjectJSON(vct string, subjectFields []string) string {
	fieldsJSON := ""
	if vct != "" {
		fieldsJSON += `[
		{
			"path": ["$.vct"],
			"filter": {
				"type": "string",
				"const": "` + vct + `"
			}
		}`

		for _, field := range subjectFields {
			fieldsJSON += `,
		{
			"path": ["$.` + field + `"],
			"intent_to_retain": false
		}`
		}
		fieldsJSON += `
	]`
	}

	constraintsJSON := ""
	if fieldsJSON != "" {
		constraintsJSON = `,
				"constraints": {
					"fields": ` + fieldsJSON + `
				}`
	}

	return `{
		"query": {
			"presentation_definition": {
				"id": "dynamic-presentation-kbjwt",
				"input_descriptors": [
					{
						"id": "credential-request",
						"name": "SD-JWT VC with KB-JWT",
						"purpose": "Verify credential with key binding",
						"format": {
							"dc+sd-jwt": {
								"sd-jwt_alg_values": ["ES256"],
								"kb-jwt_alg_values": ["ES256"]
							}
						}` + constraintsJSON + `
					}
				]
			}
		},
		"state": "example-state-kbjwt",
		"base_url": "` + verifierURL + `",
		"is_request_uri": true,
		"response_uri": "` + responseURI + `",
		"client_id": "` + clientID + `"
	}`
}

func filterRequestedClaims(available []string, selected []string) []string {
	if len(selected) == 0 {
		return available
	}

	availableSet := make(map[string]struct{}, len(available))
	for _, name := range available {
		availableSet[name] = struct{}{}
	}

	filtered := make([]string, 0, len(selected))
	for _, name := range selected {
		if _, ok := availableSet[name]; ok {
			filtered = append(filtered, name)
		}
	}
	return filtered
}

func presentation(w *wallet.Wallet, key *common.MockKeyEntry, receivedCredential *wallet.SavedCredential, options *sdjwtvc.SdJwtVcPresentationOptions, logger *slog.Logger) {
	logger.Info("Verifier Details", "URL", verifierURL)
	logger.Info(
		"Key binding presentation settings",
		"format", "dc+sd-jwt",
		"response_uri", responseURI,
		"client_id", clientID,
		"require_key_binding", options.RequireKeyBinding,
		"audience", "resolved from request object",
		"nonce", "resolved from request object",
	)
	logger.Info("Using received credential for presentation", "credential_id", receivedCredential.Entry.Id)

	payload, err := parseSDJWTPayload(receivedCredential.Entry.Raw)
	if err != nil {
		logger.Error("Failed to parse SD-JWT payload", "error", err)
		panic(err)
	}
	logger.Info("Decoded SD-JWT payload", "payload", payload)

	vct, _ := payload["vct"].(string)
	disclosureNames := extractDisclosureNames(receivedCredential.Entry.Raw)
	requestedClaims := filterRequestedClaims(disclosureNames, options.SelectedClaims)
	logger.Info(
		"Credential analysis",
		"vct", vct,
		"available_disclosed_fields", disclosureNames,
		"requested_fields", requestedClaims,
	)

	jsonBody := buildRequestObjectJSON(vct, requestedClaims)
	logger.Info("Generated presentation definition", "json", jsonBody)

	reqBody := io.NopCloser(strings.NewReader(jsonBody))
	req, err := http.NewRequest("POST", verifierURL+"/request-object", reqBody)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/plain")

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

	urlParsed, err := url.Parse(string(body))
	if err != nil {
		panic(err)
	}
	if urlParsed.Scheme != "openid4vp" {
		panic("invalid request URI scheme")
	}
	logger.Info("Request URI is valid", "scheme", urlParsed.Scheme)

	err = w.PresentCredential(string(body), key, options)
	if err != nil {
		logger.Error("Failed to present credential", "error", err)
		panic(err)
	}
	logger.Info("Credential presented successfully")
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	runtime, err := common.NewOID4VPRuntime(os.Getenv("VCKNOTS_CERT_PATH"))
	if err != nil {
		panic(err)
	}
	credStore := runtime.CredStore
	serializer := runtime.Serializer
	w := runtime.Wallet

	sdJwtCredFile, err := os.ReadFile("example_sd_jwt.txt")
	if err != nil {
		panic(err)
	}
	sdJwtCredFile = []byte(strings.TrimRight(string(sdJwtCredFile), "\r\n"))
	err = credStore.SaveCredentialEntry(credstore.CredentialEntry{
		Id:         "sample-sdjwt-kbjwt",
		ReceivedAt: time.Now(),
		Raw:        sdJwtCredFile,
		MimeType:   string(credential.SDJwtVC),
	}, credstore.SupportedCredStoreTypes(0))
	if err != nil {
		panic(err)
	}

	savedSdJwtCredEntry, err := credStore.GetCredentialEntry("sample-sdjwt-kbjwt", credstore.SupportedCredStoreTypes(0))
	if err != nil {
		panic(err)
	}

	logger.Info("Starting SD-JWT + KB-JWT server integration check...")

	mockKey := common.NewMockKeyEntry()

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
		RequireKeyBinding: true,
	}

	presentation(w, mockKey, &savedSdJwtCred, &options, logger)
}
