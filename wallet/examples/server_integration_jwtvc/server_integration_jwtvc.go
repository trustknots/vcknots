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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/examples/common"
	"github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func receiveCredential(w *wallet.Wallet, key *common.MockKeyEntry, logger *slog.Logger) *wallet.SavedCredential {
	logger.Info("Fetching credential offer from server...")

	// Fetch credential offer from the server
	serverURL := "http://localhost:8080"
	offerEndpoint := serverURL + "/configurations/UniversityDegreeCredential/offer"

	resp, err := http.Post(offerEndpoint, "application/json", nil)
	if err != nil {
		logger.Error("Failed to fetch credential offer", "error", err)
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read offer response", "error", err)
		panic(err)
	}

	// Parse the openid-credential-offer URL
	offerURL := string(body)
	logger.Info("Received offer URL", "url", offerURL)

	// Extract the credential_offer parameter from the URL
	// Format: openid-credential-offer://?credential_offer={encoded-json}
	if !strings.HasPrefix(offerURL, "openid-credential-offer://?credential_offer=") {
		logger.Error("Invalid offer URL format", "url", offerURL)
		panic(fmt.Errorf("invalid offer URL format"))
	}

	encodedOffer := strings.TrimPrefix(offerURL, "openid-credential-offer://?credential_offer=")
	decodedOffer, err := url.QueryUnescape(encodedOffer)
	if err != nil {
		logger.Error("Failed to decode offer", "error", err)
		panic(err)
	}

	logger.Info("Decoded offer", "offer", decodedOffer)

	// Parse the credential offer JSON
	var offerData map[string]interface{}
	if err := json.Unmarshal([]byte(decodedOffer), &offerData); err != nil {
		logger.Error("Failed to parse offer JSON", "error", err)
		panic(err)
	}

	// Extract credential_issuer
	credentialIssuerStr, ok := offerData["credential_issuer"].(string)
	if !ok {
		logger.Error("Missing credential_issuer in offer")
		panic(fmt.Errorf("missing credential_issuer"))
	}

	credentialIssuerURL, err := url.Parse(credentialIssuerStr)
	if err != nil {
		logger.Error("Failed to parse credential issuer URL", "error", err)
		panic(err)
	}

	// Extract credential_configuration_ids
	configIDs := []string{}
	if ids, ok := offerData["credential_configuration_ids"].([]interface{}); ok {
		for _, id := range ids {
			if idStr, ok := id.(string); ok {
				configIDs = append(configIDs, idStr)
			}
		}
	}

	// Extract grants
	grants := make(map[string]*wallet.CredentialOfferGrant)
	if grantsData, ok := offerData["grants"].(map[string]interface{}); ok {
		for grantType, grantValue := range grantsData {
			if grantMap, ok := grantValue.(map[string]interface{}); ok {
				grant := &wallet.CredentialOfferGrant{}
				if preAuthCode, ok := grantMap["pre-authorized_code"].(string); ok {
					grant.PreAuthorizedCode = preAuthCode
				}
				grants[grantType] = grant
			}
		}
	}

	credentialOffer := &wallet.CredentialOffer{
		CredentialIssuer:           credentialIssuerURL,
		CredentialConfigurationIDs: configIDs,
		Grants:                     grants,
	}

	logger.Info("Parsed credential offer",
		"issuer", credentialIssuerURL.String(),
		"configs", configIDs,
		"grants", len(grants))

	// Create ReceiveCredentialRequest using OID4VCI
	receiveReq := wallet.ReceiveCredentialRequest{
		CredentialOffer: credentialOffer,
		Type:            types.Oid4vci,
		Key:             key,
	}

	// Use w.ReceiveCredential with proper parameters
	savedCredential, err := w.ReceiveCredential(receiveReq)
	if err != nil {
		logger.Error("Failed to receive credential via controller", "error", err)
		panic(err)
	}

	logger.Info("Successfully imported demo credential via wallet.ReceiveCredential",
		"entry_id", savedCredential.Entry.Id,
		"raw_length", len(savedCredential.Entry.Raw),
	)

	// Display received credential details
	logger.Info("=== Received Credential Details ===")
	logger.Info("Credential Entry ID", "id", savedCredential.Entry.Id)
	logger.Info("Credential MimeType", "mime_type", savedCredential.Entry.MimeType)
	logger.Info("Credential Received At", "received_at", savedCredential.Entry.ReceivedAt)
	logger.Info("Credential Raw Content", "raw", string(savedCredential.Entry.Raw))

	// Try to parse and display as JSON for better readability
	var credentialJSON map[string]interface{}
	if err := json.Unmarshal(savedCredential.Entry.Raw, &credentialJSON); err == nil {
		prettyJSON, err := json.MarshalIndent(credentialJSON, "", "  ")
		if err == nil {
			logger.Info("Credential Content (formatted)", "json", string(prettyJSON))
		}
	}

	// Display stored credentials
	getEntriesReq := wallet.GetCredentialEntriesRequest{}

	credentials, totalCount, err := w.GetCredentialEntries(getEntriesReq)
	if err != nil {
		logger.Error("Failed to get credential entries", "error", err)
		panic(err)
	}

	logger.Info("Stored credentials", "count", len(credentials), "total", totalCount)

	return savedCredential
}

func presentation(w *wallet.Wallet, key *common.MockKeyEntry, receivedCredential *wallet.SavedCredential, options *sdjwtvc.SdJwtVcPresentationOptions, logger *slog.Logger) {
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

	// Determine the specific credential type (excluding VerifiableCredential)
	var specificType string
	for _, t := range credentialTypes {
		if t != "VerifiableCredential" {
			specificType = t
			break
		}
	}

	if specificType == "" {
		logger.Error("No specific credential type found")
		panic(fmt.Errorf("no specific credential type found"))
	}

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
	w := runtime.Wallet

	logger.Info("Starting server integration check...")

	mockKey := common.NewMockKeyEntry()
	receivedCredential := receiveCredential(w, mockKey, logger)

	// Tests - Use the received credential for presentation
	presentation(w, mockKey, receivedCredential, nil, logger)
}
