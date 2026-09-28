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
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/examples/common"
)

const requestTimeout = 10 * time.Second

// credentialOfferURIPrefix is the expected scheme/prefix of an OID4VCI credential offer URI.
const credentialOfferURIPrefix = "openid-credential-offer://?credential_offer="

var httpClient = &http.Client{
	Timeout: requestTimeout,
}

type runOptions struct {
	CredentialOfferURI string
	TxCode             string
}

func parseRunOptions(args []string) (runOptions, error) {
	var opts runOptions
	fs := flag.NewFlagSet("server_integration_jwtvc", flag.ContinueOnError)
	fs.StringVar(&opts.CredentialOfferURI, "credential-offer-uri", "", "openid-credential-offer URI to use instead of fetching one from the local server")
	fs.StringVar(&opts.TxCode, "tx-code", "", "tx_code to send to the token endpoint")
	fs.StringVar(&opts.TxCode, "tx_code", "", "tx_code to send to the token endpoint")

	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if rest := fs.Args(); len(rest) > 0 {
		return opts, fmt.Errorf("unexpected positional arguments: %s", strings.Join(rest, ", "))
	}
	if err := opts.validate(); err != nil {
		return opts, err
	}

	return opts, nil
}

// validate checks the parsed configuration before the integration flow starts.
func (o runOptions) validate() error {
	if o.CredentialOfferURI != "" && !strings.HasPrefix(o.CredentialOfferURI, credentialOfferURIPrefix) {
		return fmt.Errorf("--credential-offer-uri must start with %q", credentialOfferURIPrefix)
	}
	return nil
}

func serverURLFromEnv() string {
	if raw := strings.TrimSpace(os.Getenv("VCKNOTS_SERVER_URL")); raw != "" {
		return strings.TrimRight(raw, "/")
	}
	return "http://localhost:8080"
}

func receiveCredential(w *wallet.Wallet, key *common.MockKeyEntry, logger *slog.Logger, serverURL string, credentialOfferURI string, txCode string) *wallet.SavedCredential {
	offerURL := credentialOfferURI
	if offerURL == "" {
		logger.Info("Fetching credential offer from server...")

		// Fetch credential offer from the server
		offerEndpoint := serverURL + "/configurations/UniversityDegreeCredential/offer"

		resp, err := httpClient.Post(offerEndpoint, "application/json", nil)
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

		offerURL = strings.TrimSpace(string(body))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			logger.Error("Server returned error fetching offer", "status", resp.Status, "body", offerURL)
			panic(fmt.Sprintf("server error fetching offer: %s - %s", resp.Status, offerURL))
		}
	} else {
		logger.Info("Using credential offer URI from command line")
	}

	// Parse the openid-credential-offer URL
	logger.Info("Received offer URL", "url", offerURL)

	// ParseCredentialOfferURL reads the by-value offer
	// (openid-credential-offer://?credential_offer=...) without any I/O.
	credentialOffer, err := wallet.ParseCredentialOfferURL(offerURL)
	if err != nil {
		logger.Error("Failed to parse credential offer", "error", err)
		panic(err)
	}

	logger.Info("Parsed credential offer",
		"issuer", credentialOffer.CredentialIssuer.String(),
		"configs", credentialOffer.CredentialConfigurationIDs,
		"grants", len(credentialOffer.Grants))
	if txCode != "" {
		logger.Info("Using tx_code from command line")
	}

	// The local server speaks OpenID4VCI 1.0: the Pre-Authorized Code Token
	// Request (Section 6), then a Credential Request naming the
	// credential_configuration_id with a key proof for the holder key
	// (Section 8). The wallet's Config.CredentialAcceptance authenticates the
	// issuer before the credential is stored.
	ctx := context.Background()
	grant, err := w.AuthorizePreAuthorizedIssuance(ctx, wallet.PreAuthorizedIssuanceRequest{
		CredentialOffer: credentialOffer,
		TxCode:          txCode,
	})
	if err != nil {
		logger.Error("Failed to obtain an access token", "error", err)
		panic(err)
	}
	result, err := w.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{key},
	})
	if err != nil {
		logger.Error("Failed to receive credential", "error", err)
		panic(err)
	}
	if result.Deferred != nil || len(result.Credentials) == 0 {
		logger.Error("The issuer deferred the credential; this sample does not poll")
		panic(fmt.Errorf("credential issuance was deferred"))
	}
	savedCredential := result.Credentials[0]

	logger.Info("Successfully imported demo credential via wallet.RequestCredential",
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

func presentation(w *wallet.Wallet, key *common.MockKeyEntry, receivedCredential *wallet.SavedCredential, logger *slog.Logger, serverURL string) {
	// Print the verifier details
	logger.Info("Verifier Details", "URL", serverURL)

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

	// Create DCQL query based on the decoded credential
	jsonBody := `{
		"query": {
			"dcql_query": {
				"credentials": [
					{
						"id": "credential-request",
						"format": "jwt_vc_json",
						"meta": {
							"type_values": [["` + specificType + `"]]
						}
					}
				]
			}
		},
		"state": "example-state",
		"base_url": "` + serverURL + `",
		"is_request_uri": true,
		"response_uri": "` + serverURL + `/callback",
		"client_id": "x509_san_dns:localhost"
	}`

	logger.Info("Generated DCQL query", "json", jsonBody)
	reqBody := io.NopCloser(strings.NewReader(jsonBody))
	req, err := http.NewRequest("POST", serverURL+"/request-object", reqBody)
	if err != nil {
		panic(err)
	}

	resp, err := httpClient.Do(req)
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
	redirectURI, err := common.PresentAll(context.Background(), w, string(body), key, nil)
	if err != nil {
		logger.Error("Failed to present credential", "error", err)
		panic(err)
	}
	if redirectURI != "" {
		logger.Info("Verifier requested redirect", "redirect_uri", redirectURI)
	}
	logger.Info("Credential presented successfully")
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	opts, err := parseRunOptions(os.Args[1:])
	if err != nil {
		logger.Error("Invalid arguments", "error", err)
		os.Exit(2)
	}

	// The local sample server listens on plain http.
	runtime, err := common.NewOID4VPRuntime(os.Getenv("VCKNOTS_CERT_PATH"), true)
	if err != nil {
		panic(err)
	}
	w := runtime.Wallet

	logger.Info("Starting server integration check...")
	serverURL := serverURLFromEnv()

	mockKey := common.NewMockKeyEntry()
	receivedCredential := receiveCredential(w, mockKey, logger, serverURL, opts.CredentialOfferURI, opts.TxCode)

	// Tests - Use the received credential for presentation
	presentation(w, mockKey, receivedCredential, logger, serverURL)
}
