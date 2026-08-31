package main

// OID4VCI Final 1.0 Conformance Test (Issuer-Initiated, SD-JWT VC)
//
// Setup:
//  1. Open https://www.certification.openid.net/ and create a test plan:
//     - Test plan: "OpenID for Verifiable Credential Issuance 1.0 Final/HAIP: Test a Wallet"
//     - Credential Format: sd_jwt_vc
//     - Authorization Code Flow Variant: issuer_initiated
//     - Credential Offer Variant: by_value or by_reference
//  2. Run each test module; copy the openid-credential-offer:// URI shown by the suite.
//  3. Execute: go run conformance_sdjwt.go "<openid-credential-offer-uri>"

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/examples/common"
	"github.com/trustknots/vcknots/wallet/receiver"
)

const preAuthorizedGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

const (
	credentialOfferRequestTimeout  = 10 * time.Second
	maxCredentialOfferResponseSize = 1 << 20
)

var txCodeInDescriptionPattern = regexp.MustCompile(`<([^<>]+)>`)

var credentialOfferHTTPClient = &http.Client{
	Timeout: credentialOfferRequestTimeout,
	CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if !strings.EqualFold(req.URL.Scheme, "https") {
			return fmt.Errorf("credential_offer_uri redirect must use HTTPS")
		}
		return nil
	},
}

func fetchCredentialOffer(credentialOfferURI string) (string, error) {
	parsedURI, err := url.Parse(credentialOfferURI)
	if err != nil {
		return "", fmt.Errorf("invalid credential_offer_uri: %w", err)
	}
	if !strings.EqualFold(parsedURI.Scheme, "https") {
		return "", fmt.Errorf("credential_offer_uri must use HTTPS")
	}

	resp, err := credentialOfferHTTPClient.Get(parsedURI.String())
	if err != nil {
		return "", fmt.Errorf("failed to fetch credential_offer_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCredentialOfferResponseSize+1))
	if err != nil {
		return "", fmt.Errorf("failed to read credential_offer_uri response: %w", err)
	}
	if int64(len(body)) > maxCredentialOfferResponseSize {
		return "", fmt.Errorf("credential_offer_uri response exceeds %d bytes", maxCredentialOfferResponseSize)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("credential_offer_uri request failed: status=%d", resp.StatusCode)
	}
	if strings.TrimSpace(string(body)) == "" {
		return "", fmt.Errorf("credential_offer_uri response body is empty")
	}

	return string(body), nil
}

// parseCredentialOffer resolves an openid-credential-offer:// URI into a wallet.CredentialOffer.
// It supports both by_value (credential_offer param) and by_reference (credential_offer_uri param).
func parseCredentialOffer(offerURI string, logger *slog.Logger) *wallet.CredentialOffer {
	parsed, err := url.Parse(offerURI)
	if err != nil {
		logger.Error("Failed to parse offer URI", "error", err)
		panic(err)
	}

	var offerJSON string
	if v := parsed.Query().Get("credential_offer"); v != "" {
		// by_value: JSON is embedded directly in the URL parameter
		offerJSON = v
	} else if uri := parsed.Query().Get("credential_offer_uri"); uri != "" {
		offerJSON, err = fetchCredentialOffer(uri)
		if err != nil {
			logger.Error("Failed to fetch credential_offer_uri", "error", err)
			panic(err)
		}
	} else {
		panic(fmt.Errorf("neither credential_offer nor credential_offer_uri found in URI"))
	}

	logger.Info("Credential offer received")

	var offerData struct {
		CredentialIssuer           string                                  `json:"credential_issuer"`
		CredentialConfigurationIDs []string                                `json:"credential_configuration_ids"`
		Grants                     map[string]*wallet.CredentialOfferGrant `json:"grants"`
	}
	if err := json.Unmarshal([]byte(offerJSON), &offerData); err != nil {
		logger.Error("Failed to parse credential offer JSON", "error", err)
		panic(err)
	}

	issuerURL, err := url.Parse(offerData.CredentialIssuer)
	if err != nil {
		logger.Error("Failed to parse credential_issuer URL", "error", err)
		panic(err)
	}

	logger.Info("Parsed credential offer",
		"issuer", offerData.CredentialIssuer,
		"configuration_ids", offerData.CredentialConfigurationIDs,
	)

	return &wallet.CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: offerData.CredentialConfigurationIDs,
		Grants:                     offerData.Grants,
	}
}

func validateAnonymousPreAuthorizedFlow(offer *wallet.CredentialOffer) error {
	if offer == nil {
		return fmt.Errorf("credential offer is required")
	}

	grant, ok := offer.Grants[preAuthorizedGrantType]
	if !ok || grant == nil || grant.PreAuthorizedCode == "" {
		return fmt.Errorf("this sample only supports issuer_initiated pre-authorized flow (%s); configure the test plan to avoid client_attestation and provide a valid credential offer", preAuthorizedGrantType)
	}

	return nil
}

func resolveTxCode(offer *wallet.CredentialOffer, explicitTxCode string, logger *slog.Logger) (string, error) {
	if offer == nil {
		return "", fmt.Errorf("credential offer is required")
	}

	grant := offer.Grants[preAuthorizedGrantType]
	if grant == nil || grant.TxCode == nil {
		return "", nil
	}

	txCode := strings.TrimSpace(explicitTxCode)
	if txCode != "" {
		return txCode, nil
	}

	if grant.TxCode.Description != "" {
		if m := txCodeInDescriptionPattern.FindStringSubmatch(grant.TxCode.Description); len(m) == 2 {
			derived := strings.TrimSpace(m[1])
			if derived != "" {
				logger.Info("Using tx_code extracted from credential offer description")
				return derived, nil
			}
		}
	}

	return "", fmt.Errorf("tx_code is required by credential offer; pass it as 2nd arg or OID4VCI_TX_CODE")
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if len(os.Args) < 2 {
		logger.Error("Usage: conformance_sdjwt <openid-credential-offer-uri> [tx_code]")
		os.Exit(1)
	}

	explicitTxCode := strings.TrimSpace(os.Getenv("OID4VCI_TX_CODE"))
	if len(os.Args) >= 3 {
		explicitTxCode = strings.TrimSpace(os.Args[2])
	}

	// wallet.NewWalletWithConfig fills every nil field with its default implementation,
	// so passing an empty Config is sufficient for the OID4VCI-only flow.
	w, err := wallet.NewWalletWithConfig(wallet.Config{})
	if err != nil {
		logger.Error("Failed to initialize wallet", "error", err)
		os.Exit(1)
	}

	logger.Info("Wallet initialized")

	mockKey := common.NewMockKeyEntry()
	offer := parseCredentialOffer(os.Args[1], logger)
	if err := validateAnonymousPreAuthorizedFlow(offer); err != nil {
		logger.Error("Invalid test plan / offer for this sample", "error", err)
		logger.Error("Set Authorization Code Flow Variant to issuer_initiated and disable client_attestation-based client authentication")
		os.Exit(1)
	}
	txCode, err := resolveTxCode(offer, explicitTxCode, logger)
	if err != nil {
		logger.Error("Missing tx_code", "error", err)
		os.Exit(1)
	}

	savedCredential, err := w.ReceiveCredential(wallet.ReceiveCredentialRequest{
		CredentialOffer: offer,
		Type:            receiver.Oid4vci,
		Key:             mockKey,
		RequestedFormat: credential.SDJwtVC,
		TxCode:          txCode,
	})
	if err != nil {
		logger.Error("Failed to receive credential", "error", err)
		os.Exit(1)
	}

	logger.Info("=== Credential Received ===")
	logger.Info("Entry ID", "id", savedCredential.Entry.Id)
	logger.Info("MimeType", "mime_type", savedCredential.Entry.MimeType)
	logger.Info("Received At", "received_at", savedCredential.Entry.ReceivedAt)
	logger.Info("Credential payload stored")
}
