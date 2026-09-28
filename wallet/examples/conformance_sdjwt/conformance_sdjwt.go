package main

// OID4VCI Final 1.0 Conformance Test (Issuer-Initiated, SD-JWT VC)
//
// Setup:
//  1. Open https://www.certification.openid.net/ and create a test plan:
//     - Test plan: "OpenID for Verifiable Credential Issuance 1.0 Final/HAIP: Test a Wallet"
//     - Credential Format: sd_jwt_vc
//     - Authorization Code Flow Variant: issuer_initiated
//     - Credential Offer Variant: by_value or by_reference
//     - Client Authentication Type: private_key_jwt
//     - Sender Constrain: none or dpop
//
//     none is not selectable here; mtls is unimplemented, and this sample does
//     not configure client_attestation.
//
//  2. Match the wallet to the variants picked above. The suite rejects the token
//     request before issuing anything when the two disagree, so nothing here is
//     configured implicitly; with no environment set no test plan accepts it.
//
//     client_auth_type=private_key_jwt:
//
//     export OID4VCI_CLIENT_CONFIG=./conformance-clients.json
//     export OID4VCI_CLIENT_ID=<client_id registered with the test plan>
//     export OID4VCI_CLIENT_PRIVATE_JWK=./conformance-client-private.jwks.json
//
//     OID4VCI_CLIENT_CONFIG points at a client registration in the format
//     wallet/clientconfig reads; ../config/wallet-clients.json shows the shape.
//     Register the public half of the signing key (that file's jwks member) with
//     the test plan as the client's JWKS, otherwise the suite cannot verify the
//     client_assertion signature. The private key stays in a separate file, which
//     must be mode 0600 unless OID4VCI_ALLOW_INSECURE_KEY_PERMS=1 is set.
//
//     Reusing ../config/wallet-clients.json needs one more variable, because it
//     pins client_assertion_audience at the local sample authorization server:
//
//     export OID4VCI_CLIENT_ASSERTION_AUDIENCE=
//
//     The empty value clears that override so the aud claim follows the issuer
//     the suite advertises, which is what it checks the assertion against.
//
//     Authorization servers that advertise none (not the conformance suite):
//
//     export OID4VCI_CLIENT_ID=<client_id the authorization server knows>
//
//     For a server advertising none but omitting
//     pre-authorized_grant_anonymous_access_supported, which 12.3 defaults false.
//
//     sender_constrain=dpop:
//
//     export OID4VCI_DPOP=1
//
//  3. Run each test module; copy the openid-credential-offer:// URI shown by the suite.
//  4. Execute: go run conformance_sdjwt.go "<openid-credential-offer-uri>" [tx_code]
//     VCKNOTS_ISSUER_CA_PATH names a PEM file with the certificate authority the
//     suite signs its SD-JWT VC (x5c) with.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/clientconfig"
	"github.com/trustknots/vcknots/wallet/examples/common"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

const preAuthorizedGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// Environment variables that match the wallet to the test plan variants.
//
// The conformance suite fixes client_auth_type and sender_constrain per test
// plan and advertises them in the authorization server metadata. Configuring
// the wallet differently is not a soft mismatch: the token endpoint rejects the
// request with invalid_client before any credential is issued.
// Named because the log hints below quote them back; the single-use ones are
// spelled out at their one call site.
const (
	envClientConfig = "OID4VCI_CLIENT_CONFIG"
	envClientID     = "OID4VCI_CLIENT_ID"
	envDPoP         = "OID4VCI_DPOP"
)

var txCodeInDescriptionPattern = regexp.MustCompile(`<([^<>]+)>`)

// envFlag reports whether an environment variable asks for a feature to be on.
// An unset value is off, and an unparseable one is reported rather than
// silently ignored: a typo here changes which variant is exercised, and the
// resulting conformance failure looks like a wallet defect.
func envFlag(logger *slog.Logger, name string) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false
	}

	value, err := strconv.ParseBool(raw)
	if err != nil {
		logger.Warn("Ignoring unparseable boolean environment variable",
			"name", name, "value", raw, "expected", "1, 0, true or false")
		return false
	}
	return value
}

// buildWalletConfig assembles the wallet configuration from the environment, so
// that one binary covers every client_auth_type and sender_constrain
// combination the test plan offers.
func buildWalletConfig(logger *slog.Logger) (wallet.Config, error) {
	config := wallet.Config{}

	if path := strings.TrimSpace(os.Getenv(envClientConfig)); path != "" {
		opts := []clientconfig.Option{}
		if clientID := strings.TrimSpace(os.Getenv(envClientID)); clientID != "" {
			opts = append(opts, clientconfig.WithClientID(clientID))
		}
		if keyPath := strings.TrimSpace(os.Getenv("OID4VCI_CLIENT_PRIVATE_JWK")); keyPath != "" {
			opts = append(opts, clientconfig.WithPrivateJWKFile(keyPath))
		}
		// A client_assertion_audience in the file wins over the authorization
		// server metadata issuer, which is right for a fixed deployment and
		// wrong for the conformance suite: every test instance gets its own
		// issuer URL. Setting this variable to the empty string clears the
		// override and restores the issuer-derived default.
		if audience, isSet := os.LookupEnv("OID4VCI_CLIENT_ASSERTION_AUDIENCE"); isSet {
			opts = append(opts, clientconfig.WithAssertionAudience(strings.TrimSpace(audience)))
		}
		if envFlag(logger, "OID4VCI_ALLOW_INSECURE_KEY_PERMS") {
			opts = append(opts, clientconfig.AllowInsecureFilePermissions())
		}

		clientAuth, err := clientconfig.Load(path, opts...)
		if err != nil {
			return wallet.Config{}, fmt.Errorf("failed to load client configuration %q: %w", path, err)
		}

		config.ClientAuth = clientAuth
		logger.Info("Client authentication configured",
			"method", clientAuth.Method,
			"client_id", clientAuth.ClientID,
			"signing_alg", clientAuth.SigningAlg,
		)
	} else if clientID := strings.TrimSpace(os.Getenv(envClientID)); clientID != "" {
		// Accepting none is not accepting an unnamed request; only
		// pre-authorized_grant_anonymous_access_supported permits that (12.3).
		config.ClientAuth = wallet.ClientAuthConfig{
			Method:   receiverTypes.None,
			ClientID: clientID,
		}
		logger.Info("Client authentication configured",
			"method", receiverTypes.None,
			"client_id", clientID,
			"hint", "the token request will carry client_id without a client_assertion")
	} else {
		logger.Info("No client authentication configured",
			"hint", envClientConfig+" selects a client registration for client_auth_type=private_key_jwt, "+
				"which every conformance test plan for this module requires; "+
				envClientID+" alone names the wallet against an authorization server that "+
				"advertises none in token_endpoint_auth_methods_supported")
	}

	if envFlag(logger, envDPoP) {
		// Key is left unset so that NewWalletWithConfig generates one. The same
		// key is then reused for every request, which is what binds the access
		// token to the wallet through its jkt thumbprint.
		config.DPoP = wallet.DPoPConfig{Enabled: true}
		logger.Info("DPoP enabled for sender_constrain=dpop")
	} else {
		logger.Info("DPoP disabled; running the sender_constrain=none variant",
			"hint", envDPoP+"=1 enables it")
	}

	return config, nil
}

func validatePreAuthorizedFlow(offer *wallet.CredentialOffer) error {
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

	// wallet.NewWalletWithConfig fills every nil field with its default
	// implementation. The credential acceptance policy is required: the
	// conformance suite signs its SD-JWT VC with x5c, so its certificate
	// authority is passed in VCKNOTS_ISSUER_CA_PATH.
	issuerAcceptance, err := common.SampleIssuerAcceptance(os.Getenv("VCKNOTS_ISSUER_CA_PATH"), false)
	if err != nil {
		logger.Error("Failed to load the issuer trust", "error", err)
		os.Exit(1)
	}
	walletConfig, err := buildWalletConfig(logger)
	if err != nil {
		logger.Error("Failed to configure wallet", "error", err)
		os.Exit(1)
	}
	walletConfig.CredentialAcceptance = issuerAcceptance
	w, err := wallet.NewWalletWithConfig(walletConfig)
	if err != nil {
		logger.Error("Failed to initialize wallet", "error", err)
		os.Exit(1)
	}

	logger.Info("Wallet initialized")

	ctx := context.Background()
	holderKey := common.NewMockKeyEntry()
	// ResolveCredentialOffer takes the by_value (credential_offer) and the
	// by_reference (credential_offer_uri) forms of OpenID4VCI 1.0 Section 4.1.
	offer, err := w.ResolveCredentialOffer(ctx, os.Args[1])
	if err != nil {
		logger.Error("Failed to resolve credential offer", "error", err)
		os.Exit(1)
	}
	logger.Info("Parsed credential offer",
		"issuer", offer.CredentialIssuer.String(),
		"configuration_ids", offer.CredentialConfigurationIDs,
	)
	if err := validatePreAuthorizedFlow(offer); err != nil {
		logger.Error("Invalid test plan / offer for this sample", "error", err)
		logger.Error("Set Authorization Code Flow Variant to issuer_initiated and disable client_attestation-based client authentication")
		os.Exit(1)
	}
	txCode, err := resolveTxCode(offer, explicitTxCode, logger)
	if err != nil {
		logger.Error("Missing tx_code", "error", err)
		os.Exit(1)
	}

	// OpenID4VCI 1.0 Pre-Authorized Code Flow: the Token Request (Section
	// 6), then the Credential Request (Section 8) with a key proof for the
	// holder key.
	grant, err := w.AuthorizePreAuthorizedIssuance(ctx, wallet.PreAuthorizedIssuanceRequest{
		CredentialOffer: offer,
		TxCode:          txCode,
	})
	if err != nil {
		logger.Error("Failed to obtain an access token", "error", err)
		os.Exit(1)
	}
	result, err := w.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{holderKey},
	})
	if err != nil {
		logger.Error("Failed to receive credential", "error", err)
		os.Exit(1)
	}
	if result.Deferred != nil || len(result.Credentials) == 0 {
		logger.Error("The issuer deferred the credential; this sample does not poll")
		os.Exit(1)
	}
	savedCredential := result.Credentials[0]

	logger.Info("=== Credential Received ===")
	logger.Info("Entry ID", "id", savedCredential.Entry.Id)
	logger.Info("MimeType", "mime_type", savedCredential.Entry.MimeType)
	logger.Info("Received At", "received_at", savedCredential.Entry.ReceivedAt)
	logger.Info("Credential payload stored")
}
