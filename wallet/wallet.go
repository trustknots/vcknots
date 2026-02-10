// Package wallet provides a verifiable credential wallet implementation.
//
// This package implements the OpenID for Verifiable Credentials specifications,
// enabling applications to receive credentials from issuers (OID4VCI) and present
// them to verifiers (OID4VP). It supports multiple credential formats including
// JWT-VC and SD-JWT-VC.
//
// Basic usage:
//
//	// Create a wallet with default configuration
//	w, err := wallet.NewWallet()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Receive a credential from an issuer
//	credential, err := w.ReceiveCredential(wallet.ReceiveCredentialRequest{
//		CredentialOffer: offer,
//		Type:            receiverTypes.Oid4vci,
//		Key:             keyEntry,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Present credentials to a verifier
//	err = w.PresentCredential(authorizationRequestURI, keyEntry, options)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// For advanced use cases such as custom protocol plugins or storage backends,
// use NewWalletWithConfig to provide custom dispatcher implementations.
package wallet

import (
	"github.com/trustknots/vcknots/wallet/controller"
)

// Controller provides the main wallet operations.
type Controller = controller.Controller

// Config holds dispatcher dependencies for Controller.
type Config = controller.Config

// ReceiveCredentialRequest contains parameters for receiving a credential.
type ReceiveCredentialRequest = controller.ReceiveCredentialRequest

// CredentialOffer represents an OID4VCI credential offer.
type CredentialOffer = controller.CredentialOffer

// CredentialOfferGrant contains grant information in a credential offer.
type CredentialOfferGrant = controller.CredentialOfferGrant

// GetCredentialEntriesRequest contains query parameters for stored credentials.
type GetCredentialEntriesRequest = controller.GetCredentialEntriesRequest

// SavedCredential represents a stored credential with its metadata.
type SavedCredential = controller.SavedCredential

// DIDCreateOptions contains options for DID generation.
type DIDCreateOptions = controller.DIDCreateOptions

// IKeyEntry represents a key entry interface for cryptographic operations.
type IKeyEntry = controller.IKeyEntry

// NewWallet creates a wallet instance with default configuration.
//
// The returned Controller provides methods for credential operations:
//   - ReceiveCredential: obtain credentials from issuers using OID4VCI
//   - PresentCredential: present credentials to verifiers using OID4VP
//   - GetCredentialEntries: query stored credentials
//   - GenerateDID: create decentralized identifiers
//   - VerifyCredential: verify credential signatures
//
// All protocol implementations (OID4VCI, OID4VP) and serialization formats
// (JWT-VC, SD-JWT-VC) are enabled by default.
//
// Returns an error if initialization of any component fails.
func NewWallet() (*Controller, error) {
	return controller.NewControllerWithDefaults()
}

// NewWalletWithConfig creates a wallet with custom component configurations.
//
// This function enables advanced use cases such as:
//   - Registering custom protocol plugins (e.g., non-standard issuance flows)
//   - Using alternative storage backends (e.g., database instead of file system)
//   - Injecting mock components for testing
//
// Any configuration field left nil will be initialized with its default implementation.
//
// Example:
//
//	config := wallet.Config{
//		Receiver: customReceiverDispatcher,
//	}
//	w, err := wallet.NewWalletWithConfig(config)
//
// For typical usage, NewWallet is recommended instead.
func NewWalletWithConfig(config controller.Config) (*Controller, error) {
	return controller.NewController(config)
}
