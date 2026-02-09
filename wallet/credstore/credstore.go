// Package credstore defines the interface for credential storage operations.
// It provides methods to save, retrieve, and manage credential entries.
package credstore

import (
	"github.com/trustknots/vcknots/wallet/credstore/types"
)

// Re-export some types related to credstore
type CredentialEntry = types.CredentialEntry
type CredStore = types.CredStore
type SupportedCredStoreTypes = types.SupportedCredStoreTypes
