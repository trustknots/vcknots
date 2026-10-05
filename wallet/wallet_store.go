package wallet

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore/types"
)

// GetCredentialEntriesRequest holds parameters for querying credential entries.
type GetCredentialEntriesRequest struct {
	Offset int
	Limit  *int
	Filter func(*SavedCredential) bool
}

// SavedCredential represents a credential with its storage entry.
type SavedCredential struct {
	Credential *credential.Credential
	Entry      *types.CredentialEntry
	// Verification records what the wallet authenticated before storing this
	// credential. It is nil for credentials loaded from storage.
	Verification *acceptance.Verification
}

// convertEntryToSavedCredential converts a CredentialEntry to SavedCredential.
// Returns error if conversion fails (invalid flavor or deserialization error).
func (w *Wallet) convertEntryToSavedCredential(entry types.CredentialEntry) (*SavedCredential, error) {
	f, err := entry.SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("invalid serialization flavor: %w", err)
	}

	cred, err := w.serializer.DeserializeCredential(f, entry.Raw)
	if err != nil {
		return nil, fmt.Errorf("deserialization failed: %w", err)
	}

	return &SavedCredential{
		Credential: cred,
		Entry:      &entry,
	}, nil
}

// ErrNoCredentialStore reports an operation that needs the wallet's credential
// store on a wallet built with Config.Storeless. Such a wallet presents the
// credentials the caller names by value and persists nothing.
var ErrNoCredentialStore = common.NewCodedError("no_credential_store", "this wallet holds no credential store")

// GetCredentialEntries retrieves credential entries with optional filtering.
func (w *Wallet) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error) {
	entries, total, err := w.getCredentialEntries(req)
	return entries, total, classify(err)
}

func (w *Wallet) getCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error) {
	if w.credStore == nil {
		return nil, 0, ErrNoCredentialStore
	}
	if req.Filter != nil {
		result, err := w.credStore.GetCredentialEntries(0, nil, types.SupportedCredStoreTypes(0))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get credential entries: %w", err)
		}

		var filteredCredentials []*SavedCredential
		if result.Entries != nil {
			for _, entry := range *result.Entries {
				savedCred, err := w.convertEntryToSavedCredential(entry)
				if err != nil {
					continue // Skip invalid entries
				}

				if req.Filter(savedCred) {
					filteredCredentials = append(filteredCredentials, savedCred)
				}
			}
		}

		start := req.Offset
		if start > len(filteredCredentials) {
			start = len(filteredCredentials)
		}

		end := len(filteredCredentials)
		if req.Limit != nil && start+*req.Limit < end {
			end = start + *req.Limit
		}

		return filteredCredentials[start:end], len(filteredCredentials), nil
	}

	result, err := w.credStore.GetCredentialEntries(req.Offset, req.Limit, types.SupportedCredStoreTypes(0))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get credential entries: %w", err)
	}

	var savedCredentials []*SavedCredential
	if result.Entries != nil {
		for _, entry := range *result.Entries {
			savedCred, err := w.convertEntryToSavedCredential(entry)
			if err != nil {
				continue // Skip invalid entries
			}
			savedCredentials = append(savedCredentials, savedCred)
		}
	}

	totalCount := 0
	if result.TotalCount != nil {
		totalCount = *result.TotalCount
	}

	return savedCredentials, totalCount, nil
}

// GetCredentialEntry retrieves a single credential entry by ID. It returns
// nil and no error when no entry has that ID.
func (w *Wallet) GetCredentialEntry(id string) (*SavedCredential, error) {
	entry, err := w.getCredentialEntry(id)
	return entry, classify(err)
}

func (w *Wallet) getCredentialEntry(id string) (*SavedCredential, error) {
	if w.credStore == nil {
		return nil, ErrNoCredentialStore
	}
	entry, err := w.credStore.GetCredentialEntry(id, types.SupportedCredStoreTypes(0))
	if err != nil {
		return nil, fmt.Errorf("failed to get credential entry: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	savedCred, err := w.convertEntryToSavedCredential(*entry)
	if err != nil {
		return nil, fmt.Errorf("failed to convert credential: %w", err)
	}

	return savedCred, nil
}
