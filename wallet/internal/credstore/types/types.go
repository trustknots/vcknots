package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/trustknots/vcknots/wallet/internal/credential"
)

// Sentinel errors for credential store operations
var (
	ErrCredentialNotFound     = errors.New("credential not found")
	ErrInvalidCredentialID    = errors.New("invalid credential ID")
	ErrCredentialExists       = errors.New("credential already exists")
	ErrInvalidCredentialEntry = errors.New("invalid credential entry")
	ErrStorageFailed          = errors.New("storage operation failed")
	ErrRetrievalFailed        = errors.New("credential retrieval failed")
	ErrSerializationFailed    = errors.New("credential serialization failed")
	ErrDeserializationFailed  = errors.New("credential deserialization failed")
	ErrInvalidLocation        = errors.New("invalid storage location")
	ErrInvalidMimeType        = errors.New("invalid or unsupported MIME type")
	ErrStorageCorrupted       = errors.New("storage data corrupted")
	ErrPluginNotFound         = errors.New("credential store plugin not found")
	ErrNilPlugin              = errors.New("credential store plugin cannot be nil")
)

// CredStoreError represents an error during credential store operations
type CredStoreError struct {
	Location SupportedCredStoreTypes `json:"location"`
	ID       string                  `json:"id,omitempty"`
	Op       string                  `json:"operation"`
	Err      error                   `json:"error"`
}

func (e *CredStoreError) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("credential store %v operation %s for ID %s: %v", e.Location, e.Op, e.ID, e.Err)
	}
	return fmt.Sprintf("credential store %v operation %s: %v", e.Location, e.Op, e.Err)
}

func (e *CredStoreError) Unwrap() error {
	return e.Err
}

// NewCredStoreError creates a new CredStoreError
func NewCredStoreError(location SupportedCredStoreTypes, id, op string, err error) *CredStoreError {
	return &CredStoreError{
		Location: location,
		ID:       id,
		Op:       op,
		Err:      err,
	}
}

type CredentialEntry struct {
	// TODO: Define the actual fields for credential entry
	Id         string
	ReceivedAt time.Time
	Raw        []byte
	MimeType   string
}

func (ce *CredentialEntry) Serialize() ([]byte, error) {
	return json.Marshal(ce)
}

func (ce *CredentialEntry) SerializationFlavor() (credential.SupportedSerializationFlavor, error) {
	switch ce.MimeType {
	case string(credential.JwtVc):
		return credential.JwtVc, nil
	case string(credential.SDJwtVC):
		return credential.SDJwtVC, nil
	case string(credential.MockFormat):
		return credential.MockFormat, nil
	default:
		return "", fmt.Errorf("unknown serialization flavor")
	}
}

type SupportedCredStoreTypes int

type CredStore interface {
	SaveCredentialEntry(credentialEntry CredentialEntry, location SupportedCredStoreTypes) error

	GetCredentialEntries(offset int, limit *int, location SupportedCredStoreTypes) (*GetCredentialEntriesResult, error)

	GetCredentialEntry(id string, location SupportedCredStoreTypes) (*CredentialEntry, error)
}

type GetCredentialEntriesResult struct {
	Entries    *[]CredentialEntry
	TotalCount *int
}

func ParseCredentialEntry(data []byte) (CredentialEntry, error) {
	var entry CredentialEntry
	err := json.Unmarshal(data, &entry)
	return entry, err
}
