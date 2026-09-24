package types

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// UnmarshalJSON preserves the difference between an absent optional object and
// an invalid explicit null. Decode atomically so an error cannot leave metadata
// from a partially decoded response in the destination.
func (m *CredentialIssuerMetadata) UnmarshalJSON(data []byte) error {
	type metadata CredentialIssuerMetadata
	var decoded metadata
	wire := struct {
		*metadata
		RequestEncryption json.RawMessage `json:"credential_request_encryption"`
	}{metadata: &decoded}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if len(wire.RequestEncryption) > 0 {
		if bytes.Equal(bytes.TrimSpace(wire.RequestEncryption), []byte("null")) {
			return fmt.Errorf("credential_request_encryption must be an object")
		}
		var encryption CredentialRequestEncryption
		if err := json.Unmarshal(wire.RequestEncryption, &encryption); err != nil {
			return fmt.Errorf("invalid credential_request_encryption: %w", err)
		}
		decoded.CredentialRequestEncryption = &encryption
	}
	*m = CredentialIssuerMetadata(decoded)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler. It refuses an encryption_required
// member that is not a JSON boolean, including null.
func (e *CredentialRequestEncryption) UnmarshalJSON(data []byte) error {
	type encryption CredentialRequestEncryption
	var decoded encryption
	wire := struct {
		*encryption
		Required json.RawMessage `json:"encryption_required"`
	}{encryption: &decoded}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	if len(wire.Required) > 0 {
		var required bool
		if bytes.Equal(bytes.TrimSpace(wire.Required), []byte("null")) {
			return fmt.Errorf("credential request encryption_required must be a boolean")
		}
		if err := json.Unmarshal(wire.Required, &required); err != nil {
			return fmt.Errorf("credential request encryption_required must be a boolean: %w", err)
		}
		decoded.EncryptionRequired = &required
	}
	*e = CredentialRequestEncryption(decoded)
	return nil
}
