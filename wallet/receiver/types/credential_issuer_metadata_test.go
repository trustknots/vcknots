package types

import (
	"encoding/json"
	"testing"
)

func TestCredentialIssuerMetadataPreservesRequestEncryptionRequirement(t *testing.T) {
	for _, value := range []string{"true", "false"} {
		t.Run(value, func(t *testing.T) {
			var metadata CredentialIssuerMetadata
			if err := json.Unmarshal([]byte(`{"credential_request_encryption":{"encryption_required":`+value+`}}`), &metadata); err != nil {
				t.Fatal(err)
			}
			required := metadata.CredentialRequestEncryption.EncryptionRequired
			if required == nil || *required != (value == "true") {
				t.Fatalf("encryption_required = %v, want %s", required, value)
			}
			encoded, err := json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			var restored CredentialIssuerMetadata
			if err := json.Unmarshal(encoded, &restored); err != nil {
				t.Fatal(err)
			}
			if restored.CredentialRequestEncryption.EncryptionRequired == nil || *restored.CredentialRequestEncryption.EncryptionRequired != *required {
				t.Fatalf("requirement lost in round trip: %s", encoded)
			}
		})
	}
	var absent CredentialIssuerMetadata
	if err := json.Unmarshal([]byte(`{"credential_request_encryption":{}}`), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.CredentialRequestEncryption.EncryptionRequired != nil {
		t.Fatal("omitted encryption_required was converted to false")
	}
}

func TestCredentialIssuerMetadataRejectsMalformedRequestEncryptionAtomically(t *testing.T) {
	for _, value := range []string{`null`, `[]`, `{"encryption_required":null}`, `{"encryption_required":"false"}`, `{"encryption_required":0}`} {
		t.Run(value, func(t *testing.T) {
			metadata := CredentialIssuerMetadata{CredentialIssuer: "https://original.example"}
			err := json.Unmarshal([]byte(`{"credential_issuer":"https://partial.example","credential_request_encryption":`+value+`}`), &metadata)
			if err == nil {
				t.Fatal("accepted malformed encryption metadata")
			}
			if metadata.CredentialIssuer != "https://original.example" {
				t.Fatal("failed decode modified destination")
			}
		})
	}
}
