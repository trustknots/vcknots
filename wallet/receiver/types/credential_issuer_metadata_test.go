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

// The non-normative credential issuer metadata example of OpenID4VCI 1.0
// (examples/credential_issuer_metadata_sd_jwt_long.json) publishes
// credential_request_encryption.jwks as a bare array of JWKs, and an mso_mdoc
// configuration lists COSE algorithm identifiers. Neither makes the document
// unreadable.
func TestCredentialIssuerMetadataReadsTheSpecificationExampleShapes(t *testing.T) {
	document := `{
	  "credential_issuer": "https://credential-issuer.example.com",
	  "credential_endpoint": "https://credential-issuer.example.com/credential",
	  "credential_request_encryption": {
	    "jwks": [{"kty":"EC","kid":"ac","use":"enc","crv":"P-256","alg":"ECDH-ES",
	      "x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk","y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"}],
	    "enc_values_supported": ["A128GCM"],
	    "encryption_required": true
	  },
	  "credential_configurations_supported": {
	    "org.iso.18013.5.1.mDL": {"format": "mso_mdoc", "credential_signing_alg_values_supported": [-7, -9, -65535]}
	  }
	}`
	var metadata CredentialIssuerMetadata
	if err := json.Unmarshal([]byte(document), &metadata); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if metadata.CredentialRequestEncryption == nil || len(metadata.CredentialRequestEncryption.Jwks.Keys) != 1 || metadata.CredentialRequestEncryption.Jwks.Keys[0].KeyID != "ac" {
		t.Fatalf("credential_request_encryption = %#v", metadata.CredentialRequestEncryption)
	}
	algs := metadata.CredentialConfigurationSupported["org.iso.18013.5.1.mDL"].CredentialSigningAlgValuesSupported
	if len(algs) != 3 || algs[2] != "-65535" {
		t.Fatalf("credential_signing_alg_values_supported = %v", algs)
	}

	var set CredentialIssuerMetadata
	if err := json.Unmarshal([]byte(`{"credential_request_encryption":{"jwks":{"keys":[{"kty":"EC","kid":"ac","crv":"P-256","alg":"ECDH-ES","x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk","y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"}]},"enc_values_supported":["A128GCM"],"encryption_required":false}}`), &set); err != nil {
		t.Fatalf("a JWK Set: %v", err)
	}
	if len(set.CredentialRequestEncryption.Jwks.Keys) != 1 {
		t.Fatalf("a JWK Set: %#v", set.CredentialRequestEncryption)
	}
}
