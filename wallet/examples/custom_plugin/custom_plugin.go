package main

// Custom Plugin Example
//
// This example demonstrates how external packages can implement custom
// serialization plugins by implementing the Serializer interface and
// registering them with the SerializationDispatcher.
//
// Usage:
//   cd examples/custom_plugin && go run custom_plugin.go

import (
	"fmt"
	"log"

	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

// CustomSerializer implements a custom credential serialization format.
type CustomSerializer struct{}

func (s *CustomSerializer) SerializeCredential(
	flavor credential.SupportedSerializationFlavor,
	cred *credential.Credential,
) ([]byte, error) {
	return []byte(fmt.Sprintf("CUSTOM:%s:%s", cred.ID, cred.Issuer)), nil
}

func (s *CustomSerializer) DeserializeCredential(
	flavor credential.SupportedSerializationFlavor,
	data []byte,
) (*credential.Credential, error) {
	return &credential.Credential{
		ID:     "custom-deserialized",
		Types:  []string{"VerifiableCredential"},
		Issuer: "custom-issuer",
	}, nil
}

func (s *CustomSerializer) SerializePresentation(
	flavor credential.SupportedSerializationFlavor,
	presentation *credential.CredentialPresentation,
	key keystore.KeyEntry,
	options types.SerializePresentationOptions,
) ([]byte, *credential.CredentialPresentation, error) {
	return []byte("custom-presentation"), presentation, nil
}

func (s *CustomSerializer) DeserializePresentation(
	flavor credential.SupportedSerializationFlavor,
	data []byte,
) (*credential.CredentialPresentation, error) {
	return &credential.CredentialPresentation{}, nil
}

func main() {
	fmt.Println("=== Custom Serializer Plugin Example ===")

	// Create custom plugin instance
	customPlugin := &CustomSerializer{}

	// Register custom plugin with the dispatcher
	dispatcher, err := serializer.NewSerializationDispatcher(
		serializer.WithDefaultConfig(),
		serializer.WithPlugin(credential.MockFormat, customPlugin),
	)
	if err != nil {
		log.Fatalf("Failed to create dispatcher: %v", err)
	}

	// Use the custom plugin to serialize a credential
	testCred := &credential.Credential{
		ID:     "test-credential-123",
		Types:  []string{"VerifiableCredential"},
		Issuer: "did:example:issuer",
	}

	serialized, err := dispatcher.SerializeCredential(credential.MockFormat, testCred)
	if err != nil {
		log.Fatalf("Failed to serialize: %v", err)
	}

	fmt.Printf("Serialized credential: %s\n", string(serialized))

	// Deserialize the credential
	deserialized, err := dispatcher.DeserializeCredential(credential.MockFormat, serialized)
	if err != nil {
		log.Fatalf("Failed to deserialize: %v", err)
	}

	fmt.Printf("Deserialized credential ID: %s\n", deserialized.ID)
	fmt.Println()
	fmt.Println("✓ Custom plugin successfully registered and used!")
}
