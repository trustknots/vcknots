package main

// Custom Dispatcher Configuration Example
//
// This example demonstrates how external packages can configure each
// dispatcher independently and compose them into a custom wallet
// configuration.
//
// Usage:
//   cd examples/custom_dispatcher && go run custom_dispatcher.go

import (
	"fmt"
	"log"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/idprof"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

func main() {
	fmt.Println("=== Custom Dispatcher Configuration Example ===\n")

	// Configure each dispatcher independently
	serializerDisp, err := serializer.NewSerializationDispatcher(
		serializer.WithDefaultConfig(),
	)
	if err != nil {
		log.Fatalf("Failed to create serializer: %v", err)
	}

	idProfDisp, err := idprof.NewIdentityProfileDispatcher(
		idprof.WithDefaultConfig(),
	)
	if err != nil {
		log.Fatalf("Failed to create idprof: %v", err)
	}

	verifierDisp, err := verifier.NewVerificationDispatcher(
		verifier.WithDefaultConfig(),
	)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	receiverDisp, err := receiver.NewReceivingDispatcher(
		receiver.WithDefaultConfig(),
	)
	if err != nil {
		log.Fatalf("Failed to create receiver: %v", err)
	}

	presenterDisp, err := presenter.NewPresentationDispatcher(
		presenter.WithDefaultConfig(),
	)
	if err != nil {
		log.Fatalf("Failed to create presenter: %v", err)
	}

	credStoreDisp, err := credstore.NewCredStoreDispatcher(
		credstore.WithDefaultConfig(),
	)
	if err != nil {
		log.Fatalf("Failed to create credstore: %v", err)
	}

	// Create wallet with custom dispatcher configuration
	w, err := wallet.NewWalletWithConfig(wallet.Config{
		Serializer: serializerDisp,
		IDProfiler: idProfDisp,
		Verifier:   verifierDisp,
		Receiver:   receiverDisp,
		Presenter:  presenterDisp,
		CredStore:  credStoreDisp,
	})

	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
	}

	fmt.Println("✓ Wallet successfully created with custom dispatcher configuration!")
	fmt.Printf("  - Wallet: %p\n", w)
	fmt.Println("\nThis demonstrates that external packages can:")
	fmt.Println("  1. Access all dispatcher constructors")
	fmt.Println("  2. Configure each dispatcher independently")
	fmt.Println("  3. Compose custom wallet configurations")
}
