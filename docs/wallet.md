---
sidebar_position: 4
---

# How to Set Up and Use the Wallet Feature

This tutorial explains how to set up the VCKnots wallet library, provides sample implementations of its main features, and describes important considerations for using it in production environments.

## 1. Prerequisites

This section outlines all the technical requirements needed to build the `vcknots/wallet` library and run the tutorial samples.

### 1-1. Go Environment Requirements

* **Go version:** The `vcknots/wallet` library requires Go 1.24.5.
* **Development environment management (mise):**
    - For this project, we strongly recommend using mise ([https://mise.jdx.dev/](https://mise.jdx.dev/)) to manage the development environment.
    - For example, by running `mise install` as shown below, the required Go version will be installed automatically and environment variables will be configured.

```bash
# macOS
brew install mise

# Install via curl
curl https://mise.jdx.dev/install.sh | sh

# (From the root of the vcknots repository)
cd wallet
mise install
```

* **GOPRIVATE 環境変数:** 
    - もしmise を使用しない場合、`go mod download` が失敗します。
    - これを回避するため、以下の環境変数を手動で設定する必要があります。

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 1-2. Requirements for the Sample Execution Environment (Verifier/Issuer Server)

The sample code in this tutorial for the Wallet library (especially for receiving and presenting Credentials) assumes that counterpart services (an Issuer and a Verifier) are available.

* **Node.js server:** The sample code in this tutorial requires that the Node.js-based sample server (`vcknots/server`), referenced in `README.md` and `package.json`, is running at http://localhost:8080.  

* **Server setup:** This server uses the Hono framework and `@trustknots/vcknots`, and provides Issuer and Verifier endpoints defined in `example.ts` (for example: `/issue/credentials`, `/verifiers/:verifier/callback`).  

* **Server startup steps:**
    - Setting up this Node.js server is not optional; it is **required**.
    - The `receiveMockCredential` and `presentation` functions in `server_integration.go` implicitly trigger HTTP requests to localhost:8080. If this server is not running, the code in “3. Sample Implementation” will fail with a `connection refused` error.

Before running the Wallet Go code, **be sure** to start the server by executing the commands below.



```bash
# From the wallet directory, move to the server directory
cd ../server
pnpm install
pnpm -F server start
```

## 2. Initial Setup

This section explains how to install the library dependencies and initialize the Controller instance, which aggregates the core Wallet features.

### 2-1. Installing Dependencies

After setting `GOPRIVATE` as a prerequisite, run the following command at the project root (the `wallet` directory) to download the dependencies listed in `go.mod` (such as `github.com/go-jose/go-jose/v4`, `go.etcd.io/bbolt`, `golang.org/x/crypto`, etc.).


```bash
go mod download
```

### 2-2. Initializing the Wallet Controller

- The `vcknots/wallet` library uses a highly modular, dispatcher-based architecture.
- The core logic (`controller.go`) depends on interfaces that handle specific tasks such as credstore (persistence), receiver (receiving), presenter (presentation), and verifier (verification).

- The `main` function in `server_integration.go` provides a standard recipe for instantiating the Controller.
- This shows that the library heavily relies on a dependency injection (DI) pattern using a combination of default settings (`WithDefaultConfig()`) and plugins (`WithPlugin(presenter.Oid4vp, ...)`).

The following code represents the standard Controller initialization process based on `server_integration.go`.
This controller instance is required to run the tutorial sample code.

```go
package main

import (
	"log"
	"net/url"
	
	// Dispatcher packages inside vcknots/wallet
	vcknots_wallet "github.com/trustknots/vcknots/wallet/pkg/controller"
	"github.com/trustknots/vcknots/wallet/pkg/credstore"
	"github.com/trustknots/vcknots/wallet/pkg/dispatcher/idprof"
	receiverTypes "github.com/trustknots/vcknots/wallet/pkg/dispatcher/receiver"
	"github.com/trustknots/vcknots/wallet/pkg/dispatcher/serializer"
	"github.com/trustknots/vcknots/wallet/pkg/dispatcher/verifier"
	"github.com/trustknots/vcknots/wallet/pkg/presenter"
	oid4vp "github.com/trustknots/vcknots/wallet/pkg/presenter/oid4vp" // OID4VP plugin
	"github.com/trustknots/vcknots/wallet/pkg/util"
	
	// Standard library for key generation and signing
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	// Libraries used in the sample implementation
	"io"
	"net/http"
	"github.com/trustknots/vcknots/wallet/pkg/types"
)

// NewController initializes all dispatchers
// and returns the integrated Wallet controller.
func NewController() *vcknots_wallet.Controller {
    logger := util.NewLogger()

    // 1. Initialize each dispatcher with default settings
    credStoreDispatcher := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
    receiverDispatcher := receiverTypes.NewReceivingDispatcher(receiverTypes.WithDefaultConfig())
    serializationDispatcher := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
    verificationDispatcher := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
    idProfileDispatcher := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())

    // 2. Initialize the OID4VP plugin
    // (the presentation logic is implemented as a plugin)
    oid4vpPlugin, err := oid4vp.New(
        oid4vp.WithLogger(logger),
        oid4vp.WithVerificationDispatcher(verificationDispatcher),
    )
    if err!= nil {
        panic(err)
    }

    // 3. Register the OID4VP plugin with the presentation dispatcher
    presentationDispatcher := presenter.NewPresentationDispatcher(
        presenter.WithPlugin(presenter.Oid4vp, oid4vpPlugin),
    )

    // 4. Aggregate all dispatchers into the controller configuration
    config := vcknots_wallet.ControllerConfig{
        CredStore:  credStoreDispatcher,
        IdProf:     idProfileDispatcher,
        Receiver:   receiverDispatcher,
        Serializer: serializationDispatcher,
        Verifier:   verificationDispatcher,
        Presenter:  presentationDispatcher,
        Logger:     logger,
    }

    // 5. Instantiate the controller
    return vcknots_wallet.NewController(config)
}

var (
    // This controller will be used later in the tutorial
    controller = NewController()
)
```

## 3. Sample Implementation of Wallet Features

Using the Controller instance, this section provides concrete Go code samples that perform the main Wallet functions (key preparation, receiving Credentials, and presenting Credentials).
These samples are based on the logic in `server_integration.go`.

### 3-1. Preparing Test Keys (IKeyEntry Interface)

The main methods in `controller.go` (`ReceiveCredential`, `PresentCredential`) require the `IKeyEntry` interface for signing operations.
This allows library users to freely swap out key management implementations (for example: in-memory, HSM, secure enclave).

The `IKeyEntry` interface is defined as follows:

```go
// IKeyEntry is an interface that encapsulates a key and its operations.
type IKeyEntry interface {
    ID() string
    PublicKey() jose.JSONWebKey
    Sign(databyte) (byte, error)
}
```

For this tutorial, we use the in-memory mock implementation (`MockKeyEntry`) provided in `server_integration.go`.

The `Sign` method of this `MockKeyEntry` is not just a simple wrapper around `ecdsa.Sign`.
It includes the logic to generate ES256 signatures (SHA-256 hash) commonly required in OID4VP, and to serialize the result into IEEE P1363 format (a 64-byte byte string consisting of the concatenation of r and s).


```go
// MockKeyEntry is a test implementation of IKeyEntry
type MockKeyEntry struct {
    id         string
    privateKey *ecdsa.PrivateKey
}

func (m *MockKeyEntry) ID() string { return m.id }

func (m *MockKeyEntry) PublicKey() jose.JSONWebKey {
    return jose.JSONWebKey{
        Key:       m.privateKey.PublicKey,
        Algorithm: "ES256", // P-256 curve
        Use:       "sig",
    }
}

// Sign performs SHA-256 hashing -> ECDSA signing -> conversion to IEEE P1363 format
func (m *MockKeyEntry) Sign(payloadbyte) (byte, error) {
    hash := sha256.Sum256(payload)
    r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
    if err!= nil {
        return nil, err
    }

    // P-256 (256 bits / 8 = 32 bytes)
    const keySize = 32
    // Serialize r and s into 64-byte (IEEE P1363) format
    signature := make(byte, 2*keySize)
    r.FillBytes(signature)
    s.FillBytes(signature)
    return signature, nil
}

// NewMockKeyEntry generates a new test key
func NewMockKeyEntry() (*MockKeyEntry, error) {
    // Generate a new key on the P-256 curve
    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err!= nil {
        return nil, err
    }
    
    return &MockKeyEntry{
        id:         "test-key-id-" + uuid.NewString(), // A unique ID for each execution
        privateKey: privKey,
    }, nil
}

// Prepare the key that will be used later in the tutorial
var testKey, _ = NewMockKeyEntry()
```

### 3-2. Receiving a Credential

- This feature calls the Controller’s `ReceiveCredential` method based on a `CredentialOffer` from the Issuer (Node.js server).
- The `ReceiveCredential` method takes a `ReceiveCredentialRequest` struct as its argument.
- Referring to the `receiveMockCredential` function in `server_integration.go`, the following shows the process for receiving a mock Credential (issued by a test Issuer).

```go
func receiveTestCredential(key *MockKeyEntry) (*vcknots_wallet.SavedCredential, error) {
    // 1. Simulate a Credential Offer (Mock)
    // In a real scenario, the offer URL would be obtained from a QR code or deep link
    issuerURL, _ := url.Parse("http://localhost:8080/issuers/test_issuer/configurations/test_config")

    offer := &vcknots_wallet.CredentialOffer{
        CredentialIssuer:         issuerURL,
        CredentialConfigurationIDs:string{"UniversityDegree_jwt_vc_json-ld"}, // Match with the server side
        Grants: map[string]*vcknots_wallet.CredentialOfferGrant{
            "pre-authorized_code": {
                PreAuthorizedCode: "test_code", // Fixed code for mock use
            },
        },
    }

    // 2. Create the receive request
    receiveReq := vcknots_wallet.ReceiveCredentialRequest{
        CredentialOffer:      offer,
        Type:                 receiverTypes.Mock, // Mock type that does not communicate with the server side
        Key:                  key,                // Key used for signing (e.g. PoP)
        CachedIssuerMetadata: nil,                // Specify nil when there is no metadata
    }

    // 3. Call the Controller's ReceiveCredential
    log.Println("Attempting to receive credential...")
    savedCred, err := controller.ReceiveCredential(receiveReq)
    if err!= nil {
        log.Printf("Error receiving credential: %v\n", err)
        return nil, err
    }

    log.Printf("Successfully received and saved credential. ID: %s\n", savedCred.Entry.ID)
    return savedCred, nil
}
```

### 3-3. Presenting a Credential (OID4VP)

- After receiving a request URI in the form `openid4vp://authorize?...` from the Verifier (Node.js server), the Controller’s `PresentCredential` method is called.
- This method parses the `uriString` (OID4VP request), analyzes the request content (`presentation_definition`), searches the `credstore` for matching Credentials, uses `IKeyEntry` to sign a Verifiable Presentation (VP), and sends it to the Verifier’s `callback` endpoint via `HTTP POST`.
- Based on the `presentation` function in `server_integration.go`, it processes the request URI obtained from the Node.js server (`/verifiers/test_verifier/request` endpoint).


```go
func presentTestCredential(key *MockKeyEntry) error {
    // 1. Obtain the OID4VP request URI from the Verifier (Node.js server)
    // This URI is usually obtained by scanning a QR code
    // Here, we directly call /verifiers/test_verifier/request
    resp, err := http.Get("http://localhost:8080/verifiers/test_verifier/request")
    if err!= nil {
        log.Printf("Failed to get OID4VP request URI from server: %v\n", err)
        return err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err!= nil {
        return err
    }

    oid4vpRequestURI := string(body)
    log.Printf("Received OID4VP Request URI: %s\n", oid4vpRequestURI)

    // 2. Call the Controller's PresentCredential
    // Parsing, searching, signing, and HTTP POST are all performed internally
    log.Println("Attempting to present credential...")
    err = controller.PresentCredential(oid4vpRequestURI, key)
    if err!= nil {
        log.Printf("Error presenting credential: %v\n", err)
        return err
    }

    log.Println("Successfully presented credential to the verifier.")
    return nil
}
```

### 3-4. Referencing Saved Credentials

- Credentials saved via `ReceiveCredential` can be searched and listed using the Controller’s `GetCredentialEntries` method.
- This request allows pagination (`Offset`, `Limit`) and advanced filtering using a `Filter` function.


```go
func listSavedCredentials() (*vcknots_wallet.SavedCredential, error) {
    limit := 10
    getEntriesReq := vcknots_wallet.GetCredentialEntriesRequest{
        Offset: 0,
        Limit:  &limit,
        Filter: func(sc *vcknots_wallet.SavedCredential) bool {
            // Example: filter only 'UniversityDegree'
            // return sc.Credential.HasType("UniversityDegree")
            return true // In this example, retrieve all
        },
    }

    log.Println("Fetching saved credential entries...")
    entries, total, err := controller.GetCredentialEntries(getEntriesReq)
    if err!= nil {
        log.Printf("Error getting credential entries: %v\n", err)
        return nil, err
    }

    log.Printf("Found %d matching entries (Total: %d)\n", len(entries), total)
    for _, entry := range entries {
        log.Printf(" - Entry ID: %s, Credential Type: %v\n", entry.Entry.ID, entry.Credential.Types)
    }
    return entries, nil
}
```

## 4. Registering Wallet Metadata

- This section does **not** describe a feature for the Wallet to register its **own** metadata, but rather explains the capability to **retrieve and process** the metadata of the **Issuer** with which the Wallet interacts.

- When receiving a Credential, the Wallet must first access the Issuer’s `.well-known/openid-credential-issuer` endpoint and obtain that Issuer’s configuration (such as public keys, supported Credential types, endpoints, etc.).

- The Controller provides the `FetchCredentialIssuerMetadata` method specifically for this task.
- This method is implicitly called within the internal flow of `ReceiveCredential`, or can be explicitly called beforehand to set the `CachedIssuerMetadata` field of `ReceiveCredentialRequest`.

- By providing `CachedIssuerMetadata` when calling `ReceiveCredential`, you can avoid the network overhead of re-fetching the metadata every time `ReceiveCredential` is executed.


```go
func fetchIssuerMetadata() (*receiverTypes.CredentialIssuerMetadata, error) {
    // Note: This URL is the Issuer's base URL and does not include the /.well-known/... path
    // FetchCredentialIssuerMetadata resolves the path internally
    issuerURL, _ := url.Parse("http://localhost:8080") // Issuer base URL

    log.Println("Fetching issuer metadata from:", issuerURL.String())
    
    // Call the method defined in the controller
    metadata, err := controller.FetchCredentialIssuerMetadata(
        issuerURL,
        receiverTypes.OpenID4VCI, // Specify the protocol type
    )

    if err!= nil {
        log.Printf("Failed to fetch issuer metadata: %v\n", err)
        return nil, err
    }

    log.Printf("Successfully fetched metadata for issuer: %s\n", metadata.CredentialIssuer)
    // metadata.CredentialEndpoint, metadata.JWKS...
    return metadata, nil
}
```

## 5. Explanation of Type Definitions

This section explains the main Go type definitions used when interacting with the Controller in the `vcknots/wallet` library.

| Type / Interface | Description |
| :---- | :---- |
| **IKeyEntry** | Core interface for key management. Defines three methods: `ID()`, `PublicKey()`, and `Sign()`. Library users must implement this to integrate with HSMs, secure enclaves, and similar systems. |
| **DIDCreateOptions** | Options passed to the `GenerateDID` method. Specifies the type of DID to generate (`TypeID`) and the associated public key (`PublicKey`). |
| **ReceiveCredentialRequest** | Main input for the `ReceiveCredential` method. Encapsulates the `CredentialOffer`, the key (`IKeyEntry`) used for signing, and the optional `CachedIssuerMetadata`. |
| **CredentialOffer** | Details of the offer received from the Issuer. Includes the Issuer URL (`CredentialIssuer`), the IDs of the requested Credentials (`CredentialConfigurationIDs`), and the authorization grants (`Grants`). |
| **SavedCredential** | The actual Credential stored in the `credstore`. Wraps `*credential.Credential` (VC raw data) and `*types.CredentialEntry` (metadata). Returned by `GetCredentialEntries`. |
| **GetCredentialEntriesRequest** | Search conditions for the `GetCredentialEntries` method. Supports pagination (`Offset`, `Limit`) and dynamic filtering via a Go function (`Filter`). |

## 6. Notes

1. **MockKeyEntry must not be used in production (CRITICAL):**  
    - `MockKeyEntry` provided in `server_integration.go` is intended only for testing and demonstration.
    - **Reason:** It keeps the private key (`*ecdsa.PrivateKey`) in plaintext on the Go heap memory.
    - **Production implementation:** In a production environment, you must implement the `IKeyEntry` interface yourself. This implementation should delegate the `Sign` operation to an OS keystore (`iOS Secure Enclave`, `Android Keystore`) or an HSM (`Hardware Security Module`), and be designed so that the private key itself is never loaded into the application’s memory space (i.e., it is *non-exportable*).  

2. **GOPRIVATE configuration:**  
    - If `go mod download` or `go build` fails, the most likely cause is a missing GOPRIVATE environment variable configuration. 

3. **Signature format compatibility:**  
    - When implementing your own `IKeyEntry`, pay close attention to the signature format produced by the `Sign` method.
    - `MockKeyEntry` serializes ES256 (SHA-256 with P-256) signatures in **IEEE P1363** format (fixed 64-byte length).
    - If the Verifier expects a different format (for example, ASN.1 DER), `PresentCredential` will fail with a signature verification error.  

4. **Persistent storage (bbolt):**  
    - `credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())` uses `go.etcd.io/bbolt` (an embedded KVS) by default and attempts to persist data to a local file such as `wallet.db`.
    - Make sure that you have write permissions for the execution directory.

## 7. Troubleshooting

* **Q: `go mod download` fails with `package... is private` or `404 Not Found`.**  
  * **A:** The GOPRIVATE environment variable is not configured correctly. Go back to “1. Prerequisites” and make sure `export GOPRIVATE="github.com/trustknots/vcknots/wallet"` has been executed.  

* **Q: `ReceiveCredential` or `PresentCredential` fails with `connection refused` or `timeout`.**  
  * **A:** The Issuer/Verifier server that the `vcknots/wallet` Go code is trying to communicate with is not running. Follow “1. Prerequisites”, run `pnpm start` in the `packages/server` directory, and confirm that http://localhost:8080 responds.  

* **Q: `PresentCredential` succeeds, but the Verifier (Node.js server logs) shows `Invalid signature` or `Presentation verification failed`.**  
  * **A:** This indicates a mismatch in the signature algorithm or format between the `IKeyEntry` used by the Wallet and the Verifier.  
    1. Check whether you are using `MockKeyEntry`.  
    2. If you are using a custom `IKeyEntry`, make sure the `Sign` method, like `MockKeyEntry`, uses a SHA-256 hash and IEEE P1363 serialization.  

* **Q: `controller.ReceiveCredential` fails with `issuer metadata not found`.**  
  * **A:** The Node.js server may be running, but the `/.well-known/openid-credential-issuer` endpoint might not be functioning correctly. Run `curl http://localhost:8080/.well-known/openid-credential-issuer` (or the Issuer base URL specified in “4. Registering Wallet Metadata”) and confirm that JSON metadata is returned.