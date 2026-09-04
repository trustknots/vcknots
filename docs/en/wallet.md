---
sidebar_position: 13
---

# How to Set Up and Use the Wallet Feature

This tutorial explains how to set up the VCKnots wallet library (a Go library), how to receive and present credentials with it, and what to consider before using it in production environments.

The wallet implements the OpenID for Verifiable Credentials specifications:

* **Receiving credentials (OID4VCI):** the wallet obtains a credential from an issuer using a credential offer and the pre-authorized code flow.
* **Presenting credentials (OID4VP):** the wallet responds to an `openid4vp://` authorization request and submits a Verifiable Presentation to a verifier.

Both **JWT-VC** (`application/vc+jwt`) and **SD-JWT VC** (`application/dc+sd-jwt`) are supported for receiving and presenting, including selective disclosure and Key Binding JWT for SD-JWT VC.

## 1. Prerequisites

* **Supported specifications:**
    - Receiving: [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) (Pre-Authorized Code Flow)
    - Presenting: [OpenID for Verifiable Presentations - draft 24](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html) (cross-device flow, `response_mode=direct_post`)
    - For the full implementation scope of each feature, see [VC Knots Coverage](./support-matrix.md).

### 1-1. Go Environment Requirements

* **Go version:** The vcknots/wallet library requires the Go version pinned in `wallet/mise.toml` (currently Go 1.26.5).
* **Development environment management (mise):**
    - We recommend using [mise](https://mise.jdx.dev/) to manage the development environment.
    - Running `mise install` in the `wallet` directory installs the required Go version and sets the necessary environment variables automatically.

```bash
# macOS
brew install mise

# Install via curl
curl https://mise.jdx.dev/install.sh | sh

# (From the root of the vcknots repository)
cd wallet
mise install
```

* **GOPRIVATE environment variable:**
    - If you are not using mise, set the following environment variable manually. Without it, `go mod download` fails.

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 1-2. Requirements for the Sample Execution Environment (Issuer/Verifier Server)

The sample code in this tutorial (receiving and presenting credentials) assumes that counterpart services (an Issuer and a Verifier) are available. The Node.js-based sample server (`server/`) in this repository provides both.

Start the server before running any wallet sample code:

```bash
# From the root of the vcknots repository
pnpm install

# Build the issuer+verifier module, the server-core module, and the server module
pnpm -F @trustknots/vcknots build
pnpm -F @trustknots/server-core build
pnpm -F @trustknots/server build

# Start the server (listens on http://localhost:8080)
pnpm -F @trustknots/server start
```

The server exposes the endpoints used in this tutorial:

* `POST /configurations/:configurationId/offer` — creates a credential offer
* `POST /token`, `POST /nonce`, `POST /credentials` — OID4VCI token, nonce, and credential endpoints
* `POST /request`, `POST /request-object` — creates an OID4VP authorization request
* `POST /callback` — the verifier's response endpoint
* `GET /.well-known/openid-credential-issuer`, `GET /.well-known/oauth-authorization-server` — metadata endpoints

* **Allowing HTTP for local testing:** The wallet rejects non-HTTPS issuer and verifier endpoints by default. Because the local sample server runs on plain HTTP, enable HTTP explicitly when testing locally:

```bash
export VCKNOTS_WALLET_HTTP_ALLOWED=true
```

Alternatively, call `env.SetHTTPAllowed(true)` (package `github.com/trustknots/vcknots/wallet/env`) from your test code.

> ⚠️ **Security warning:** Do not enable `VCKNOTS_WALLET_HTTP_ALLOWED` in production. Keep HTTPS-only validation active.

## 2. Initial Setup

This section explains how to install the library dependencies and initialize the `Wallet` instance, which aggregates the core wallet features.

### 2-1. Installing Dependencies

After setting GOPRIVATE, run the following command in the `wallet` directory to download the dependencies listed in `go.mod` (such as `github.com/go-jose/go-jose/v4`, `go.etcd.io/bbolt`, `golang.org/x/crypto`, etc.).

```bash
go mod download
```

### 2-2. Initializing the Wallet

The library exposes its top-level API in the `github.com/trustknots/vcknots/wallet` package. The simplest way to create a wallet is `wallet.NewWallet()`, which initializes every dispatcher component with its default plugin implementation:

```go
import (
    "log"

    "github.com/trustknots/vcknots/wallet"
)

w, err := wallet.NewWallet()
if err != nil {
    log.Fatal(err)
}
```

Internally, the `Wallet` coordinates six dispatcher components, each responsible for one aspect of wallet functionality:

* `credstore.CredStoreDispatcher` — credential persistence (bbolt-backed local storage by default)
* `receiver.ReceivingDispatcher` — credential issuance protocols (OID4VCI)
* `presenter.PresentationDispatcher` — credential presentation protocols (OID4VP)
* `serializer.SerializationDispatcher` — credential serialization (JWT-VC, SD-JWT VC)
* `verifier.VerificationDispatcher` — cryptographic signature verification
* `idprof.IdentityProfileDispatcher` — DIDs and identity profiles (`did:key`)

When you need custom configuration (for example, to set the trust roots used for verifying OID4VP request objects), construct the dispatchers yourself and pass them to `wallet.NewWalletWithConfig`. Every dispatcher constructor returns an error, and any field left `nil` in `wallet.Config` falls back to its default implementation. The following code is the initialization used by the samples under `wallet/examples/`:

```go
package main

import (
    "crypto/x509"
    "fmt"
    "os"

    "github.com/trustknots/vcknots/wallet"
    "github.com/trustknots/vcknots/wallet/credstore"
    "github.com/trustknots/vcknots/wallet/idprof"
    "github.com/trustknots/vcknots/wallet/presenter"
    "github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
    "github.com/trustknots/vcknots/wallet/receiver"
    "github.com/trustknots/vcknots/wallet/serializer"
    "github.com/trustknots/vcknots/wallet/verifier"
)

func newWallet(certPath string) (*wallet.Wallet, error) {
    credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
    if err != nil {
        return nil, err
    }

    receiverDisp, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
    if err != nil {
        return nil, err
    }

    serializerDisp, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
    if err != nil {
        return nil, err
    }

    verifierDisp, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
    if err != nil {
        return nil, err
    }

    idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
    if err != nil {
        return nil, err
    }

    // Trust roots for verifying the x5c certificate chain of OID4VP request objects
    certFile, err := os.ReadFile(certPath)
    if err != nil {
        return nil, err
    }
    certPool := x509.NewCertPool()
    if !certPool.AppendCertsFromPEM(certFile) {
        return nil, fmt.Errorf("failed to parse certificate: %s", certPath)
    }

    oid4vpPresenter := &oid4vp.Oid4vpPresenter{
        X509TrustChainRoots: certPool,
    }
    presenterDisp, err := presenter.NewPresentationDispatcher(
        presenter.WithPlugin(presenter.Oid4vp, oid4vpPresenter),
    )
    if err != nil {
        return nil, err
    }

    return wallet.NewWalletWithConfig(wallet.Config{
        CredStore:  credStore,
        IDProfiler: idProf,
        Receiver:   receiverDisp,
        Serializer: serializerDisp,
        Verifier:   verifierDisp,
        Presenter:  presenterDisp,
    })
}
```

* **Storage location:** The default credential store persists credentials with `go.etcd.io/bbolt` to `<user config dir>/vcknots/wallet/.local_credstore.db` (for example `~/.config/vcknots/wallet/.local_credstore.db` on Linux, `~/Library/Application Support/vcknots/wallet/.local_credstore.db` on macOS).

## 3. Sample Implementation of Wallet Features

Using the `Wallet` instance, this section provides concrete Go code samples for the main wallet functions: key preparation, receiving credentials, and presenting credentials. These samples are based on `wallet/examples/server_integration_sdjwt/server_integration_sdjwt.go` and `wallet/examples/common/common.go`.

### 3-1. Preparing Test Keys (IKeyEntry Interface)

The main workflow methods (`ReceiveCredential`, `PresentCredential`) require the `IKeyEntry` interface for signing operations. This allows library users to swap out key management implementations (for example: in-memory, HSM, secure enclave).

The `IKeyEntry` interface is defined as follows:

```go
// IKeyEntry represents a key entry interface for signing operations.
type IKeyEntry interface {
    ID() string
    PublicKey() jose.JSONWebKey
    Sign(data []byte) ([]byte, error)
}
```

* **Signature format:** ECDSA implementations of `Sign` may return either DER-encoded ASN.1 signatures or raw IEEE P1363 (`R || S`) signatures. The library normalizes DER-encoded signatures to IEEE P1363 internally (via `JWKSigner`), so both formats work.

For this tutorial, we use an in-memory implementation equivalent to `MockKeyEntry` in `wallet/examples/common/common.go`:

```go
// MockKeyEntry is a test implementation of IKeyEntry.
type MockKeyEntry struct {
    id         string
    privateKey *ecdsa.PrivateKey
}

func NewMockKeyEntry() (*MockKeyEntry, error) {
    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }
    return &MockKeyEntry{
        id:         "test-key-id-" + uuid.NewString(),
        privateKey: privKey,
    }, nil
}

func (m *MockKeyEntry) ID() string { return m.id }

func (m *MockKeyEntry) PublicKey() jose.JSONWebKey {
    return jose.JSONWebKey{
        Key:       &m.privateKey.PublicKey,
        Algorithm: "ES256", // P-256 curve
        Use:       "sig",
    }
}

// Sign performs SHA-256 hashing -> ECDSA signing -> IEEE P1363 serialization.
func (m *MockKeyEntry) Sign(payload []byte) ([]byte, error) {
    hash := sha256.Sum256(payload)
    r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
    if err != nil {
        return nil, err
    }

    const keySize = 32 // P-256: 256 bits / 8
    signature := make([]byte, 2*keySize)
    r.FillBytes(signature[:keySize])
    s.FillBytes(signature[keySize:])
    return signature, nil
}
```

### 3-2. Receiving a Credential (OID4VCI)

The wallet receives a credential by calling `ReceiveCredential` with a `CredentialOffer` obtained from the issuer. In a real deployment the offer URI comes from a QR code or deep link; with the local sample server you can create one via `POST /configurations/:configurationId/offer`.

The offer URI has the form `openid-credential-offer://?credential_offer=...`. Parse it into a `wallet.CredentialOffer` and pass it to `ReceiveCredential`:

```go
import (
    "encoding/json"
    "net/url"

    "github.com/trustknots/vcknots/wallet"
    "github.com/trustknots/vcknots/wallet/credential"
    "github.com/trustknots/vcknots/wallet/receiver"
)

func receiveSDJwtCredential(w *wallet.Wallet, key wallet.IKeyEntry, offerURI string) (*wallet.SavedCredential, error) {
    // 1. Parse the openid-credential-offer:// URI
    parsed, err := url.Parse(offerURI)
    if err != nil {
        return nil, err
    }

    var offerJSON struct {
        CredentialIssuer           string                                  `json:"credential_issuer"`
        CredentialConfigurationIDs []string                                `json:"credential_configuration_ids"`
        Grants                     map[string]*wallet.CredentialOfferGrant `json:"grants"`
    }
    if err := json.Unmarshal([]byte(parsed.Query().Get("credential_offer")), &offerJSON); err != nil {
        return nil, err
    }

    issuerURL, err := url.Parse(offerJSON.CredentialIssuer)
    if err != nil {
        return nil, err
    }

    offer := &wallet.CredentialOffer{
        CredentialIssuer:           issuerURL,
        CredentialConfigurationIDs: offerJSON.CredentialConfigurationIDs,
        Grants:                     offerJSON.Grants, // key: "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }

    // 2. Receive the credential via OID4VCI (pre-authorized code flow)
    return w.ReceiveCredential(wallet.ReceiveCredentialRequest{
        CredentialOffer: offer,
        Type:            receiver.Oid4vci,
        Key:             key,                 // used to sign the JWT proof (key binding)
        RequestedFormat: credential.SDJwtVC,  // "application/dc+sd-jwt"
    })
}
```

Notes on `ReceiveCredentialRequest`:

* **RequestedFormat:** Set `credential.SDJwtVC` to receive an SD-JWT VC, or `credential.JwtVc` for a JWT-VC. When omitted, the format is resolved from the issuer metadata for the first credential configuration ID (falling back to JWT-VC).
* **TxCode:** When the offer requires a transaction code, set `TxCode`; it is sent to the token endpoint as `tx_code`.
* **CachedIssuerMetadata:** When set, `ReceiveCredential` skips fetching the issuer metadata (see section 4).

`ReceiveCredential` fetches the issuer and authorization server metadata, obtains an access token with the pre-authorized code, generates a JWT proof signed with `Key`, requests the credential, and stores the result in the credential store. It returns a `*wallet.SavedCredential` containing both the parsed credential and its storage entry.

### 3-3. Presenting a Credential (OpenID4VP)

After receiving a request URI in the form `openid4vp://authorize?...` from the verifier (typically by scanning a QR code; with the local sample server, via `POST /request` or `POST /request-object`), call `PresentCredential`:

```go
import (
    "log"

    sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func presentCredential(w *wallet.Wallet, key wallet.IKeyEntry, oid4vpURI string) error {
    // Options for SD-JWT VC presentations: selective disclosure and Key Binding JWT
    options := &sdjwtvc.SdJwtVcPresentationOptions{
        SelectedClaims:    []string{"given_name", "family_name"},
        RequireKeyBinding: true,
    }

    redirectURI, err := w.PresentCredential(oid4vpURI, key, options)
    if err != nil {
        return err
    }
    if redirectURI != "" {
        log.Printf("Verifier requested redirect: %s\n", redirectURI)
    }
    return nil
}
```

`PresentCredential` parses the OID4VP request (including JAR request objects referenced by `request_uri`, whose signatures are verified against `X509TrustChainRoots`), selects the most recently received credential from the store (matching against the presentation definition is not performed yet), serializes and signs the Verifiable Presentation with `key`, and posts it to the verifier's `response_uri` (`response_mode=direct_post`). The wallet does not send anything to `redirect_uri`; when the verifier's response contains a `redirect_uri`, it is returned to the caller as the return value, or empty when there is none.

* **Presentation options:** The third argument accepts a format-specific options value. For SD-JWT VC, `sdjwtvc.SdJwtVcPresentationOptions` controls which claims are disclosed (`SelectedClaims`) and whether a Key Binding JWT is attached (`RequireKeyBinding`). The KB-JWT audience and nonce are filled automatically from the OID4VP request (`client_id` and `nonce`), as are `transaction_data` hashes when the request contains transaction data. Pass `nil` to use the default options for the credential's format (for JWT-VC presentations, `nil` is typical).
* **Redirect handling:** Use `PresentCredentialWithOptions` with `&wallet.PresentCredentialOptions{OnRedirect: func(uri string) error {...}}` when you want a callback invoked with the verifier's redirect URI.

### 3-4. Referencing Saved Credentials

Credentials saved via `ReceiveCredential` can be listed with `GetCredentialEntries`, which supports pagination (`Offset`, `Limit`) and filtering with a Go function (`Filter`). A single entry can be fetched by ID with `GetCredentialEntry`.

```go
func listSavedCredentials(w *wallet.Wallet) ([]*wallet.SavedCredential, error) {
    limit := 10
    entries, total, err := w.GetCredentialEntries(wallet.GetCredentialEntriesRequest{
        Offset: 0,
        Limit:  &limit,
        Filter: func(sc *wallet.SavedCredential) bool {
            return true // Example: return sc.Entry.MimeType == string(credential.SDJwtVC)
        },
    })
    if err != nil {
        return nil, err
    }

    log.Printf("Found %d matching entries (Total: %d)\n", len(entries), total)
    for _, entry := range entries {
        log.Printf(" - Entry ID: %s, MimeType: %s\n", entry.Entry.Id, entry.Entry.MimeType)
    }
    return entries, nil
}
```

## 4. Fetching Issuer Metadata

When receiving a credential, the wallet must access the issuer's `.well-known/openid-credential-issuer` endpoint to obtain the issuer's configuration (credential endpoint, supported credential configurations, and so on).

`ReceiveCredential` fetches this metadata implicitly, but you can also fetch it explicitly with `FetchCredentialIssuerMetadata` and pass the result via the `CachedIssuerMetadata` field of `ReceiveCredentialRequest`. This avoids re-fetching the metadata on every `ReceiveCredential` call.

```go
import (
    "log"
    "net/url"

    receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func fetchIssuerMetadata(w *wallet.Wallet) (*receiverTypes.CredentialIssuerMetadata, error) {
    // Note: pass the issuer's base URL; the /.well-known/... path is resolved internally
    issuerURL, _ := url.Parse("http://localhost:8080")

    metadata, err := w.FetchCredentialIssuerMetadata(issuerURL, receiverTypes.Oid4vci)
    if err != nil {
        return nil, err
    }

    log.Printf("Fetched metadata for issuer: %s\n", metadata.CredentialIssuer)
    // metadata.CredentialEndpoint, metadata.CredentialConfigurationSupported, ...
    return metadata, nil
}
```

## 5. Explanation of Type Definitions

This section explains the main Go type definitions used when interacting with the `Wallet` in the vcknots/wallet library.

### IKeyEntry {#IKeyEntry}

Core interface for key management. Defines three methods: `ID()`, `PublicKey()`, and `Sign()`. Library users implement this to integrate with HSMs, secure enclaves, and similar systems.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### Config {#Config}

Input for `NewWalletWithConfig`. Holds the six dispatcher components and the optional DPoP configuration ([DPoPConfig](#DPoPConfig)). `nil` fields fall back to default implementations.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### ReceiveCredentialRequest {#ReceiveCredentialRequest}

Main input for `ReceiveCredential`. Encapsulates the [CredentialOffer](#CredentialOffer), the receiving protocol (`Type`), the key used for proof signing ([IKeyEntry](#IKeyEntry)), the requested credential format (`RequestedFormat`), the optional `CachedIssuerMetadata`, and the optional `TxCode`.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### CredentialOffer {#CredentialOffer}

Details of the offer received from the issuer. Includes the issuer URL (`CredentialIssuer`), the credential configuration IDs (`CredentialConfigurationIDs`), and the authorization grants (`Grants`).

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### SavedCredential {#SavedCredential}

A credential stored in the credential store. Wraps `*credential.Credential` (the parsed credential) and `*types.CredentialEntry` (storage metadata: ID, raw bytes, MIME type, received time). Returned by `ReceiveCredential`, `GetCredentialEntries`, and `GetCredentialEntry`.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### GetCredentialEntriesRequest {#GetCredentialEntriesRequest}

Search conditions for `GetCredentialEntries`. Supports pagination (`Offset`, `Limit`) and dynamic filtering via a Go function (`Filter`).

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### PresentCredentialOptions {#PresentCredentialOptions}

Input for `PresentCredentialWithOptions`. Holds the format-specific `SerializeOptions` and an optional `OnRedirect` callback.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### SdJwtVcPresentationOptions {#SdJwtVcPresentationOptions}

Options for SD-JWT VC presentations: `SelectedClaims`, `RequireKeyBinding`, `Audience`, `Nonce`, and `TransactionData`. Audience and nonce are filled from the OID4VP request automatically.

For the definition, see [wallet/serializer/plugins/sdjwtvc/sdjwtvc.go](https://github.com/trustknots/vcknots/blob/main/wallet/serializer/plugins/sdjwtvc/sdjwtvc.go).

### DIDCreateOptions {#DIDCreateOptions}

Options for `GenerateDID`. Specifies the DID type (`TypeID`, e.g. `"did:key"`) and the associated public key (`PublicKey`).

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

### DPoPConfig {#DPoPConfig}

Enables DPoP proofs for the token and credential endpoints (`Enabled`), with an optional dedicated key (`Key`). When enabled without a key, an in-memory P-256 key is generated.

For the definition, see [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go).

## 6. Methods of Wallet

### ReceiveCredential

Receives a credential from an issuer via OID4VCI (pre-authorized code flow) and stores it in the credential store.

```go
func (w *Wallet) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error)
```

**Parameters**:
- `req`: Receive request ([ReceiveCredentialRequest](#ReceiveCredentialRequest))

**Return value**:
- The received and stored credential ([SavedCredential](#SavedCredential))

### PresentCredential

Responds to an OID4VP authorization request and submits a Verifiable Presentation to the verifier.

```go
func (w *Wallet) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error)
```

**Parameters**:
- `uriString`: The OID4VP request URI (`openid4vp://authorize?...`)
- `key`: The key used to sign the presentation ([IKeyEntry](#IKeyEntry))
- `options`: Format-specific presentation options (for SD-JWT VC, [SdJwtVcPresentationOptions](#SdJwtVcPresentationOptions)); pass `nil` to use the defaults for the credential's format

**Return value**:
- The redirect URI provided by the verifier, or an empty string when there is none

### PresentCredentialWithOptions

Same as `PresentCredential`, and additionally invokes a callback when the verifier returns a redirect URI.

```go
func (w *Wallet) PresentCredentialWithOptions(uriString string, key IKeyEntry, options *PresentCredentialOptions) (string, error)
```

**Parameters**:
- `uriString`: The OID4VP request URI (`openid4vp://authorize?...`)
- `key`: The key used to sign the presentation ([IKeyEntry](#IKeyEntry))
- `options`: Serialization options and redirect callback ([PresentCredentialOptions](#PresentCredentialOptions))

**Return value**:
- The redirect URI provided by the verifier, or an empty string when there is none

### GetCredentialEntries

Retrieves stored credentials with optional pagination and filtering.

```go
func (w *Wallet) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error)
```

**Parameters**:
- `req`: Search conditions ([GetCredentialEntriesRequest](#GetCredentialEntriesRequest))

**Return value**:
- The matching credentials ([SavedCredential](#SavedCredential)) and the total number of matches

### GetCredentialEntry

Retrieves a single stored credential by ID.

```go
func (w *Wallet) GetCredentialEntry(id string) (*SavedCredential, error)
```

**Parameters**:
- `id`: The credential entry ID

**Return value**:
- The stored credential ([SavedCredential](#SavedCredential)); with the default local store, an error is returned when the ID does not exist

### FetchCredentialIssuerMetadata

Fetches the issuer metadata from the issuer's `.well-known/openid-credential-issuer` endpoint.

```go
func (w *Wallet) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error)
```

**Parameters**:
- `endpoint`: The issuer's base URL (the `/.well-known/...` path is resolved internally)
- `receivingType`: The receiving protocol (`receiver.Oid4vci`)

**Return value**:
- The issuer metadata (`receiverTypes.CredentialIssuerMetadata`)

### GenerateDID

Generates a DID from a public key.

```go
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error)
```

**Parameters**:
- `options`: The DID type and public key ([DIDCreateOptions](#DIDCreateOptions))

**Return value**:
- The generated identity profile (`idprofTypes.IdentityProfile`)

## 7. Notes

1. **Mock key entries must not be used in production (CRITICAL):**
    - The in-memory key implementation shown in this tutorial (and `MockKeyEntry` in `wallet/examples/common/`) is intended only for testing and demonstration, because it keeps the private key in plaintext on the Go heap.
    - In a production environment, implement `IKeyEntry` so that the `Sign` operation is delegated to an OS keystore (iOS Secure Enclave, Android Keystore) or an HSM, and the private key itself is never loaded into the application's memory space (non-exportable).

2. **GOPRIVATE configuration:**
    - If `go mod download` or `go build` fails, the most likely cause is a missing GOPRIVATE environment variable.

3. **Signature format compatibility:**
    - `Sign` may return either DER-encoded ASN.1 or raw IEEE P1363 signatures for ES256; the library normalizes DER to P1363 before embedding signatures in JWS structures.

4. **Persistent storage (bbolt):**
    - `credstore.WithDefaultConfig()` persists credentials with `go.etcd.io/bbolt` to `<user config dir>/vcknots/wallet/.local_credstore.db`. Make sure the process can create and write to this directory.

5. **HTTPS enforcement and runtime environment variables (`wallet/env/env.go`):**
    - The wallet requires HTTPS for issuer and verifier endpoints by default.
    - `VCKNOTS_WALLET_HTTP_ALLOWED=true` allows HTTP endpoints (intended for local development/testing only).
    - `VCKNOTS_WALLET_DEBUG=true` enables debug mode and also enables the HTTP allowance behavior.
    - **Production guidance:** keep both variables unset (or `false`) so HTTPS-only validation remains active.

6. **Strict validation of OpenID4VP `client_id`:**
    - The wallet validates `client_id` strictly, in line with the OpenID4VP conformance tests. Duplicate prefixes (for example, `x509_san_dns:x509_san_dns:...`) and malformed values are rejected.
    - For the `x509_san_dns:` scheme, the certificate is extracted from the `x5c` header of the request JWT, and the Subject Alternative Name (SAN) DNS field of the certificate is matched against the `client_id` value.
    - See `wallet/presenter/plugins/oid4vp/` for the validation logic.

7. **Test configuration for certificate validation (`InsecureSkipX509Verify`):**
    - The `Oid4vpPresenter` struct provides the `InsecureSkipX509Verify` option for test environments.
    - **Default behavior (production):** full certificate chain validation is performed against `X509TrustChainRoots`.
    - **Test configuration (`InsecureSkipX509Verify: true`):** skips certificate chain validation and extracts the certificate directly from the `x5c` header; only SAN-to-`client_id` matching is performed.
    - ⚠️ **Critical warning:** use `InsecureSkipX509Verify: true` only for conformance testing or local development. **Never** use this in production.

8. **DPoP support (optional):**
    - Setting `wallet.Config{DPoP: wallet.DPoPConfig{Enabled: true}}` makes the wallet attach DPoP proofs to token and credential requests, and handle DPoP nonce challenges from the server.

## 8. Troubleshooting

* **Q: `go mod download` fails with `package ... is private` or `404 Not Found`.**
  * **A:** The GOPRIVATE environment variable is not configured. Go back to "1. Prerequisites" and make sure `export GOPRIVATE="github.com/trustknots/vcknots/wallet"` has been executed (or use mise).

* **Q: `ReceiveCredential` or `PresentCredential` fails with `connection refused` or `timeout`.**
  * **A:** The Issuer/Verifier server is not running. Follow "1. Prerequisites", start the server with `pnpm -F @trustknots/server start`, and confirm that http://localhost:8080 responds.

* **Q: `ReceiveCredential` fails with `credential issuer must use https scheme`.**
  * **A:** The wallet enforces HTTPS by default. For local testing against the HTTP sample server, set `VCKNOTS_WALLET_HTTP_ALLOWED=true` (or call `env.SetHTTPAllowed(true)`).

* **Q: `ReceiveCredential` fails with `failed to fetch issuer metadata`.**
  * **A:** The server may be running, but the `/.well-known/openid-credential-issuer` endpoint might not be functioning. Run `curl http://localhost:8080/.well-known/openid-credential-issuer` and confirm that JSON metadata is returned.

* **Q: A `client_id` validation error occurs during OpenID4VP conformance testing.**
  * **A:** Conformance tests intentionally send malformed `client_id` values (such as duplicate prefixes) to test the wallet's validation logic. Errors like `invalid client_id: duplicate prefix detected` or `SAN of the certificate and client_id did not match` are **expected behavior** and indicate that the wallet is correctly enforcing its security checks.

* **Q: An `x509: certificate is not standards compliant` error occurs during OpenID4VP conformance testing.**
  * **A:** Conformance test servers may use self-signed or non-standard certificates. Set `InsecureSkipX509Verify: true` only in test environments:
    ```go
    p := &oid4vp.Oid4vpPresenter{
        X509TrustChainRoots:    systemRoots,
        InsecureSkipX509Verify: true, // Test environments only
    }
    ```
  * ⚠️ **Warning:** always leave this `false` (or unset) in production.

For runnable end-to-end samples (JWT-VC, SD-JWT VC, and SD-JWT VC with KB-JWT), see [wallet/examples/README.md](https://github.com/trustknots/vcknots/blob/main/wallet/examples/README.md).
