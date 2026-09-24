---
sidebar_position: 13
---

# How to Set Up and Use the Wallet Feature

This tutorial explains how to set up the VCKnots wallet library (a Go library), how to receive and present credentials with it, and what to consider before using it in production environments.

The wallet implements the OpenID for Verifiable Credentials specifications:

* **Receiving credentials (OpenID4VCI):** the wallet obtains credentials from an issuer through the Pre-Authorized Code Flow or the Authorization Code Flow.
* **Presenting credentials (OpenID4VP):** the wallet answers an Authorization Request (an `openid4vp:` URI, a Request Object, or a W3C Digital Credentials API invocation) with a Verifiable Presentation.

Both **JWT-VC** (`jwt_vc_json`, `application/vc+jwt`) and **SD-JWT VC** (`dc+sd-jwt`, `application/dc+sd-jwt`) are supported for receiving and presenting, including selective disclosure and the Key Binding JWT for SD-JWT VC.

## Supported protocols and profiles

The wallet implements **OpenID4VCI 1.0** and **OpenID4VP 1.0**. **HAIP 1.0** is a profile selected with `Config.Profile`: the zero value of `profile.Profile` is `profile.Final`, and `profile.HAIP` adds the HAIP constraints. OpenID4VCI Draft 13 and OpenID4VP Draft 24 are available through the `Draft13()` and `Draft24()` views, and the pre-existing `ReceiveCredential` / `PresentCredential` methods are kept.

| Protocol / feature | Public API | Notes |
| --- | --- | --- |
| OpenID4VCI 1.0 Pre-Authorized Code Flow | `AuthorizePreAuthorizedIssuance` + `RequestCredential` | `tx_code` is required exactly when the offer declares one. |
| OpenID4VCI 1.0 Authorization Code Flow (PKCE, PAR, RFC 9207 `iss`) | `BeginIssuance` + `AuthorizeIssuance` + `RequestCredential` | The library does not open the browser. PKCE is always `S256`. PAR is used when the authorization server advertises it and required under HAIP. Wallet-initiated issuance (no offer) is supported. |
| Credential Offer by value or by reference | `ResolveCredentialOffer`, `ParseCredentialOfferURL` | `ParseCredentialOfferURL` performs no I/O. |
| Client authentication, DPoP | `Config.ClientAuth`, `Config.DPoP`, `Config.Attestation.Client` | `private_key_jwt` or OAuth 2.0 Attestation-Based Client Authentication. DPoP proofs are sent whenever `Config.DPoP.Key` is set. |
| Batch issuance | `CredentialRequest.HolderKeys` | One key proof per holder key, up to `batch_credential_issuance.batch_size`. |
| Key attestation (Appendix D) | `Config.Attestation.Key`, `CredentialRequest.KeyAttestation` | Attestations are authenticated before they are sent (`attestation.TrustPolicy`). |
| Credential Request / Response encryption | `Config.Issuance.CredentialEncryption` | The response key is ephemeral. |
| Deferred issuance | `RequestDeferredCredential` | One request per call; the library does not poll. |
| Notification | `NotifyIssuer` | The library never notifies on its own. |
| Signed Credential Issuer Metadata | `oid4vci.Oid4vciReceiver.IssuerMetadataSigning` | OpenID4VCI 1.0 §12.2.3. |
| Credential acceptance before storage | `Config.CredentialAcceptance` (`acceptance.Policy`), `VerifyCredentialForAcceptance` | Required by every OpenID4VCI 1.0 and Draft 13 view method. |
| OpenID4VP 1.0 over `direct_post` / `direct_post.jwt` | `ParsePresentationRequest`, `ParsePresentationRequestObject`, `SelectCredentials`, `SubmitPresentation`, `DeclinePresentation`; `PresentCredential` | Requests are answered through an `*oid4vp.AdmittedRequest` handle. |
| Verifier authentication | `oid4vp.Oid4vpPresenter` (`RequestObjectValidation`, `PreRegisteredClients`) | `x509_san_dns`, `x509_hash`, `redirect_uri`, pre-registered clients, `verifier_attestation`, `openid_federation`. See [Verifier authentication](#verifier-authentication). |
| `request_uri` GET / POST with `wallet_nonce` | `ParsePresentationRequest` | A POST always sends a fresh `wallet_nonce` and, when configured, `wallet_metadata`. |
| DCQL | `SelectCredentials`, `oid4vp.ResolveSatisfiableDCQLCredentials`, `oid4vp.ValidateDCQLMatches` | `credential_sets`, `claims`, `claim_sets`, `values`, nested and array claim paths, `multiple`, `trusted_authorities` of type `aki` and `openid_federation`. |
| `transaction_data` | `Config.SupportedTransactionDataTypes` | `dc+sd-jwt` presentations with key binding only. |
| W3C Digital Credentials API (`dc_api`, `dc_api.jwt`; unsigned, signed, multi-signed) | `ParseDCAPIRequest` + `SubmitPresentation` | Protocol handling only; the caller supplies the platform-authenticated origin. |
| OpenID4VCI Draft 13 | `Draft13()`, `ReceiveCredential` | Refused under HAIP. |
| OpenID4VP Draft 24 (Presentation Exchange) | `Draft24()` + `SubmitPresentation` | Refused under HAIP. |
| Formats | `credential.SDJwtVC`, `credential.JwtVc`, `credential.LdpVc` | SD-JWT VC issuer `typ` may be `dc+sd-jwt` or `vc+sd-jwt`. `ldp_vc` uses Data Integrity `eddsa-rdfc-2022` proofs. |

**Not implemented.** ISO mdoc (`mso_mdoc`): there is no mdoc / COSE / CBOR serializer, so no mdoc presentation can be built. The `decentralized_identifier` Client Identifier Prefix is parsed and refused. Of the DCQL `trusted_authorities` types `aki` and `openid_federation` are evaluated; an entry of another type (`etsi_tl`) matches no credential.

### Profiles (Final and HAIP)

* **Final** is OpenID4VCI 1.0 and OpenID4VP 1.0 without additional constraints. It is the default: a zero `profile.Profile` normalizes to `profile.Final`.
* **HAIP** adds the HAIP 1.0 constraints. Select it with `Config.Profile`, and build the receiver and presenter plugins with the same profile (`oid4vci.Oid4vciReceiver.Profile`, `oid4vp.Oid4vpPresenter.Profile`). The plugins the wallet builds itself get the wallet's profile.
* The wallet never changes a plugin it is given. See [Profile rules](#profile-rules) for what `NewWalletWithConfig` checks.

## 1. Prerequisites

* **Supported specifications:**
    - Receiving: [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), with HAIP 1.0 as an optional profile; OpenID4VCI Draft 13
    - Presenting: [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), with HAIP 1.0 as an optional profile; OpenID4VP Draft 24
    - For the full implementation scope of each feature, see [VC Knots Coverage](./support-matrix.md).

### 1-1. Go Environment Requirements

* **Go version:** The vcknots/wallet library requires the Go version pinned in `wallet/mise.toml` (Go 1.26.6).
* **Development environment management (mise):**
    - We recommend using [mise](https://mise.jdx.dev/) to manage the development environment.
    - Running `mise install` in the `wallet` directory installs the required Go version and sets the necessary environment variables.

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

The sample code in this tutorial assumes that counterpart services (an Issuer and a Verifier) are available. The Node.js-based sample server (`server/`) in this repository provides both.

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
* `POST /token`, `POST /nonce`, `POST /credentials` — OpenID4VCI token, nonce, and credential endpoints
* `POST /request`, `POST /request-object` — creates an OpenID4VP authorization request
* `POST /callback` — the verifier's response endpoint
* `GET /.well-known/openid-credential-issuer`, `GET /.well-known/oauth-authorization-server` — metadata endpoints

* **Allowing HTTP for local testing:** The wallet rejects non-HTTPS issuer and verifier endpoints by default. Because the local sample server runs on plain HTTP, enable HTTP explicitly when testing locally:

```bash
export VCKNOTS_WALLET_HTTP_ALLOWED=true
```

The variable is read when a default dispatcher or plugin is built (`NewWallet`, `receiver.WithDefaultConfig`, `presenter.WithDefaultConfig`). A plugin you construct yourself uses its own `AllowHTTP` field instead. `env.SetHTTPAllowed(true)` (package `github.com/trustknots/vcknots/wallet/env`) sets the variable from test code.

> ⚠️ **Security warning:** Do not enable `VCKNOTS_WALLET_HTTP_ALLOWED` or `AllowHTTP` in production. HAIP refuses both.

## 2. Initial Setup

This section explains how to install the library dependencies and initialize the `Wallet` instance.

### 2-1. Installing Dependencies

After setting GOPRIVATE, run the following command in the `wallet` directory to download the dependencies listed in `go.mod`:

```bash
go mod download
```

### 2-2. Initializing the Wallet

The top-level API is in the `github.com/trustknots/vcknots/wallet` package. `wallet.NewWallet()` initializes every dispatcher with its default plugin:

```go
import "github.com/trustknots/vcknots/wallet"

func newDefaultWallet() (*wallet.Wallet, error) {
	return wallet.NewWallet()
}
```

The `Wallet` coordinates six dispatchers:

* `credstore.CredStoreDispatcher` — credential persistence (bbolt-backed local storage by default)
* `receiver.ReceivingDispatcher` — credential issuance protocols (OpenID4VCI)
* `presenter.PresentationDispatcher` — credential presentation protocols (OpenID4VP)
* `serializer.SerializationDispatcher` — credential serialization (JWT-VC, SD-JWT VC, LDP-VC)
* `verifier.VerificationDispatcher` — signature verification
* `idprof.IdentityProfileDispatcher` — DIDs and identity profiles (`did:key`, `did:jwk`)

To configure a plugin, for example the trust roots used for OpenID4VP Request Objects, build the dispatcher yourself and pass it to `wallet.NewWalletWithConfig`. Every `nil` dispatcher in `wallet.Config` falls back to its default. The samples under `wallet/examples/` build the wallet like this:

```go
package main

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/env"
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

	// Trust roots for the x5c chain of signed OpenID4VP Request Objects.
	certFile, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certFile) {
		return nil, fmt.Errorf("failed to parse certificate: %s", certPath)
	}

	oid4vpPresenter := &oid4vp.Oid4vpPresenter{
		AllowHTTP:           env.IsHTTPAllowed(), // local sample server only
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

* **Storage location:** The default credential store persists credentials with `go.etcd.io/bbolt` to `<user config dir>/vcknots/wallet/.local_credstore.db` (for example `~/.config/vcknots/wallet/.local_credstore.db` on Linux). `Config.Storeless` builds a wallet without a store: received credentials are returned and not stored, and presentations take credentials by value.

## 3. Sample Implementation of Wallet Features

This section shows the smallest receive and present samples, based on `wallet/examples/server_integration_sdjwt/server_integration_sdjwt.go` and `wallet/examples/common/common.go`. They use `ReceiveCredential` and `PresentCredential`, which run a whole flow in one call. The staged API that a wallet with a user needs is described in [OpenID4VCI 1.0 issuance](#openid4vci-10-issuance) and [OpenID4VP 1.0 presentation](#openid4vp-10-presentation).

### 3-1. Preparing Test Keys (IKeyEntry Interface)

Every key the wallet signs with (holder, DPoP, client authentication, attester) is an `IKeyEntry`:

```go
import "github.com/go-jose/go-jose/v4"

// IKeyEntry is a signing key.
type IKeyEntry interface {
	ID() string
	PublicKey() jose.JSONWebKey
	Sign(data []byte) ([]byte, error)
}
```

* **Signature format:** ECDSA implementations of `Sign` may return DER-encoded ASN.1 or raw IEEE P1363 (`R || S`) signatures; the library converts DER to P1363.
* **Algorithm:** `PublicKey().Algorithm` selects the JWS algorithm. When it is empty, the curve decides (P-256, P-384, P-521 give ES256, ES384, ES512; Ed25519 gives EdDSA). An RSA key must set it.

`keystore.NewKeyEntryFromJWK` builds an `IKeyEntry` from a private EC JWK. For this tutorial, an in-memory key equivalent to `MockKeyEntry` in `wallet/examples/common/common.go`:

```go
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

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
		Algorithm: "ES256",
		Use:       "sig",
	}
}

// Sign hashes with SHA-256, signs with ECDSA and returns the IEEE P1363 form.
func (m *MockKeyEntry) Sign(payload []byte) ([]byte, error) {
	hash := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	const keySize = 32 // P-256
	signature := make([]byte, 2*keySize)
	r.FillBytes(signature[:keySize])
	s.FillBytes(signature[keySize:])
	return signature, nil
}
```

### 3-2. Receiving a Credential (OID4VCI)

`ReceiveCredential` runs a Pre-Authorized Code issuance in one call. In a real deployment the offer URI comes from a QR code or deep link; with the local sample server, create one with `POST /configurations/:configurationId/offer`.

```go
import (
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/receiver"
)

func receiveSDJwtCredential(w *wallet.Wallet, key wallet.IKeyEntry, offerURI string) (*wallet.SavedCredential, error) {
	// openid-credential-offer://?credential_offer=...
	offer, err := wallet.ParseCredentialOfferURL(offerURI)
	if err != nil {
		return nil, err
	}

	return w.ReceiveCredential(wallet.ReceiveCredentialRequest{
		CredentialOffer: offer,
		Type:            receiver.Oid4vci,
		Key:             key,                // signs the key proof
		RequestedFormat: credential.SDJwtVC, // "application/dc+sd-jwt"
	})
}
```

Notes on `ReceiveCredentialRequest`:

* **RequestedFormat:** `credential.SDJwtVC` or `credential.JwtVc`. When empty, the format of the first offered configuration is used.
* **TxCode:** sent to the token endpoint as `tx_code` when the offer requires one.
* **CachedIssuerMetadata:** when set, the issuer metadata is not fetched (see section 4).

`ReceiveCredential` fetches the issuer and authorization server metadata, obtains an access token with the pre-authorized code, signs the key proof with `Key`, requests the credential, checks it and stores it. The check is `Config.CredentialAcceptance` when it is set; without a policy the credential is only parsed (`typ`, `alg`, and a `cnf` that must match `Key`) and its issuer is not authenticated. `ReceiveCredential` is refused under HAIP; new code uses `AuthorizePreAuthorizedIssuance` and `RequestCredential`.

### 3-3. Presenting a Credential (OpenID4VP)

After receiving a request URI of the form `openid4vp:?...` from the verifier (with the local sample server, via `POST /request` or `POST /request-object`), call `PresentCredential`:

```go
import (
	"log"

	"github.com/trustknots/vcknots/wallet"
	sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func presentCredential(w *wallet.Wallet, key wallet.IKeyEntry, oid4vpURI string) error {
	// Limits SD-JWT VC disclosure to these claims.
	options := &sdjwtvc.SdJwtVcPresentationOptions{
		SelectedClaims: []string{"given_name", "family_name"},
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

`PresentCredential` is `ParsePresentationRequest`, `SelectCredentials` and `SubmitPresentation` in one call. It admits the request under the presenter's trust policy (see [Verifier authentication](#verifier-authentication)), chooses stored credentials that satisfy the DCQL query, signs one presentation per credential with `key` and sends the response to the endpoint the request named. It never contacts the `redirect_uri` the verifier returns; the URI is the return value, or empty when there is none.

* **Presentation options:** The third argument is a format-specific options value, or `nil` for the serializer's default. The KB-JWT audience and nonce always come from the request. For SD-JWT VC, a non-empty `SelectedClaims` limits disclosure, and a request for a claim outside it fails. A Key Binding JWT is attached when the DCQL query requires holder binding (the default), when `RequireKeyBinding` is set, when `transaction_data` is presented, and under HAIP whenever the credential carries `cnf`.
* **Redirect handling:** `PresentCredentialWithOptions` with `&wallet.PresentCredentialOptions{OnRedirect: func(uri string) error {...}}` calls back with the verifier's redirect URI.
* **Draft 24:** `PresentCredential` parses OpenID4VP 1.0 requests only. Use `Draft24()` for a Presentation Exchange request.

### 3-4. Referencing Saved Credentials

`GetCredentialEntries` lists stored credentials with pagination (`Offset`, `Limit`) and a Go filter (`Filter`). `GetCredentialEntry` returns one entry by ID, or `nil` and no error when no entry has that ID.

```go
import (
	"log"

	"github.com/trustknots/vcknots/wallet"
)

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

`FetchCredentialIssuerMetadata` fetches the issuer's `.well-known/openid-credential-issuer` document. `ReceiveCredential` fetches it itself unless `ReceiveCredentialRequest.CachedIssuerMetadata` is set. The OpenID4VCI 1.0 methods always re-discover the metadata and take no cached copy.

```go
import (
	"log"
	"net/url"

	"github.com/trustknots/vcknots/wallet"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func fetchIssuerMetadata(w *wallet.Wallet) (*receiverTypes.CredentialIssuerMetadata, error) {
	// The Credential Issuer Identifier; the well-known path is inserted internally.
	issuerURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		return nil, err
	}

	metadata, err := w.FetchCredentialIssuerMetadata(issuerURL, receiverTypes.Oid4vci)
	if err != nil {
		return nil, err
	}

	log.Printf("Fetched metadata for issuer: %s\n", metadata.CredentialIssuer)
	return metadata, nil
}
```

The receiver refuses metadata whose `credential_issuer` is not the requested identifier (OpenID4VCI 1.0 §12.2.4).

## 5. Explanation of Type Definitions

This section lists the main types of the `wallet` package. The field-level documentation is in the Go doc of [wallet/](https://github.com/trustknots/vcknots/tree/main/wallet).

### IKeyEntry {#IKeyEntry}

A signing key: `ID()`, `PublicKey()` and `Sign()`. It has the method set of `keystore.KeyEntry`, so values convert both ways. See [Keys and signing](#keys-and-signing).

### Config {#Config}

Input for `NewWalletWithConfig`. Every field is optional.

| Field | Meaning |
| --- | --- |
| `CredStore`, `IDProfiler`, `Receiver`, `Serializer`, `Verifier`, `Presenter` | The dispatchers. `nil` builds the default. The OpenID4VP plugin of an injected `Presenter` must be an `*oid4vp.Oid4vpPresenter`, because the presentation methods answer its `*oid4vp.AdmittedRequest` handles. |
| `Profile` | `profile.Final` (zero value) or `profile.HAIP`. |
| `Storeless` | No credential store. `CredStore` must then be `nil`; methods that need a store return `ErrNoCredentialStore`. |
| `CredentialAcceptance` | `*acceptance.Policy` applied before a received credential is returned or stored. `nil` makes every OpenID4VCI 1.0 method, every `Draft13()` method and `VerifyCredentialForAcceptance` fail with `ErrCredentialAcceptancePolicyRequired`. |
| `SupportedTransactionDataTypes` | The `transaction_data` types of the presenter the wallet builds. Setting it together with `Presenter` is refused; set `Oid4vpPresenter.SupportedTransactionDataTypes` on an injected plugin. |
| `DPoP` | [DPoPConfig](#DPoPConfig). |
| `ClientAuth` | [ClientAuthConfig](#ClientAuthConfig). `ClientID` is the wallet's `client_id` for every OpenID4VCI version. |
| `Issuance` | `IssuanceConfig{RedirectURI, CredentialEncryption}`: the Authorization Code Flow `redirect_uri` and the holder's `CredentialEncryptionPolicy`. |
| `Attestation` | `AttestationConfig{Client, ClientKey, Key, Trust}`: client and key attestation providers, the key the client attestation binds (`nil` means `DPoP.Key`) and the `attestation.TrustPolicy` that authenticates them. |
| `TestHooks` | `*TestHooks{KeyProof, PresentationExchangeResponse}`: rewrite Draft 13 key proofs and Draft 24 responses after they were built, for testing a peer. Refused under HAIP. |

### ReceiveCredentialRequest {#ReceiveCredentialRequest}

Input for `ReceiveCredential`: the [CredentialOffer](#CredentialOffer), the receiving protocol (`Type`), the key proof key (`Key`), the requested format (`RequestedFormat`), the optional `CachedIssuerMetadata` and the optional `TxCode`.

### CredentialOffer {#CredentialOffer}

A Credential Offer: the issuer URL (`CredentialIssuer`), the configuration IDs (`CredentialConfigurationIDs`) and the grants (`Grants`). A `CredentialOfferGrant` carries `PreAuthorizedCode`, `TxCode`, `IssuerState` and the `AuthorizationServer` hint.

### SavedCredential {#SavedCredential}

A received or stored credential: `Credential` (parsed), `Entry` (storage entry: ID, raw bytes, MIME type, received time) and `Verification` (`*acceptance.Verification`, what was authenticated before storing; `nil` for credentials loaded from storage).

### GetCredentialEntriesRequest {#GetCredentialEntriesRequest}

Search conditions for `GetCredentialEntries`: `Offset`, `Limit` and `Filter`.

### PresentCredentialOptions {#PresentCredentialOptions}

Input for `PresentCredentialWithOptions`: `SerializeOptions` and an optional `OnRedirect` callback.

### SdJwtVcPresentationOptions {#SdJwtVcPresentationOptions}

Options for SD-JWT VC presentations (package `serializer/plugins/sdjwtvc`): `SelectedClaims`, `RequireKeyBinding`, `LimitDisclosureToSelectedClaims`, `RequireRootClaimMatch`, and the request-bound `Audience`, `Nonce`, `TransactionData` and `TransactionDataHashesAlg`, which the wallet fills from the request.

### DIDCreateOptions {#DIDCreateOptions}

Options for `GenerateDID`: the DID type (`TypeID`, for example `"did:key"`) and the public key (`PublicKey`).

### DPoPConfig {#DPoPConfig}

`Key` is the wallet's DPoP key. The OpenID4VCI 1.0 methods send a DPoP proof whenever it is set; HAIP requires it (`ErrDPoPKeyRequired`). `Enabled` generates an in-memory key when `Key` is `nil` and forces DPoP on the `Draft13()` and `ReceiveCredential` paths, which otherwise use DPoP only when the authorization server advertises it.

### ClientAuthConfig {#ClientAuthConfig}

Token endpoint client authentication: `Method` (`""` means none, or `receiverTypes.PrivateKeyJwt`), `ClientID`, `Key`, `AssertionAudience` and `SigningAlg` (ES256, ES384 or ES512). With `private_key_jwt` the authorization server must advertise both the method and the signing algorithm; otherwise the token request is not sent (`client_authentication_unavailable`).

## 6. Methods of Wallet

`*Wallet` has 25 methods:

| Area | Methods |
| --- | --- |
| Construction and storage | `SetReceiver` (deprecated), `GetCredentialEntries`, `GetCredentialEntry`, `GenerateDID` |
| Credential checks | `VerifyCredential`, `VerifyCredentialForAcceptance` |
| OpenID4VCI 1.0 | `ResolveCredentialOffer`, `BeginIssuance`, `AuthorizeIssuance`, `AuthorizePreAuthorizedIssuance`, `RequestCredential`, `RequestDeferredCredential`, `NotifyIssuer` |
| OpenID4VCI one-call and metadata | `ReceiveCredential`, `FetchCredentialIssuerMetadata` |
| OpenID4VP 1.0 | `ParsePresentationRequest`, `ParsePresentationRequestObject`, `ParseDCAPIRequest`, `SelectCredentials`, `SubmitPresentation`, `DeclinePresentation` |
| OpenID4VP one-call | `PresentCredential`, `PresentCredentialWithOptions` |
| Draft views | `Draft13()` (`BeginIssuance`, `AuthorizeIssuance`, `AuthorizePreAuthorizedIssuance`, `RequestCredential`, `RequestDeferredCredential`, `NotifyIssuer`), `Draft24()` (`ParsePresentationRequest`, `ParsePresentationRequestObject`) |

The methods that take a `context.Context` stop when it is canceled. Every error a method returns carries a code (see [Error codes](#error-codes)).

### ReceiveCredential

Receives a credential through the Pre-Authorized Code Flow and stores it.

```go
func (w *Wallet) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error)
```

**Parameters**:
- `req`: Receive request ([ReceiveCredentialRequest](#ReceiveCredentialRequest))

**Return value**:
- The received and stored credential ([SavedCredential](#SavedCredential))

### PresentCredential

Answers an OpenID4VP 1.0 Authorization Request with the library's own credential choice.

```go
func (w *Wallet) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error)
```

**Parameters**:
- `uriString`: The request URI (`openid4vp:?...`)
- `key`: The holder key ([IKeyEntry](#IKeyEntry))
- `options`: Format-specific presentation options (for SD-JWT VC, [SdJwtVcPresentationOptions](#SdJwtVcPresentationOptions)), or `nil`

**Return value**:
- The redirect URI the verifier returned, or an empty string

### PresentCredentialWithOptions

Same as `PresentCredential`, and calls `OnRedirect` with the verifier's redirect URI.

```go
func (w *Wallet) PresentCredentialWithOptions(uriString string, key IKeyEntry, options *PresentCredentialOptions) (string, error)
```

### GetCredentialEntries

Retrieves stored credentials with optional pagination and filtering.

```go
func (w *Wallet) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error)
```

**Return value**:
- The matching credentials and the total number of matches

### GetCredentialEntry

Retrieves one stored credential by ID; `nil` and no error when there is none.

```go
func (w *Wallet) GetCredentialEntry(id string) (*SavedCredential, error)
```

### FetchCredentialIssuerMetadata

Fetches the Credential Issuer Metadata.

```go
func (w *Wallet) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error)
```

### GenerateDID

Generates a DID from a public key.

```go
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error)
```

### VerifyCredential

Reports whether a credential's proof verifies under a public key. Only `acceptance.DefaultSigningAlgorithms()` (ES256) are accepted.

```go
func (w *Wallet) VerifyCredential(credential *credential.Credential, pubKey jose.JSONWebKey) bool
```

### VerifyCredentialForAcceptance

Runs `Config.CredentialAcceptance` over a raw credential, the check issuance runs before storing, and stores nothing.

```go
func (w *Wallet) VerifyCredentialForAcceptance(ctx context.Context, raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey) (*credential.Credential, *acceptance.Verification, error)
```

### SetReceiver

Replaces the receiver dispatcher after checking its plugins as `NewWalletWithConfig` does. A refused dispatcher is not installed; every method that needs the receiver then returns the refusal. Deprecated: set `Config.Receiver`.

```go
func (w *Wallet) SetReceiver(r *receiver.ReceivingDispatcher)
```

The OpenID4VCI 1.0 and OpenID4VP 1.0 methods are described in the next sections.

## OpenID4VCI 1.0 issuance {#openid4vci-10-issuance}

### Staged flow and state

An OpenID4VCI 1.0 issuance runs in stages, and each stage returns the state the next one takes:

| Stage | Method | Returns |
| --- | --- | --- |
| Resolve the offer | `ResolveCredentialOffer(ctx, raw)` | `*CredentialOffer` |
| Start the Authorization Code Flow | `BeginIssuance(ctx, IssuanceRequest)` | `*IssuanceAuthorization` |
| Exchange the code | `AuthorizeIssuance(ctx, authorization, redirectURL)` | `*IssuanceGrant` |
| Exchange a pre-authorized code | `AuthorizePreAuthorizedIssuance(ctx, PreAuthorizedIssuanceRequest)` | `*IssuanceGrant` |
| Request the credentials | `RequestCredential(ctx, grant, CredentialRequest)` | `*IssuanceResult` |
| Poll a deferred transaction once | `RequestDeferredCredential(ctx, deferred)` | `*IssuanceResult` |
| Notify the issuer | `NotifyIssuer(ctx, notification, event, description)` | `error` |

The state types (`IssuanceAuthorization`, `IssuanceGrant`, `DeferredIssuance`, `IssuanceNotification`) are JSON-serializable and carry a `Version`, so a stage can run in another process. They hold identifiers and secrets only: each stage re-discovers the issuer and authorization server metadata, and checks that the state still fits the wallet (the same `ClientAuth.ClientID`, `Issuance.RedirectURI` and DPoP key, an authorization server the issuer still delegates to), refusing a mismatch with `ErrIssuanceStateMismatch`. A state of the other OpenID4VCI version is refused with `ErrIssuanceVersionMismatch`.

**The state JSON is a bearer secret.** It carries the PKCE `code_verifier`, the access token or the ephemeral response decryption key. Keep it server-side or encrypted, and out of logs.

Every OpenID4VCI 1.0 method requires `Config.CredentialAcceptance`. Under HAIP each stage also requires `Config.DPoP.Key`, and the stages that call the PAR or token endpoint (`BeginIssuance`, `AuthorizeIssuance`, `AuthorizePreAuthorizedIssuance`) require a client authentication mechanism (`private_key_jwt` or `Config.Attestation.Client`, HAIP §4.4.1).

### Authorization Code Flow

`BeginIssuance` resolves the metadata, checks the Credential Configuration against the profile and `Config.Issuance.CredentialEncryption`, pushes the authorization request when the server supports RFC 9126 PAR (HAIP requires it), and returns the URL to open in the holder's browser. `AuthorizeIssuance` takes the whole redirect URL the browser delivered, checks it (RFC 6749 §4.1.2, RFC 9207 `iss`, `state`, `redirect_uri`) and exchanges the code.

```go
import (
	"context"
	"encoding/json"

	"github.com/trustknots/vcknots/wallet"
)

// beginIssuance starts an Authorization Code Flow from a Credential Offer URI.
// The caller opens authorizationURL in the holder's browser and keeps state.
func beginIssuance(ctx context.Context, w *wallet.Wallet, offerURI string) (state []byte, authorizationURL string, err error) {
	offer, err := w.ResolveCredentialOffer(ctx, offerURI)
	if err != nil {
		return nil, "", err
	}
	authorization, err := w.BeginIssuance(ctx, wallet.IssuanceRequest{CredentialOffer: offer})
	if err != nil {
		return nil, "", err
	}
	state, err = json.Marshal(authorization) // a bearer secret
	return state, authorization.AuthorizationURL, err
}

// finishIssuance continues from the redirect the holder's browser delivered.
func finishIssuance(ctx context.Context, w *wallet.Wallet, state []byte, redirectURL string, holderKey wallet.IKeyEntry) (*wallet.IssuanceResult, error) {
	var authorization wallet.IssuanceAuthorization
	if err := json.Unmarshal(state, &authorization); err != nil {
		return nil, err
	}
	grant, err := w.AuthorizeIssuance(ctx, &authorization, redirectURL)
	if err != nil {
		return nil, err
	}
	return w.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{holderKey},
	})
}
```

* **Wallet-initiated issuance:** with `CredentialOffer` nil, set `IssuanceRequest.CredentialIssuer` and `CredentialConfigurationID`.
* **`AuthorizationRequestType`:** the empty value uses `scope` when the configuration advertises one and `authorization_details` otherwise; `AuthorizationRequestScope` and `AuthorizationRequestDetails` force one. HAIP allows `scope` only.
* **Redirect checks:** `ErrAuthorizationRedirectInvalid`, `ErrAuthorizationRedirectURIMismatch`, `ErrAuthorizationStateMismatch`, `ErrAuthorizationIssMismatch`, `ErrAuthorizationIssMissing` and `ErrAuthorizationCodeMissing` are matched with `errors.Is`. An `error=` redirect is an `*AuthorizationResponseError`.
* **`request_uri` lifetime:** `IssuanceAuthorization.RequestURIExpired(now)` reports whether the pushed `request_uri` can still be opened. It bounds opening the URL only; the redirect may arrive later.
* **Endpoint refusals:** the metadata, PAR, token and nonce endpoints report an `*oid4vci.EndpointError` naming the `Stage`; the Credential and Deferred Credential endpoints report a `*receiverTypes.CredentialEndpointError` carrying the §8.3.1.2 error code.

### Pre-Authorized Code Flow

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
)

func receivePreAuthorized(ctx context.Context, w *wallet.Wallet, offerURI, txCode string, holderKey wallet.IKeyEntry) (*wallet.IssuanceResult, error) {
	offer, err := w.ResolveCredentialOffer(ctx, offerURI)
	if err != nil {
		return nil, err
	}
	grant, err := w.AuthorizePreAuthorizedIssuance(ctx, wallet.PreAuthorizedIssuanceRequest{
		CredentialOffer: offer,
		TxCode:          txCode, // required exactly when the offer carries tx_code
	})
	if err != nil {
		return nil, err
	}
	return w.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{holderKey},
	})
}
```

The client is anonymous unless `private_key_jwt` or `Config.Attestation.Client` authenticates it; `Config.ClientAuth.ClientID` is sent when set, and HAIP requires it.

### Credential request, deferred issuance and notification

`RequestCredential` sends one key proof per holder key (more than one requests a batch), a key attestation when needed, and request and response encryption per `Config.Issuance.CredentialEncryption`. The credentials are checked under `Config.CredentialAcceptance` and stored unless the wallet is storeless. `IssuanceResult` holds either `Credentials` or a pending `Deferred` transaction, and a `Notification` when the issuer asked to be notified. When the credentials are refused, the error comes with a result whose `Notification` lets the caller report `credential_failure`.

The library neither polls nor notifies on its own:

```go
import (
	"context"
	"time"

	"github.com/trustknots/vcknots/wallet"
)

// completeIssuance polls a deferred transaction and reports the outcome to the
// issuer.
func completeIssuance(ctx context.Context, w *wallet.Wallet, result *wallet.IssuanceResult, err error) error {
	for err == nil && result.Deferred != nil {
		wait := max(result.Deferred.Interval, 5*time.Second)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		result, err = w.RequestDeferredCredential(ctx, result.Deferred)
	}
	if err != nil {
		if result != nil && result.Notification != nil {
			_ = w.NotifyIssuer(ctx, result.Notification, wallet.NotificationCredentialFailure, "")
		}
		return err
	}
	if result.Notification != nil {
		return w.NotifyIssuer(ctx, result.Notification, wallet.NotificationCredentialAccepted, "")
	}
	return nil
}
```

`DeferredIssuance.Interval` is the interval the issuer asked for; the caller decides how long to wait. `NotifyIssuer` finds the `notification_endpoint` in the re-discovered metadata and sends `credential_accepted`, `credential_failure` or `credential_deleted`.

### Key attestation

When the issuer requires a key attestation (`key_attestations_required`, OpenID4VCI 1.0 Appendix D) and neither `CredentialRequest.KeyAttestation` nor `Config.Attestation.Key` supplies one, `RequestCredential` sends nothing and returns `*KeyAttestationRequiredError`. It names what the attestation must cover, so an attester in another process can sign it:

```go
import (
	"context"
	"errors"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/attestation"
)

func requestWithKeyAttestation(ctx context.Context, w *wallet.Wallet, grant *wallet.IssuanceGrant, holderKey wallet.IKeyEntry,
	sign func(context.Context, attestation.KeyRequest) (string, error)) (*wallet.IssuanceResult, error) {
	request := wallet.CredentialRequest{HolderKeys: []wallet.IKeyEntry{holderKey}}
	result, err := w.RequestCredential(ctx, grant, request)
	var required *wallet.KeyAttestationRequiredError
	if !errors.As(err, &required) {
		return result, err
	}
	jwt, err := sign(ctx, attestation.KeyRequest{
		Keys:     required.HolderKeys,
		Nonce:    required.CNonce,
		Audience: required.Audience,
	})
	if err != nil {
		return nil, err
	}
	request.KeyAttestation = &attestation.KeyAttestation{JWT: jwt}
	return w.RequestCredential(ctx, required.Grant, request)
}
```

`NonceRejected` is set when the supplied attestation carried another nonce or the issuer answered `invalid_nonce`; `Grant` then names the fresh `c_nonce`. `IssuerRequired` is false when the attestation was only volunteered with `IncludeKeyAttestation`.

### Credential encryption

`Config.Issuance.CredentialEncryption` is the holder's policy for Credential Request (§8.1) and Credential Response (§8.2) encryption. Each of `Request` and `Response` is `CredentialEncryptionFollowIssuer` (encrypt what the issuer advertises, obey an issuer that requires it), `CredentialEncryptionRequired` (refuse an issuer that does not offer it, `ErrCredentialEncryptionUnavailable`) or `CredentialEncryptionDisabled` (refuse an issuer that requires it, `ErrCredentialEncryptionDisallowed`). The response key is carried only inside an encrypted request, so requiring response encryption requires request encryption. A conflict is refused at `BeginIssuance` or `AuthorizePreAuthorizedIssuance`. The response decryption key is ephemeral and travels in `DeferredIssuance`. A plaintext response after encryption was requested is refused.

### Client authentication, DPoP and attestations

* **`private_key_jwt`:** `Config.ClientAuth` with `Method: receiverTypes.PrivateKeyJwt`, `ClientID` and `Key`. The package `clientconfig` loads it from a JSON registration file.
* **Attestation-Based Client Authentication:** `Config.Attestation.Client` (`attestation.ClientProvider`) supplies the Wallet Attestation for the selected authorization server; the PoP is signed with `Config.Attestation.ClientKey`, or `Config.DPoP.Key` when that is nil.
* **Key attestation:** `Config.Attestation.Key` (`attestation.KeyProvider`).
* **DPoP:** proofs are signed with `Config.DPoP.Key`; a DPoP-bound grant must be presented with the same key (`ErrDPoPKeyMismatch`). One `use_dpop_nonce` retry is made when the server asks for it.

The library never holds an attester's private key. Before an attestation is sent, it is authenticated under `Config.Attestation.Trust` (`attestation.TrustPolicy`): an attestation with `x5c` is verified with its leaf key, and the chain is validated when `TrustAnchors` or `RootCAs` are set; one without `x5c` needs `ResolveKey`. The `StaticClientAttester` and `StaticKeyAttester` of package `attestation` self-issue with a local key for tests and single-operator deployments; the wallet resolves their key itself. Under HAIP the attestation must carry a non-self-signed `x5c` leaf without the trust anchor. A refused attestation is `attestation.ErrClientAttestationInvalid` or `attestation.ErrKeyAttestationInvalid`.

### Signed issuer metadata

`oid4vci.Oid4vciReceiver.IssuerMetadataSigning` configures OpenID4VCI 1.0 §12.2.3 signed Credential Issuer Metadata. `Request` sends the signed-metadata `Accept` header and has no effect without trust material; `Require` rejects an unsigned document. The signer is authenticated from the `x5c` header against `TrustAnchors` or `RootCAs`, and `sub` and `credential_issuer` must both be the requested identifier. `RequireIssuerDNSBinding` and `ExpectedLeafDNSName` add a DNS binding of the leaf certificate. Every re-discovery applies this policy.

Every rejection of a signed document satisfies `errors.Is(err, ErrIssuerMetadataSignatureInvalid)`; `ErrIssuerMetadataSubjectMismatch`, `ErrIssuerMetadataLeafDNSMismatch` and `ErrIssuerMetadataExpired` wrap it. `ErrIssuerMetadataSignatureRequired` is the `Require` outcome. `CredentialIssuerMetadata.MetadataSignature` records the accepted signer, and `RawDocument` keeps the accepted document.

`oid4vci.Oid4vciReceiver.IssuerMetadataFederation` (a `*federation.Resolver` with the wallet's `TrustAnchors` and discovery bounds) serves an issuer that publishes its metadata only through OpenID Federation. When the metadata document answers 404, the metadata is the `openid_credential_issuer` metadata derived from a Trust Chain to one of the anchors, after the chain's metadata policies; its `credential_issuer` must still be the requested identifier. Without a valid chain the discovery fails. It is not consulted when `IssuerMetadataSigning.Require` is set, because federation metadata is not §12.2.3 signed metadata.

### Draft 13

`w.Draft13()` runs OpenID4VCI Draft 13 with the same staged methods and state types; the states carry `IssuanceVersionDraft13`. A Credential Offer is required, the `c_nonce` comes from the Token and Credential Responses, one key proof is sent, and there are no key attestations or credential encryption. `Config.TestHooks.KeyProof` rewrites the key proof for testing.

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
)

func receiveDraft13(ctx context.Context, w *wallet.Wallet, offerURI, txCode string, holderKey wallet.IKeyEntry) (*wallet.IssuanceResult, error) {
	offer, err := wallet.ParseCredentialOfferURL(offerURI)
	if err != nil {
		return nil, err
	}
	draft13 := w.Draft13()
	grant, err := draft13.AuthorizePreAuthorizedIssuance(ctx, wallet.PreAuthorizedIssuanceRequest{
		CredentialOffer: offer,
		TxCode:          txCode,
	})
	if err != nil {
		return nil, err
	}
	return draft13.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{holderKey},
	})
}
```

## Credential acceptance

Package `acceptance` decides whether a received credential may be stored. It needs no wallet: `acceptance.NewAcceptor(profile, serializer, verifier)` returns an `Acceptor` whose `Verify(ctx, raw, policy, options)` applies an `acceptance.Policy`. The wallet runs the same check with `Config.CredentialAcceptance` before it returns or stores a credential.

The checks are:

* **Parse and header.** The credential parses, the issuer JWT carries an algorithm from `Policy.SigningAlgorithms` (default `acceptance.DefaultSigningAlgorithms()`, ES256) and, for SD-JWT VC, a `dc+sd-jwt` or `vc+sd-jwt` `typ`.
* **Issuer key.** `IssuerX509` validates the `x5c` chain (anchors, CRL revocation, optional EKU and `RequireIssuerDNSBinding`). `ResolveIssuerKeys` or `ResolveIssuerKeysFromClaims` supply candidate keys for credentials without usable `x5c`; they are not consulted for an `x5c` credential when `IssuerX509` is set, unless `ResolveIssuerKeysWhenX5CUntrusted` applies to a chain that reaches no anchor.
* **Holder binding.** A `cnf.jwk` must match the holder key the credential was requested with; `RequireHolderBinding` also refuses a credential without `cnf`.
* **Validity.** The signature, `exp` / `nbf` (with `ClockSkew`), SD-JWT disclosure integrity and `_sd_alg`, and `ExpectedSDJWTVCType` when set.
* **`ldp_vc`.** The `eddsa-rdfc-2022` Data Integrity proof is verified with a key from `ResolveIssuerKeys` (called with the proof's `verificationMethod` as `kid` and `EdDSA` as `alg`) over the JSON-LD contexts pinned in `Policy.DataIntegrityContexts`. The `verificationMethod` must belong to the credential's `issuer`, the validity period is `validFrom` / `validUntil`, and an issuance binds the holder through a `did:key` or `did:jwk` `credentialSubject.id`. `IssuerX509` does not apply; `UnverifiedIssuer` does.

`acceptance.Verification` (also `SavedCredential.Verification`) records the issuer key, the certificate fingerprints, revocation counters and the holder-binding outcome. Failures wrap the sentinels of package `acceptance` (`ErrIssuerKeyUnresolved`, `ErrIssuerSignatureInvalid`, `ErrHolderBindingMismatch`, …); an untrusted or revoked chain arrives as `*x509.SigningChainError` or `*x509.CRLCheckError` of package `common/x509`.

### Fail-closed defaults

* A `nil` policy on an OpenID4VCI 1.0 method, a `Draft13()` method or `VerifyCredentialForAcceptance` stores nothing (`ErrCredentialAcceptancePolicyRequired`). `ReceiveCredential` without a policy only parses the credential.
* `UnverifiedIssuer: true` accepts a credential without authenticating its issuer. It applies only when neither `IssuerX509` nor a resolver is set, and the other checks still run.
* Under HAIP an SD-JWT VC requires `IssuerX509` (HAIP §6.1.1): it must carry `x5c` (`ErrHAIPX5CRequired`) without the trust anchor (`ErrHAIPTrustAnchorInX5C`), and `UnverifiedIssuer` does not apply to it.
* `AllowUnadvertisedRevocation` keeps certificates without a CRL distribution point on the trust path and reports them separately. OCSP is not consulted.

## OpenID4VP 1.0 presentation {#openid4vp-10-presentation}

### Admitted requests

A presentation request is parsed and admitted once, then answered through the handle the parse returned. `*oid4vp.AdmittedRequest` records which presenter admitted the request and where the response goes; the endpoint is never taken from the caller, and a handle is answered only by the presenter that admitted it (`oid4vp.ErrRequestNotAdmittedHere`).

| Method | Purpose |
| --- | --- |
| `ParsePresentationRequest(ctx, uri)` | Parse and admit an Authorization Request URI, dereferencing `request_uri`. |
| `ParsePresentationRequestObject(ctx, requestObject, src)` | Authenticate a Request Object the caller already holds. |
| `ParseDCAPIRequest(ctx, invocation)` | Admit a Digital Credentials API request. |
| `SelectCredentials(ctx, h)` | The library's own choice of stored credentials. |
| `SubmitPresentation(ctx, h, Presentation)` | Check, serialize and send the response. |
| `DeclinePresentation(ctx, h, code, description)` | Send an OpenID4VP error response (§8.5). |

`h.Request()` returns a copy of the parsed request for a consent screen, `h.ResponseEndpoint()` the endpoint (nil for the DC API), and `h.RequestObject()` the Request Object the request was authenticated from.

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

func presentWithConsent(ctx context.Context, w *wallet.Wallet, uri string, holderKey wallet.IKeyEntry,
	consent func(oid4vp.CredentialPresentationRequest, []wallet.CredentialSelection) bool) (*presenterTypes.SubmitResult, error) {
	request, err := w.ParsePresentationRequest(ctx, uri)
	if err != nil {
		return nil, err
	}
	selections, err := w.SelectCredentials(ctx, request)
	if err != nil {
		return nil, err
	}
	if !consent(request.Request(), selections) {
		return w.DeclinePresentation(ctx, request, string(oid4vp.AccessDeniedError), "the holder declined")
	}
	return w.SubmitPresentation(ctx, request, wallet.Presentation{
		Key:         holderKey,
		Credentials: selections,
	})
}
```

`Presentation` holds the default holder `Key`, the `Credentials` and optional `SerializeOptions`. Each `CredentialSelection` names a stored credential by `CredentialID` or carries it by value in `Credential` (required on a storeless wallet), lists the DCQL `QueryIDs` it answers, and may set `DisclosedClaims` (the disclosure names the holder kept; nil keeps every claim the request asks for) and its own `Key`. `SubmitPresentation` sends nothing when the selection does not answer the request. `SubmitResult` carries the verifier's `RedirectURI`, the `DCAPIResponse` for a DC API request, and `Encrypted`.

### Parsing now and presenting later

The handle is not serializable. A wallet that shows a consent screen in one request and presents in another keeps the Request Object and parses it again; the second parse authenticates the Request Object again, including its `exp`.

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

// requestSource records how the admitted Request Object reached the wallet.
func requestSource(request *oid4vp.AdmittedRequest) presenterTypes.RequestObjectSource {
	parsed := request.Request()
	source := presenterTypes.RequestObjectSource{ClientID: parsed.ClientID}
	if verification := parsed.RequestObjectVerification; verification != nil {
		source.DeliveredByReference = verification.Delivery == "reference"
		source.WalletNonce = verification.WalletNonce
	}
	return source
}

// presentLater answers a request admitted earlier from its kept Request Object.
func presentLater(ctx context.Context, w *wallet.Wallet, requestObject string, source presenterTypes.RequestObjectSource,
	p wallet.Presentation) (*presenterTypes.SubmitResult, error) {
	request, err := w.ParsePresentationRequestObject(ctx, requestObject, source)
	if err != nil {
		return nil, err
	}
	return w.SubmitPresentation(ctx, request, p)
}
```

A request in plain parameters has no Request Object (`RequestObject()` is empty); parse its URI again instead. `RequestObjectSource.DeliveredByReference` states that the Request Object was fetched from `request_uri`, which satisfies the HAIP §5.1 delivery rule for a Request Object passed by value; set it only when the wallet's own earlier parse recorded the fetch.

### Verifier authentication {#verifier-authentication}

`oid4vp.Oid4vpPresenter` authenticates the verifier from the Client Identifier Prefix:

| Prefix | Authentication |
| --- | --- |
| `x509_san_dns`, `x509_hash` | Signed Request Object required. The `x5c` chain must reach `RequestObjectValidation.TrustAnchors` / `RootCAs` (or `X509TrustChainRoots`), with CRL revocation checks. `x509_san_dns` binds a DNS SAN and the response endpoint; `x509_hash` binds the leaf certificate hash. HAIP requires `x509_hash`. |
| `redirect_uri` | Unsigned only; binds the response endpoint to the identifier. It authenticates nobody. |
| none (pre-registered) | The client must be in `PreRegisteredClients` or found by `ResolvePreRegisteredClient` (`oid4vp.ErrPreRegisteredClientUnknown`). Its `Metadata` replaces the request's metadata, and its `Metadata.RedirectURIs` are the only response endpoints accepted; a registration without them accepts no request. A signed Request Object is verified with the registered `JWKS`; `RequireSignedRequestObject` refuses an unsigned one. |
| `verifier_attestation` | Signed Request Object required; the Verifier Attestation JWT must be issued by one of `RequestObjectValidation.VerifierAttestationIssuers`, and the Request Object signed with its `cnf` key. |
| `openid_federation` | A Trust Chain to `RequestObjectValidation.Federation.TrustAnchors`; the Request Object is verified with the chain's keys. Unsigned requests are refused unless `FederationTrustOptions.AllowUnsignedRequests` is set. |
| `decentralized_identifier` | Refused. |
| `origin`, `web-origin` | Refused (`ErrClientIDPrefixReserved`). |

A prefix that requires a signature is refused in plain parameters with `ErrRequestObjectSignatureRequired`. `RequestObjectVerification` on the parsed request records what was authenticated (certificate fingerprints and a `Certificate` summary, revocation counters, the echoed `WalletNonce`, `Delivery`, `ExpiresAt`, and the `VerifierAttestation` or `Federation` evidence); no request parameter can populate it.

`RequestObjectValidationOptions` holds the relying-party policy: `TrustAnchors` or `RootCAs`, `CRL`, `AllowUnadvertisedRevocation`, `CertificateKeyUsages`, `WalletAudience`, `SigningAlgorithms` (default ES256 and RS256), `RequireExpiry`, `MaxAge` (HAIP uses 10 minutes when it is zero), `Now` and `ClockSkew`. A Request Object whose `iat` lies in the future is refused, so set `ClockSkew` to the clock difference the verifiers you accept may have. `X509TrustChainRoots` alone accepts certificates that publish no revocation information; it cannot be combined with anchors in `RequestObjectValidation`.

`InsecureSkipX509Verify` applies to the Draft 24 entry points only. With it set, the OpenID4VP 1.0 path refuses every signed Request Object, and HAIP refuses the presenter.

### DCQL

`SelectCredentials` evaluates `credential_sets` (`options`, `required`), `claims`, `claim_sets`, `values`, nested and array claim paths (OpenID4VP 1.0 §7), `multiple`, `meta` (`vct_values`, `type_values`) and `trusted_authorities` of type `aki` and `openid_federation`. An `openid_federation` value matches a credential when a Trust Chain from its issuer to a Trust Anchor of `RequestObjectValidation.Federation`, resolved under that configuration, includes the value (OpenID4VP 1.0 §6.1.1.3); without configured Trust Anchors it matches nothing. A caller that builds `oid4vp.DCQLCredentialCandidate` values itself sets `Issuer` and calls `AdmittedRequest.ResolveFederationTrustedAuthorities` before matching. It picks, for every required credential query, the credentials that satisfy it with the first claim set they satisfy; a request the store cannot answer is an `*oid4vp.AuthorizationRequestError` with code `access_denied`. Credentials without holder binding are excluded from a query that requires it. A `jwt_vc_json` or `ldp_vc` claim path starts at the credential (`["credentialSubject","given_name"]`).

A wallet whose holder chooses among candidates uses `oid4vp.ResolveDCQLClaimSets` and `oid4vp.ValidateDCQLMatches`; `SubmitPresentation` applies the same validation to the selection it is given (`oid4vp.ErrDCQLSelectionUnsatisfied`).

### `transaction_data`

`Config.SupportedTransactionDataTypes` (or `Oid4vpPresenter.SupportedTransactionDataTypes` on an injected presenter) lists the `transaction_data` types the wallet processes; with an empty list every request carrying `transaction_data` is refused with `invalid_transaction_data`. Each entry must reference credential queries of the request. Only a `dc+sd-jwt` presentation with a Key Binding JWT carries transaction data: a referenced `dc+sd-jwt` query must require holder binding, and an entry assigned to another format fails before anything is sent. Each entry is bound to one presented credential (§5.1), and the hash algorithm comes from the entries' `transaction_data_hashes_alg` (`sha-256` by default). A Draft 24 request follows the same rules: `credential_ids` name input descriptors (or Draft 24 credential queries), and each must accept an SD-JWT VC (`vc+sd-jwt`).

### Response modes and encryption

A request URI or Request Object uses `direct_post` or `direct_post.jwt`; a DC API request uses `dc_api` or `dc_api.jwt`, and each path refuses the other's modes. HAIP requires `direct_post.jwt` and, for the DC API, `dc_api.jwt`. `direct_post.jwt` and `dc_api.jwt` require encryption keys in `client_metadata.jwks` (`ErrResponseEncryptionKeyMissing`); the response is an ECDH-ES JWE with A128GCM or A256GCM, preferring A256GCM, and under HAIP the verifier must list both (`ErrResponseEncryptionEncMissing`). These checks run at parse time, before consent.

The response POST and the `request_uri` fetch do not follow redirects. A non-2xx response is an `*oid4vp.VerifierResponseError`.

### Error responses

`DeclinePresentation` answers an admitted request with an error response, encrypted under `direct_post.jwt` when the verifier metadata allows it (§8.3.1). A request that fails admission is not answered by default, because its endpoint was chosen by an unauthenticated request. `AuthorizationRequestError.SendErrorResponse(ctx, client)` sends the error response for a refused unsigned `redirect_uri` request whose `ResponseURI()` is set; `Oid4vpPresenter.SendParseErrorResponses` makes the presenter do so at parse time.

### Digital Credentials API

`ParseDCAPIRequest` admits a W3C Digital Credentials API invocation: `openid4vp-v1-unsigned`, `openid4vp-v1-signed` or `openid4vp-v1-multisigned`. The caller supplies the platform-authenticated origin, which is never read from the request. `SubmitPresentation` makes no HTTP call and returns the object to hand back to the platform: `{"vp_token": {...}}` for `dc_api`, or `{"response": <JWE>}` for `dc_api.jwt`. The Key Binding JWT `aud` is `origin:<origin>` (OpenID4VP 1.0 Appendix A.4).

```go
import (
	"context"
	"encoding/json"

	"github.com/trustknots/vcknots/wallet"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

func answerDCAPI(ctx context.Context, w *wallet.Wallet, protocol string, data json.RawMessage, origin string,
	holderKey wallet.IKeyEntry) (*presenterTypes.DCAPIResponse, error) {
	request, err := w.ParseDCAPIRequest(ctx, presenterTypes.DCAPIInvocation{
		Request: presenterTypes.DCAPIRequest{Protocol: protocol, Data: data},
		Origin:  origin, // authenticated by the platform
	})
	if err != nil {
		return nil, err
	}
	selections, err := w.SelectCredentials(ctx, request)
	if err != nil {
		return nil, err
	}
	result, err := w.SubmitPresentation(ctx, request, wallet.Presentation{Key: holderKey, Credentials: selections})
	if err != nil {
		return nil, err
	}
	return result.DCAPIResponse, nil
}
```

### Draft 24

`w.Draft24().ParsePresentationRequest` and `ParsePresentationRequestObject` admit OpenID4VP Draft 24 requests carrying a Presentation Exchange `presentation_definition`. The handle is answered with `SubmitPresentation` (a `vp_token` and `presentation_submission`) and `DeclinePresentation`. `SelectCredentials` picks the newest credential for every input descriptor, and `QueryIDs` name input descriptor ids. On an SD-JWT VC, key binding is always required and a non-nil `DisclosedClaims` limits disclosure. The Draft 24 path refuses pre-registered clients, and `Config.TestHooks.PresentationExchangeResponse` rewrites the response for testing.

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

func presentDraft24(ctx context.Context, w *wallet.Wallet, uri string, holderKey wallet.IKeyEntry) (*presenterTypes.SubmitResult, error) {
	request, err := w.Draft24().ParsePresentationRequest(ctx, uri)
	if err != nil {
		return nil, err
	}
	selections, err := w.SelectCredentials(ctx, request)
	if err != nil {
		return nil, err
	}
	return w.SubmitPresentation(ctx, request, wallet.Presentation{Key: holderKey, Credentials: selections})
}
```

## Keys and signing {#keys-and-signing}

Every key is an `IKeyEntry`; the library never needs the private key. Sub-packages that cannot import `wallet` use `keystore.KeyEntry`, which has the same method set. A key held in a hardware module or a remote signer may also implement `keystore.ContextSigner`; the library then calls `SignContext` with the context of the operation, so canceling the operation also cancels a pending signature.

```go
import (
	"context"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/keystore"
)

// remoteKey signs in a remote signing service.
type remoteKey struct {
	id     string
	public jose.JSONWebKey
	sign   func(ctx context.Context, data []byte) ([]byte, error)
}

func (k *remoteKey) ID() string                 { return k.id }
func (k *remoteKey) PublicKey() jose.JSONWebKey { return k.public }
func (k *remoteKey) Sign(data []byte) ([]byte, error) {
	return k.sign(context.Background(), data)
}
func (k *remoteKey) SignContext(ctx context.Context, data []byte) ([]byte, error) {
	return k.sign(ctx, data)
}

var (
	_ wallet.IKeyEntry       = (*remoteKey)(nil)
	_ keystore.ContextSigner = (*remoteKey)(nil)
)
```

The key proof algorithm must be one the issuer lists in `proof_signing_alg_values_supported` (`ErrProofAlgorithmNotSupported`).

## Profile rules {#profile-rules}

`NewWalletWithConfig` checks the configuration against `Config.Profile`:

* An unknown profile is refused (`profile.ErrUnknownProfile`).
* A receiver or presenter plugin that implements `profile.Carrier` must report the wallet's profile (`ErrProfileMismatch`). Under HAIP a plugin that does not implement `profile.Carrier` is refused (`ErrProfilePluginUnsupported`); under Final it is accepted.
* Under HAIP, `TestHooks` is refused and every `Draft13()` / `Draft24()` method and `ReceiveCredential` returns `ErrProfileForbidsDraft`.
* `Storeless` together with `CredStore`, `SupportedTransactionDataTypes` together with `Presenter`, and a `Presenter` plugin other than `*oid4vp.Oid4vpPresenter` are refused (`ErrInvalidArgument`).

`SetReceiver` applies the same plugin checks. Plugin fields must not change after the plugin is registered. HAIP further requires, among others: PAR, DPoP-bound access tokens, a client authentication mechanism, `scope` on every Credential Configuration, a Nonce Endpoint when a key attestation is needed, `x509_hash`, signed requests delivered by `request_uri`, the encrypted response modes, SD-JWT VC issuer `x5c`, and a Key Binding JWT for every SD-JWT VC that carries `cnf`. `AllowHTTP` and `InsecureSkipX509Verify` are refused.

## Error codes {#error-codes}

Every error the library returns names its condition with a stable, machine-readable code:

```go
// CodedError is an error with a stable code.
type CodedError interface {
	error
	ErrorCode() string
}
```

`wallet.ErrorCode(err)` returns the code of the outermost `CodedError` in the chain and whether one was found; `wallet.ErrorCodes(err)` returns every code, most specific first. `("", false)` means the error did not come from this library. Every non-nil error returned by a method of package `wallet` has a code. An error without a more specific code is `invalid_argument` (`ErrInvalidArgument`, input refused before any I/O), `canceled`, `deadline_exceeded` (these also match `context.Canceled` / `context.DeadlineExceeded`), `network_error` or `unclassified` (a missing code in the library). A plugin method called directly may return an uncoded error from a dependency. The presenter's parse methods give a refusal without a more specific code `oid4vp_request_invalid` (`oid4vp.ErrAuthorizationRequestInvalid`).

```go
import (
	"errors"

	"github.com/trustknots/vcknots/wallet"
)

func describe(err error) string {
	if errors.Is(err, wallet.ErrCredentialAcceptancePolicyRequired) {
		return "configure Config.CredentialAcceptance"
	}
	if code, ok := wallet.ErrorCode(err); ok {
		return code
	}
	return "not a wallet error"
}
```

Codes are lower_snake_case, unique across the module and never reused; removing one is a breaking change. `ErrorCode` differs from a protocol `Code` field: the field is what the peer sent, `ErrorCode` is what the library concluded. The typed errors derive their code from the condition:

| Error | Code |
| --- | --- |
| `*wallet.AuthorizationResponseError` | `authorization_error_response` |
| `*wallet.KeyAttestationRequiredError` | `key_attestation_required`, or `key_attestation_nonce_rejected` when `NonceRejected` |
| `*oid4vci.EndpointError` | `issuer_metadata_fetch_failed`, `authorization_server_metadata_fetch_failed`, `pushed_authorization_request_failed`, `token_endpoint_rejected`, `nonce_request_failed` (by `Stage`) |
| `*receiverTypes.CredentialEndpointError` | `credential_nonce_rejected` for `invalid_nonce`, otherwise `credential_endpoint_rejected` |
| `*receiverTypes.Draft13CredentialEndpointError` | `draft13_credential_invalid_proof`, `draft13_credential_issuance_pending`, otherwise `draft13_credential_endpoint_failed` |
| `*oid4vp.AuthorizationRequestError` | `oid4vp_request_rejected` |
| `*oid4vp.VerifierResponseError` | `verifier_response_rejected` |
| `*x509.SigningChainError` | the revocation code when it wraps one, otherwise `x509_chain_untrusted` |
| `*x509.CRLCheckError` | `x509_chain_revoked`, `crl_budget_exhausted`, otherwise `x509_chain_revocation_unknown` |

The sentinel errors (`Err…` variables of `wallet`, `acceptance`, `attestation`, `profile`, `receiver/plugins/oid4vci`, `presenter/plugins/oid4vp` and the other packages) carry their own codes, and `errors.Is` holds for them. The component packages (`keystore`, `credstore`, `serializer`, `verifier`, `presenter`, `idprof`, `clientconfig`) prefix their codes with the component name.

## Observing HTTP exchanges

Package `common/observe` reports the outbound HTTP exchanges of the library, each labeled with its protocol role (`Endpoint`: `issuer_metadata`, `token`, `credential`, `request_object`, `response_endpoint`, …). Wrap the transport of the `*http.Client` you give the plugins:

```go
import (
	"net/http"

	"github.com/trustknots/vcknots/wallet/common/observe"
)

func observedClient(record func(endpoint observe.Endpoint, method, url string, status int, err error)) *http.Client {
	return &http.Client{Transport: observe.Transport(nil, observe.ObserverFunc(func(e observe.Exchange) {
		status := 0
		if e.Response != nil {
			status = e.Response.StatusCode
		}
		record(e.Endpoint, e.Request.Method, e.Request.URL.Redacted(), status, e.Err)
	}))}
}
```

The observer is called after the response headers arrive; it must not read or close a body or block. A request the library did not label (a CRL download, a request of your own) is `EndpointOther`. `observe.WithEndpoint` labels a request you send through the same client.

## Environment variables

The variables are defined in `wallet/env/env.go`.

| Variable | Default | Description |
| :---- | :---- | :---- |
| `VCKNOTS_WALLET_HTTP_ALLOWED` | `false` (unset/empty) | When `true`, the default dispatchers and plugins allow HTTP endpoints (local development only). It is read when they are built. A client assertion is sent over plain HTTP only to a loopback host. HAIP refuses HTTP. |
| `VCKNOTS_WALLET_DEBUG` | `false` (unset/empty) | Enables debug logging only. It does not relax HTTPS. |

`env.IsHTTPAllowed()` is `true` only when `VCKNOTS_WALLET_HTTP_ALLOWED=true`. `env.SetHTTPAllowed(true)` and `env.SetDebugMode(true)` set them from test code.

## Changes from the previous wallet API

This section lists the changes since upstream commit `f0c7c53` to identifiers that existed there, and the behavior changes of their methods. Identifiers added since then are described in the sections above. Every exported signature of `f0c7c53` is unchanged.

**Package `wallet`**

* `Config` is no longer comparable with `==`.
* `Config` has new fields: `Profile`, `Storeless`, `CredentialAcceptance`, `SupportedTransactionDataTypes`, `Issuance`, `Attestation`, `TestHooks`. `CredentialOfferGrant` has `IssuerState` and `AuthorizationServer`; `SavedCredential` has `Verification`.
* `NewWalletWithConfig` refuses an unknown `Profile`, a plugin whose profile differs from the wallet's, and under HAIP a plugin that does not implement `profile.Carrier` and any `TestHooks`. It refuses `Storeless` with a `CredStore`, `SupportedTransactionDataTypes` with an injected `Presenter`, and a presenter plugin other than `*oid4vp.Oid4vpPresenter`. Its errors carry codes.
* `SetReceiver` is deprecated. It checks the dispatcher's plugins as `NewWalletWithConfig` does; a refused dispatcher is not installed, and every method that needs the receiver returns the refusal.
* `VerifyCredential` returns true only when the proof verifies, and only for `acceptance.DefaultSigningAlgorithms()` (ES256); a nil credential returns false.
* `ReceiveCredential` returns `ErrProfileForbidsDraft` under HAIP. The credential is checked before it is stored: under `Config.CredentialAcceptance` when set, otherwise by parsing it (`typ`, `alg`, and a `cnf` that must match `Key`). A credential that fails is not stored. A storeless wallet returns `ErrNoCredentialStore` after the check.
* `PresentCredential` and `PresentCredentialWithOptions` run `ParsePresentationRequest`, `SelectCredentials` and `SubmitPresentation`. Stored credentials are chosen by the DCQL query instead of taking the newest one, each answered query gets its own presentation, and a Key Binding JWT is attached as the query requires. The request is admitted under the rules of [Verifier authentication](#verifier-authentication).
* `GetCredentialEntries` and `GetCredentialEntry` return `ErrNoCredentialStore` on a storeless wallet.
* Every error returned by a method of `Wallet` carries a code (`wallet.ErrorCode`).

**Plugins and sub-packages**

* `oid4vp.Oid4vpPresenter` is no longer comparable with `==`. `oid4vci.Oid4vciReceiver` and `oid4vp.Oid4vpPresenter` have new fields (`HTTPClient`, `AllowHTTP`, `Profile` and others) and new methods. Their zero values require HTTPS whatever `VCKNOTS_WALLET_HTTP_ALLOWED` says; `receiver.WithDefaultConfig`, `presenter.WithDefaultConfig` and `NewWallet` read the variable when they build the plugins.
* The receiver plugin refuses every HTTP redirect (`ErrHTTPRedirectNotAllowed`), bounds response bodies, and refuses Credential Issuer Metadata whose `credential_issuer` is not the requested identifier and authorization server metadata whose `issuer` is not the requested one.
* `Oid4vpPresenter.ParsePresentationRequest` authenticates the verifier as described in [Verifier authentication](#verifier-authentication): signed Request Objects are verified by the prefix's own mechanism and never with keys from `client_metadata`, `x509_*` prefixes require a signed Request Object, a colon-less `client_id` is a pre-registered client that must be registered, and a future `iat` is refused. `InsecureSkipX509Verify` makes the OpenID4VP 1.0 path refuse signed Request Objects; it applies to the Draft 24 entry points. `X509TrustChainRoots` keeps accepting certificates without revocation information.
* The presenter no longer posts an error response when parsing fails; `SendParseErrorResponses` or `AuthorizationRequestError.SendErrorResponse` does it on request. The `request_uri` fetch and the response POST (`Present`) do not follow redirects, and a non-2xx response to `Present` is an `*oid4vp.VerifierResponseError`.
* `NewRequestBuilder` builds OpenID4VP 1.0 requests under `profile.Final`.
* `receiver.ReceivingDispatcher` and `presenter.PresentationDispatcher` have new methods (`Plugins`, the transport and parse accessors). `sdjwtvc.SdJwtVcPresentationOptions` has `LimitDisclosureToSelectedClaims` and `RequireRootClaimMatch`. `presenterTypes.PresentationRequest` has `ResponseMode`. The metadata types in `receiver/types` have new fields.
* `env.IsHTTPAllowed` no longer returns true because of `VCKNOTS_WALLET_DEBUG`.
* The sentinel errors of the component packages (`keystore`, `credstore`, `presenter/types`, `common` and others) carry codes; `errors.Is` still matches them.

## 7. Notes

1. **Mock key entries must not be used in production (CRITICAL):**
    - The in-memory key shown in this tutorial (and `MockKeyEntry` in `wallet/examples/common/`) keeps the private key in plaintext on the Go heap. Use it for tests and demonstrations only.
    - In production, implement `IKeyEntry` so that `Sign` is delegated to an OS keystore (iOS Secure Enclave, Android Keystore) or an HSM and the private key is never loaded into the application's memory.

2. **GOPRIVATE configuration:**
    - If `go mod download` or `go build` fails, the most likely cause is a missing GOPRIVATE environment variable.

3. **Persistent storage (bbolt):**
    - `credstore.WithDefaultConfig()` persists credentials to `<user config dir>/vcknots/wallet/.local_credstore.db`. The process must be able to create and write this directory.

4. **HTTPS enforcement:**
    - The wallet requires HTTPS for issuer and verifier endpoints by default. `VCKNOTS_WALLET_HTTP_ALLOWED=true` or a plugin's `AllowHTTP` relaxes it for local development only.

5. **Strict validation of OpenID4VP `client_id`:**
    - The wallet validates `client_id` strictly. Duplicate prefixes (for example `x509_san_dns:x509_san_dns:...`), malformed values and the wallet-only prefixes are rejected.
    - For `x509_san_dns`, the certificate is taken from the `x5c` header of the Request Object and one of its DNS Subject Alternative Names must equal the `client_id` value.

6. **`InsecureSkipX509Verify`:**
    - It skips certificate chain validation on the Draft 24 entry points, where only the binding and the signature are checked. The OpenID4VP 1.0 path refuses signed Request Objects while it is set, and HAIP refuses it.
    - ⚠️ Use it only for conformance testing or local development.

## 8. Troubleshooting

* **Q: `go mod download` fails with `package ... is private` or `404 Not Found`.**
  * **A:** The GOPRIVATE environment variable is not configured. See "1. Prerequisites" (or use mise).

* **Q: Receiving or presenting fails with `connection refused` or `timeout`.**
  * **A:** The Issuer/Verifier server is not running. Start it with `pnpm -F @trustknots/server start` and confirm that http://localhost:8080 responds.

* **Q: Receiving fails with `credential issuer must use https scheme`.**
  * **A:** The wallet requires HTTPS by default. For the local HTTP sample server, set `VCKNOTS_WALLET_HTTP_ALLOWED=true` before the wallet is built, or set `AllowHTTP` on the plugins you construct.

* **Q: Receiving fails with `issuer_metadata_fetch_failed`.**
  * **A:** Run `curl http://localhost:8080/.well-known/openid-credential-issuer` and confirm that JSON metadata is returned, and that its `credential_issuer` equals the identifier in the offer.

* **Q: An OpenID4VCI 1.0 method fails with `credential_acceptance_policy_required`.**
  * **A:** Set `Config.CredentialAcceptance`. For a test issuer whose key the wallet cannot authenticate, `&acceptance.Policy{UnverifiedIssuer: true}` says so explicitly.

* **Q: A `client_id` validation error occurs during OpenID4VP conformance testing.**
  * **A:** Conformance tests intentionally send malformed `client_id` values. Errors such as `duplicate prefix detected` or a SAN mismatch are expected.

* **Q: A signed Request Object from a conformance suite is rejected with an X.509 error.**
  * **A:** Configure the suite's root certificate as a trust anchor. Test certificates usually publish no CRL, so allow that explicitly:
    ```go
    import (
    	"crypto/x509"

    	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
    )

    func conformancePresenter(suiteRoot *x509.Certificate) *oid4vp.Oid4vpPresenter {
    	return &oid4vp.Oid4vpPresenter{
    		RequestObjectValidation: &oid4vp.RequestObjectValidationOptions{
    			TrustAnchors:                []*x509.Certificate{suiteRoot},
    			AllowUnadvertisedRevocation: true, // test certificates only
    		},
    	}
    }
    ```

For runnable samples, see [wallet/examples/README.md](https://github.com/trustknots/vcknots/blob/main/wallet/examples/README.md). The [public Wallet API driver](https://github.com/trustknots/vcknots/blob/main/wallet/examples/official_driver/README.md) composes a complete configuration.
