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

The wallet implements **OpenID4VCI 1.0** and **OpenID4VP 1.0**. `Config.Profiles` selects the protocol profiles it runs: one 1.0 profile, `profile.Final()` or `profile.HAIP()` (HAIP 1.0, a set of constraints on the 1.0 specifications), and the draft profiles `profile.Draft13()` (OpenID4VCI Draft 13, the `Draft13()` view) and `profile.Draft24()` (OpenID4VP Draft 24, the `Draft24()` view). The default is Final with both drafts. The methods of `Wallet` are the stages of the 1.0 protocols, which a caller runs in order; the drafts are reached only through the two views.

| Protocol / feature | Public API | Notes |
| --- | --- | --- |
| OpenID4VCI 1.0 Pre-Authorized Code Flow | `AuthorizePreAuthorizedIssuance` + `RequestCredential` | `tx_code` is required exactly when the offer declares one. |
| OpenID4VCI 1.0 Authorization Code Flow (PKCE, PAR, RFC 9207 `iss`) | `BeginIssuance` + `AuthorizeIssuance` + `RequestCredential` | The library does not open the browser, and returns an `https` authorization URL only. PKCE is always `S256`. PAR is used when the authorization server advertises it, and required under HAIP or when the server sets `require_pushed_authorization_requests`. Wallet-initiated issuance (no offer) and an offer without `grants` are supported. |
| Credential Offer by value or by reference | `ResolveCredentialOffer`, `ParseCredentialOfferURL` | `ParseCredentialOfferURL` performs no I/O. |
| Client authentication, DPoP | `Config.ClientAuth`, `Config.DPoP`, `Config.Attestation.Client` | `private_key_jwt` or OAuth 2.0 Attestation-Based Client Authentication (an ephemeral Client Instance Key per flow, server-provided Challenges). DPoP proofs are sent whenever `Config.DPoP.Key` is set. |
| Batch issuance | `CredentialRequest.HolderKeys` | One key proof per holder key, up to `batch_credential_issuance.batch_size`. |
| Key attestation (Appendix D) | `Config.Attestation.Key`, `CredentialRequest.KeyAttestation` | Attestations are authenticated before they are sent (`attestation.TrustPolicy`). |
| Credential Request / Response encryption | `Config.Issuance.CredentialEncryption` | The response key is ephemeral. |
| Deferred issuance | `RequestDeferredCredential` | One request per call; the library does not poll. |
| Notification | `NotifyIssuer` | The library never notifies on its own. |
| Signed Credential Issuer Metadata | `oid4vci.Oid4vciReceiver.IssuerMetadataSigning` | OpenID4VCI 1.0 §12.2.3 (`application/jwt`) and Draft 13 §11.2.3 (`signed_metadata`). |
| Credential acceptance before storage | `Config.CredentialAcceptance` or the `Acceptance` of `IssuanceRequest`, `PreAuthorizedIssuanceRequest` or `CredentialRequest` (`acceptance.Policy`), `VerifyCredentialForAcceptance` | Required before the token or PAR request, so no authorization is obtained for a credential the wallet would refuse. The issuer key is established by the mechanism its `iss` and `x5c` select (SD-JWT VC -19 §2.5). |
| OpenID4VP 1.0 over `direct_post` / `direct_post.jwt` | `ParsePresentationRequest`, `ParsePresentationRequestObject`, `SelectCredentials`, `SubmitPresentation`, `DeclinePresentation` | Requests are answered through an `*oid4vp.AdmittedRequest` handle. |
| Verifier authentication | `oid4vp.Oid4vpPresenter` (`RequestObjectValidation`, `PreRegisteredClients`) | `x509_san_dns`, `x509_hash`, `redirect_uri`, pre-registered clients, `verifier_attestation`, `openid_federation`. See [Verifier authentication](#verifier-authentication). |
| `request_uri` GET / POST with `wallet_nonce` | `ParsePresentationRequest`, `Draft24().ParsePresentationRequest` | The library fetches `request_uri` itself. A POST sends a fresh `wallet_nonce` unless `Oid4vpPresenter.OmitWalletNonce` is set (OID4VP 1.0 §5.10 makes it OPTIONAL for the Wallet), and, when `Oid4vpPresenter.WalletMetadata` is set, `wallet_metadata`. `RequestObjectValidationOptions.RequestURIPolicy` can tie the `request_uri` to the `client_id` before it is fetched (`oid4vp.RequestURISameHost` ties it to the host the Client Identifier names). |
| DCQL | `SelectCredentials`, `oid4vp.ResolveSatisfiableDCQLCredentials`, `oid4vp.ValidateDCQLMatches` | `credential_sets`, `claims`, `claim_sets`, `values`, nested and array claim paths, `multiple`, `trusted_authorities` of type `aki` and `openid_federation`. |
| `transaction_data` | `Config.SupportedTransactionDataTypes`, `CredentialSelection.TransactionData` | `dc+sd-jwt` presentations with key binding only; the Holder assigns each entry to a presented credential. |
| W3C Digital Credentials API (`dc_api`, `dc_api.jwt`; unsigned, signed, multi-signed) | `ParseDCAPIRequest` + `SubmitPresentation` | Protocol handling only; the caller supplies the platform-authenticated origin. |
| OpenID4VCI Draft 13 | `Draft13()` | Needs `profile.Draft13()` in `Config.Profiles`; never with HAIP. |
| OpenID4VP Draft 24 (Presentation Exchange) | `Draft24()` + `SubmitPresentation` | Needs `profile.Draft24()` in `Config.Profiles`; never with HAIP. |
| Formats | `credential.SDJwtVC`, `credential.JwtVc`, `credential.LdpVc` | Each OpenID4VCI version has its own Credential Format Identifier table (`oid4vci.CredentialFormatFlavor`): `dc+sd-jwt`, `jwt_vc_json`, `ldp_vc` for 1.0; `vc+sd-jwt`, `jwt_vc_json`, `ldp_vc` for Draft 13. SD-JWT VC issuer `typ` must be `dc+sd-jwt`; `vc+sd-jwt` is accepted only under `profile.Draft13()`. `ldp_vc` uses Data Integrity `eddsa-rdfc-2022` proofs. |

**Not implemented.** ISO mdoc (`mso_mdoc`): there is no mdoc / COSE / CBOR serializer, so no mdoc presentation can be built. The `decentralized_identifier` Client Identifier Prefix is parsed and refused. Of the DCQL `trusted_authorities` types `aki` and `openid_federation` are evaluated; an entry of another type (`etsi_tl`) matches no credential.

### Profiles (Final, HAIP and the drafts)

A profile is a protocol version and the options the wallet applies on top of it (package `profile`): `Profile.Version()` is `profile.VersionFinal` (OpenID4VCI 1.0 and OpenID4VP 1.0), `VersionDraft13` or `VersionDraft24`, and `Profile.Options()` the constraints. Profiles are comparable: two profiles apply the same rules exactly when they are `==`, however they were built.

* **Final** (`profile.Final()`) is OpenID4VCI 1.0 and OpenID4VP 1.0 without additional constraints. The zero `profile.Profile` is Final, everywhere a profile is read.
* **HAIP** (`profile.HAIP()`) is not a version: it is Final with `profile.HAIPOptions()`, every HAIP 1.0 requirement, each an `Options` field named after the HAIP section that states it. `profile.HAIP() == profile.Final().With(profile.HAIPOptions())`.
* `Profile.With(options)` adds options and chains: a flag on in either is on, and a set (`AllowedCredentialFormats`, `AllowedClientIDPrefixes`) keeps the members both allow, so `With` never weakens an option and `profile.Final().With(a).With(b)` applies `a` and `b`. Options that together admit no input - two sets with no member in common, or `RequireSignedRequestByReference` with Client Identifier Prefixes that cannot sign a redirect-based request - are refused with a `*profile.ConflictError` (`profile.ErrOptionsConflict`) naming them.
* `Options.ForbidDraftProfiles` (HAIP 1.0 §1: the base protocols are OpenID4VCI 1.0 and OpenID4VP 1.0) refuses a draft profile beside the 1.0 profile, and `Options.ForbidExperimental` every setting of package `experimental`. Both are part of `HAIPOptions()` and, like every option, can be applied alone.
* **Draft 13** (`profile.Draft13()`) and **Draft 24** (`profile.Draft24()`) enable the draft views. They take no options (`profile.ErrDraftProfile`).
* A profile has a text form that keeps its options: `String()`, `MarshalText` / `UnmarshalText` (so `encoding/json` writes `"haip"`, not `{}`) and `profile.ParseProfile`. It is a version name or `haip`, followed by the options beyond it, each named as its `Options` field is (a nested rule as `IssuerX5C.Require`, a set as `AllowedCredentialFormats=dc+sd-jwt,mso_mdoc`), joined with `;`: `final`, `haip`, `draft13`, `draft24`, `final;RequirePAR;RequireDPoP`, `haip;AllowedCredentialFormats=mso_mdoc`. `ParseProfile(p.String()) == p`. `Options.String()` names the options that are on in the same spelling.
* An application that keeps its own per-option settings builds the profile from them with `With`, one `Options` field per setting (`profile.Final().With(profile.Options{RequirePAR: par, RequireDPoP: dpop})`), or passes the text form across a process boundary and parses it with `ParseProfile`.
* An error caused by an option carries a `*profile.OptionError` naming it (`errors.As(err, &optionErr)`; `optionErr.Option` is, for example, `"RequireDPoP"`), next to the error that classifies the refusal, whose code is unchanged. The message names the option, never "HAIP", since an option applies alone as well.
* Build the receiver and presenter plugins with the wallet's 1.0 profile (`oid4vci.Oid4vciReceiver.Profile`, `oid4vp.Oid4vpPresenter.Profile`). The plugins the wallet builds itself get it.
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

* **Allowing HTTP for local testing:** The wallet rejects non-HTTPS issuer and verifier endpoints, as OpenID4VCI 1.0 §12.2 and OpenID4VP 1.0 require. Because the local sample server runs on plain HTTP, allow HTTP explicitly in the code that builds the wallet for the test. Plain HTTP departs from the specifications, so it is reachable only through the [`experimental`](#experimental) package: `Config.Experimental.Transport` for the plugins the wallet builds, or the `Experimental` field of a plugin you construct (`Oid4vciReceiver.Experimental`, `Oid4vpPresenter.Experimental`, and `issuerkeys.Resolver.Experimental` for issuer key resolution). No environment variable relaxes it.

> ⚠️ **Security warning:** Do not allow HTTP in production. HAIP refuses it.

## 2. Initial Setup

This section explains how to install the library dependencies and initialize the `Wallet` instance.

### 2-1. Installing Dependencies

After setting GOPRIVATE, run the following command in the `wallet` directory to download the dependencies listed in `go.mod`:

```bash
go mod download
```

### 2-2. Initializing the Wallet

The top-level API is in the `github.com/trustknots/vcknots/wallet` package. `wallet.NewWallet()` initializes every dispatcher with its default plugin. It sets no `Config.CredentialAcceptance`, so each issuance must then bring its own acceptance policy (see [Credential acceptance](#credential-acceptance)); a wallet that receives credentials usually sets one with `NewWalletWithConfig`:

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
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/idprof"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// newWallet builds the wallet of the samples. allowHTTP accepts the plain
// http endpoints of the local sample server (not for production), and policy
// authenticates the issuer of every credential the wallet receives.
func newWallet(certPath string, allowHTTP bool, policy *acceptance.Policy) (*wallet.Wallet, error) {
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	receiverDisp, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{
		Experimental: experimental.Transport{AllowHTTP: allowHTTP},
	}))
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
		X509TrustChainRoots: certPool,
		// The local sample server speaks plain HTTP, which OpenID4VP does not
		// allow; opt in explicitly, and never in production.
		Experimental: experimental.Presenter{Transport: experimental.Transport{AllowHTTP: allowHTTP}},
	}
	presenterDisp, err := presenter.NewPresentationDispatcher(
		presenter.WithPlugin(presenter.Oid4vp, oid4vpPresenter),
	)
	if err != nil {
		return nil, err
	}

	return wallet.NewWalletWithConfig(wallet.Config{
		CredentialAcceptance: policy,
		CredStore:            credStore,
		IDProfiler:           idProf,
		Receiver:             receiverDisp,
		Serializer:           serializerDisp,
		Verifier:             verifierDisp,
		Presenter:            presenterDisp,
	})
}
```

* **Storage location:** The default credential store persists credentials with `go.etcd.io/bbolt` to `<user config dir>/vcknots/wallet/.local_credstore.db` (for example `~/.config/vcknots/wallet/.local_credstore.db` on Linux). `Config.Storeless` builds a wallet without a store: received credentials are returned and not stored, and presentations take credentials by value.

## 3. Sample Implementation of Wallet Features

This section shows the smallest receive and present samples, based on `wallet/examples/server_integration_sdjwt/server_integration_sdjwt.go` and `wallet/examples/common/common.go`. Both use the staged methods: the receive sample the OpenID4VCI 1.0 ones, and the present sample the OpenID4VP 1.0 ones. The rest of the staged API that a wallet with a user needs is described in [OpenID4VCI 1.0 issuance](#openid4vci-10-issuance) and [OpenID4VP 1.0 presentation](#openid4vp-10-presentation).

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

An OpenID4VCI 1.0 Pre-Authorized Code issuance takes three calls: parse the offer, exchange the pre-authorized code for an access token, and request the credential. In a real deployment the offer URI comes from a QR code or deep link; with the local sample server, create one with `POST /configurations/:configurationId/offer`.

```go
import (
	"context"
	"fmt"

	"github.com/trustknots/vcknots/wallet"
)

func receiveSDJwtCredential(ctx context.Context, w *wallet.Wallet, key wallet.IKeyEntry, offerURI, txCode string) (*wallet.SavedCredential, error) {
	// openid-credential-offer://?credential_offer=...
	offer, err := wallet.ParseCredentialOfferURL(offerURI)
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

	result, err := w.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{key}, // each key signs one key proof
	})
	if err != nil {
		return nil, err
	}
	if result.Deferred != nil {
		return nil, fmt.Errorf("the issuer deferred the credential")
	}
	return result.Credentials[0], nil
}
```

`AuthorizePreAuthorizedIssuance` fetches the issuer and authorization server metadata and obtains an access token with the pre-authorized code; `PreAuthorizedIssuanceRequest.CredentialConfigurationID` selects an offered configuration, and the first is used when it is empty. `RequestCredential` obtains a `c_nonce` from the issuer's Nonce Endpoint when it advertises one (§7), signs a key proof with each holder key, requests the credential, checks it and stores it. The check is `Config.CredentialAcceptance` (set in 2-2), unless the issuance brings its own policy: `PreAuthorizedIssuanceRequest.Acceptance`, which the grant carries to `RequestCredential`, or `CredentialRequest.Acceptance`, which overrides it. With no policy at all, `AuthorizePreAuthorizedIssuance` does not redeem the pre-authorized code and fails with `ErrCredentialAcceptancePolicyRequired`: no credential is requested or stored without an authenticated issuer (SD-JWT VC -19 §2.4). A deferred issuance, notifications and the Authorization Code Flow are described in [OpenID4VCI 1.0 issuance](#openid4vci-10-issuance).

An OpenID4VCI **Draft 13** issuer is served by the same calls on `w.Draft13()`; see [Draft 13](#draft-13).

### 3-3. Presenting a Credential (OpenID4VP)

After receiving a request URI of the form `openid4vp:?...` from the verifier (with the local sample server, via `POST /request` or `POST /request-object`), parse it, select the credentials that answer it, and submit them once the holder agrees:

```go
import (
	"context"
	"log"

	"github.com/trustknots/vcknots/wallet"
	sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func presentCredential(ctx context.Context, w *wallet.Wallet, key wallet.IKeyEntry, oid4vpURI string) error {
	request, err := w.ParsePresentationRequest(ctx, oid4vpURI)
	if err != nil {
		return err
	}
	selections, err := w.SelectCredentials(ctx, request)
	if err != nil {
		return err
	}
	// A wallet with a user shows selections (the credentials and the claims
	// they disclose) and submits only after the holder consents; it declines
	// with DeclinePresentation otherwise.
	submitted, err := w.SubmitPresentation(ctx, request, wallet.Presentation{
		Key:         key,
		Credentials: selections,
		// Limits SD-JWT VC disclosure to these claims.
		SerializeOptions: &sdjwtvc.SdJwtVcPresentationOptions{
			SelectedClaims: []string{"given_name", "family_name"},
		},
	})
	if err != nil {
		return err
	}
	if submitted.RedirectURI != "" {
		log.Printf("Verifier requested redirect: %s\n", submitted.RedirectURI)
	}
	return nil
}
```

`ParsePresentationRequest` admits the request under the presenter's trust policy (see [Verifier authentication](#verifier-authentication)) and returns an `*oid4vp.AdmittedRequest` handle. `SelectCredentials` chooses stored credentials that satisfy the DCQL query and names the claims each one discloses. `SubmitPresentation` signs one presentation per credential with `key` and sends the response to the endpoint the request named. It never contacts the `redirect_uri` the verifier returns; the URI is in `SubmitResult.RedirectURI`, empty when there is none, and the caller decides whether to follow it. See [OpenID4VP 1.0 presentation](#openid4vp-10-presentation) for choosing other credentials and claims than the selection.

* **Presentation options:** `Presentation.SerializeOptions` is a format-specific options value, or `nil` for the serializer's default. The KB-JWT audience and nonce always come from the request. For SD-JWT VC, a non-empty `SelectedClaims` limits disclosure, and a request for a claim outside it fails. A Key Binding JWT is attached when the DCQL query requires holder binding (the default), when `RequireKeyBinding` is set, when `transaction_data` is presented, and under HAIP whenever the credential carries `cnf`.
* **Draft 24:** `ParsePresentationRequest` parses OpenID4VP 1.0 requests only. Parse a Presentation Exchange request with `Draft24().ParsePresentationRequest` and continue with `SelectCredentials` and `SubmitPresentation`.

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

`FetchCredentialIssuerMetadata` fetches the issuer's OpenID4VCI 1.0 `.well-known/openid-credential-issuer` document (§12.2.2), for example to show the holder what an offer contains before they accept it. The issuance methods always re-discover the metadata and take no cached copy.

```go
import (
	"context"
	"log"
	"net/url"

	"github.com/trustknots/vcknots/wallet"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func fetchIssuerMetadata(ctx context.Context, w *wallet.Wallet) (*receiverTypes.CredentialIssuerMetadata, error) {
	// The Credential Issuer Identifier; the well-known path is inserted internally.
	issuerURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		return nil, err
	}

	metadata, err := w.FetchCredentialIssuerMetadata(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	log.Printf("Fetched metadata for issuer: %s\n", metadata.CredentialIssuer)
	return metadata, nil
}
```

The receiver refuses metadata whose `credential_issuer` is not the requested identifier (OpenID4VCI 1.0 §12.2.4), and applies the wallet's 1.0 profile, including signed metadata (see [Signed issuer metadata](#signed-issuer-metadata)).

## 5. Explanation of Type Definitions

This section lists the main types of the `wallet` package. The field-level documentation is in the Go doc of [wallet/](https://github.com/trustknots/vcknots/tree/main/wallet).

### IKeyEntry {#IKeyEntry}

A signing key: `ID()`, `PublicKey()` and `Sign()`. It has the method set of `keystore.KeyEntry`, so values convert both ways. See [Keys and signing](#keys-and-signing).

### Config {#Config}

Input for `NewWalletWithConfig`. Every field is optional.

| Field | Meaning |
| --- | --- |
| `CredStore`, `IDProfiler`, `Receiver`, `Serializer`, `Verifier`, `Presenter` | The dispatchers. `nil` builds the default. The OpenID4VP plugin of an injected `Presenter` must be an `*oid4vp.Oid4vpPresenter`, because the presentation methods answer its `*oid4vp.AdmittedRequest` handles. |
| `Profiles` | The protocol profiles: one 1.0 profile (`profile.Final()`, `profile.HAIP()`, or one of them strengthened with `With`) and optionally `profile.Draft13()` and `profile.Draft24()`. Empty is `wallet.DefaultProfiles()`: Final with both drafts. |
| `Storeless` | No credential store. `CredStore` must then be `nil`; methods that need a store return `ErrNoCredentialStore`. |
| `CredentialAcceptance` | `*acceptance.Policy` applied before a received credential is returned or stored, unless the request brings its own (`IssuanceRequest.Acceptance`, `PreAuthorizedIssuanceRequest.Acceptance`, `CredentialRequest.Acceptance`, `CredentialAcceptanceRequest.Acceptance`). With neither, `BeginIssuance`, `AuthorizeIssuance`, `AuthorizePreAuthorizedIssuance`, `RequestCredential`, `RequestDeferredCredential`, their `Draft13()` counterparts and `VerifyCredentialForAcceptance` fail with `ErrCredentialAcceptancePolicyRequired` before anything is sent. |
| `SupportedTransactionDataTypes` | The `transaction_data` types of the presenter the wallet builds. Setting it together with `Presenter` is refused; set `Oid4vpPresenter.SupportedTransactionDataTypes` on an injected plugin. |
| `DPoP` | [DPoPConfig](#DPoPConfig). |
| `ClientAuth` | [ClientAuthConfig](#ClientAuthConfig). `ClientID` is the wallet's `client_id` for every OpenID4VCI version. |
| `Issuance` | `IssuanceConfig{RedirectURI, CredentialEncryption}`: the Authorization Code Flow `redirect_uri` and the holder's `CredentialEncryptionPolicy`. |
| `Attestation` | `AttestationConfig{Client, ClientKey, ClientKeyFromDPoP, Key, Trust}`: client and key attestation providers, the Client Instance Key the client attestation binds and the `attestation.TrustPolicy` that authenticates them. With `ClientKey` nil each flow gets an ephemeral Client Instance Key (see [Client authentication](#openid4vci-10-issuance)); `ClientKeyFromDPoP` opts in to attesting `DPoP.Key`. |
| `Experimental` | `experimental.Options{Transport, Hooks}`: settings that depart from the specifications, for testing only. `Transport.AllowHTTP` accepts plain HTTP in the plugins the wallet builds (refused under HAIP and with an injected `Receiver` or `Presenter`); `Hooks{KeyProof, PresentationExchangeResponse}` rewrite Draft 13 key proofs and Draft 24 responses after they were built (refused unless a draft profile is enabled, so never under HAIP). See [experimental](#experimental). |

### CredentialOffer {#CredentialOffer}

A Credential Offer: the issuer URL (`CredentialIssuer`), the configuration IDs (`CredentialConfigurationIDs`) and the grants (`Grants`). A `CredentialOfferGrant` carries `PreAuthorizedCode`, `TxCode`, `IssuerState` and the `AuthorizationServer` hint.

### SavedCredential {#SavedCredential}

A received or stored credential: `Credential` (parsed), `Entry` (storage entry: ID, raw bytes, MIME type, received time) and `Verification` (`*acceptance.Verification`, what was authenticated before storing; `nil` for credentials loaded from storage).

### GetCredentialEntriesRequest {#GetCredentialEntriesRequest}

Search conditions for `GetCredentialEntries`: `Offset`, `Limit` and `Filter`.

### SdJwtVcPresentationOptions {#SdJwtVcPresentationOptions}

Options for SD-JWT VC presentations (package `serializer/plugins/sdjwtvc`): `SelectedClaims`, `RequireKeyBinding`, `LimitDisclosureToSelectedClaims`, `RequireRootClaimMatch`, and the request-bound `Audience`, `Nonce`, `TransactionData` and `TransactionDataHashesAlg`, which the wallet fills from the request.

### DIDCreateOptions {#DIDCreateOptions}

Options for `GenerateDID`: the DID type (`TypeID`, for example `"did:key"`) and the public key (`PublicKey`).

### DPoPConfig {#DPoPConfig}

`Key` is the wallet's DPoP key. The OpenID4VCI 1.0 methods send a DPoP proof whenever it is set; HAIP requires it (`ErrDPoPKeyRequired`). `Enabled` generates an in-memory key when `Key` is `nil` and forces DPoP on the `Draft13()` token requests, which otherwise use DPoP only when the authorization server advertises it.

### ClientAuthConfig {#ClientAuthConfig}

Token endpoint client authentication: `Method` (`""` means none, or `receiverTypes.PrivateKeyJwt`), `ClientID`, `Key`, `AssertionAudience` and `SigningAlg` (ES256, ES384 or ES512). With `private_key_jwt` the authorization server must advertise both the method and the signing algorithm; otherwise the token request is not sent (`client_authentication_unavailable`).

## 6. Methods of Wallet

`*Wallet` has 23 methods:

| Area | Methods |
| --- | --- |
| Storage and identity | `GetCredentialEntries`, `GetCredentialEntry`, `GenerateDID` |
| Credential checks | `VerifyCredentialForAcceptance`, `StatusListChecker` |
| OpenID4VCI 1.0 | `ResolveCredentialOffer`, `FetchCredentialIssuerMetadata`, `BeginIssuance`, `AuthorizeIssuance`, `AuthorizePreAuthorizedIssuance`, `RequestCredential`, `RequestDeferredCredential`, `NotifyIssuer` |
| OpenID4VP 1.0 | `ParsePresentationRequest`, `ParsePresentationRequestObject`, `ReadmitPresentationRequest`, `AdmitPresentationRequestUnderVersion`, `ParseDCAPIRequest`, `SelectCredentials`, `SubmitPresentation`, `DeclinePresentation` |
| Draft views | `Draft13()` (`BeginIssuance`, `AuthorizeIssuance`, `AuthorizePreAuthorizedIssuance`, `RequestCredential`, `RequestDeferredCredential`, `NotifyIssuer`), `Draft24()` (`ParsePresentationRequest`, `ParsePresentationRequestObject`, `ReadmitPresentationRequest`) |

There is no method that runs a whole flow in one call: a wallet with a user needs the holder's consent between the stages, and a caller that has none runs the stages itself, as `wallet/examples/common.PresentAll` does for the samples. The methods that take a `context.Context` stop when it is canceled. Every error a method returns carries a code (see [Error codes](#error-codes)).

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

Fetches the OpenID4VCI 1.0 Credential Issuer Metadata of a Credential Issuer Identifier under the wallet's 1.0 profile (see section 4).

```go
func (w *Wallet) FetchCredentialIssuerMetadata(ctx context.Context, issuer *url.URL) (*receiverTypes.CredentialIssuerMetadata, error)
```

### GenerateDID

Generates a DID from a public key.

```go
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error)
```

### VerifyCredentialForAcceptance

Runs the check issuance runs before storing over a raw credential, under `req.Acceptance` or else `Config.CredentialAcceptance`, and stores nothing. It is the second step for a caller that receives on a storeless wallet and persists later, or that re-checks a credential it holds. `CredentialIssuer` is the Credential Issuer Identifier of the issuance (a DID issuer is bound to its origin), and `Version` selects the profile: the zero value `profile.VersionFinal` applies the wallet's 1.0 profile, and `profile.VersionDraft13` applies `profile.Draft13()`, which admits the SD-JWT VC `typ` `vc+sd-jwt`. `CredentialConfiguration`, when set, is the configuration the credential was issued under: if it lists `cryptographic_binding_methods_supported`, the credential must carry a `cnf.jwk` that `HolderKey` matches (OpenID4VCI 1.0 §12.2.4; HAIP 1.0 §6.1), as `RequestCredential` requires.

```go
type CredentialAcceptanceRequest struct {
	Raw              []byte
	Flavor           credential.SupportedSerializationFlavor
	HolderKey        *jose.JSONWebKey
	CredentialIssuer string
	Version          profile.Version
	Acceptance       *acceptance.Policy
	// CredentialConfiguration, when it lists cryptographic_binding_methods_supported,
	// requires a cnf.jwk that HolderKey matches.
	CredentialConfiguration *receiverTypes.CredentialConfiguration
}

func (w *Wallet) VerifyCredentialForAcceptance(ctx context.Context, req CredentialAcceptanceRequest) (*credential.Credential, *acceptance.Verification, error)
```

A bare signature check of a parsed credential, without the acceptance policy, is `Verify(proof, key)` on the `verifier.VerificationDispatcher`; it accepts every algorithm the dispatcher registers, so the caller applies its own algorithm policy.

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

The state types (`IssuanceAuthorization`, `IssuanceGrant`, `DeferredIssuance`, `IssuanceNotification`) are JSON-serializable, so a stage can run in another process. They hold identifiers and secrets only: each stage re-discovers the issuer and authorization server metadata, and checks that the state still fits the wallet (the same `ClientAuth.ClientID`, `Issuance.RedirectURI` and DPoP key, an authorization server the issuer still delegates to), refusing a mismatch with `ErrIssuanceStateMismatch`. Each state records the profile of the flow in `Profile` (JSON `"profile"`, the text form of `profile.Profile`). A state whose `Profile` has the other OpenID4VCI version (`Profile.Version()`) is refused with `ErrIssuanceVersionMismatch`, and a stage whose wallet runs another profile of the same version refuses it before sending anything (`ErrIssuanceProfileMismatch`), so a flow never continues under other options than it began with. A caller that runs the stages in different processes builds each stage's wallet with the state's `Profile`.

**The state JSON is a bearer secret.** It carries the PKCE `code_verifier`, the ephemeral Client Instance Key of the flow, the access token or the ephemeral response decryption key. Keep it server-side or encrypted, and out of logs.

**Metadata location.** A 1.0 issuance reads Credential Issuer Metadata only from the OpenID4VCI 1.0 §12.2.2 location (the well-known path inserted before the identifier's path), and a Draft 13 issuance only from the Draft 13 §11.2.2 location (the well-known path appended to the identifier). A 404 is reported; no other location and no OpenID Federation Entity is tried.

**Credential formats.** A Credential Configuration whose `format` is not in the table of the issuance's OpenID4VCI version is refused before the token request with `oid4vci.ErrCredentialFormatUnsupported`. The identifiers are compared exactly; the other version's SD-JWT VC identifier, pre-Draft 13 names such as `jwt_vc` and unknown values are never read as another format.

Every stage from `BeginIssuance` or `AuthorizePreAuthorizedIssuance` to `RequestDeferredCredential` requires an acceptance policy and sends nothing without one (`ErrCredentialAcceptancePolicyRequired`), so no authorization is obtained, and no pre-authorized code redeemed, for a credential the wallet would refuse. The policy is `Config.CredentialAcceptance`, unless the issuance brings its own: the `Acceptance` of `IssuanceRequest` or `PreAuthorizedIssuanceRequest`, which `IssuanceAuthorization.Acceptance` and `IssuanceGrant.Acceptance` carry to `RequestCredential`, where `CredentialRequest.Acceptance` overrides it, and which `DeferredIssuance.Acceptance` carries on. A policy holds functions and trust material and is not serialized; each state records a per-request policy in the serialized `AcceptanceOverridden`, and a state read back without `Acceptance` set again (or, for a grant, a `CredentialRequest.Acceptance`) fails with `ErrCredentialAcceptancePolicyRequired` rather than falling back to `Config.CredentialAcceptance`. Under HAIP each stage requires `Config.DPoP.Key`, and the stages that call the PAR or token endpoint (`BeginIssuance`, `AuthorizeIssuance`, `AuthorizePreAuthorizedIssuance`) require a client authentication mechanism (`private_key_jwt` or `Config.Attestation.Client`, HAIP §4.4.1).

### Authorization Code Flow

`BeginIssuance` resolves the metadata, checks the Credential Configuration against the profile and `Config.Issuance.CredentialEncryption`, pushes the authorization request when the server supports RFC 9126 PAR (HAIP requires it, and so does a server that sets `require_pushed_authorization_requests`), and returns the URL to open in the holder's browser. The PAR response must carry a `request_uri` and a positive `expires_in` (RFC 9126 §2.2, `receiverTypes.ErrPARResponseInvalid`); a failed push is never replaced by sending the parameters inline. The authorization endpoint must use `https` (plain `http` only with the experimental transport, never under HAIP). An offer without `grants`, or with an empty object, starts the flow when the authorization server's `grant_types_supported` lists `authorization_code` or is absent (OpenID4VCI 1.0 §4.1.1; otherwise `ErrAuthorizationCodeGrantUnsupported`). `AuthorizeIssuance` takes the whole redirect URL the browser delivered, checks it (RFC 6749 §4.1.2, RFC 9207 `iss`, `state`, `redirect_uri`) and exchanges the code.

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

The client is anonymous unless `private_key_jwt` or `Config.Attestation.Client` authenticates it; HAIP requires `Config.ClientAuth.ClientID`. Without a client attestation, the configured `Config.ClientAuth.Method` (`none` by default) must appear in the authorization server's `token_endpoint_auth_methods_supported`: an absent list means `client_secret_basic` (RFC 8414 §2), which the wallet does not implement, so the request is refused with `client_authentication_unavailable` before it is sent, unless the server declares `pre-authorized_grant_anonymous_access_supported: true`: §6.1 makes client authentication OPTIONAL for this grant and §12.3 lets that parameter accept a request without `client_id`, so the wallet then sends an anonymous request, without client authentication and without `client_id`. With `none`, `pre-authorized_grant_anonymous_access_supported` decides only whether `client_id` is sent. When it is `true`, the token request omits `client_id` even if one is configured; otherwise (the parameter defaults to `false`, §12.3) `Config.ClientAuth.ClientID` is sent, and a wallet without one is refused with `client_authentication_unavailable`. A `private_key_jwt` or attested request always carries `client_id`.

### Credential request, deferred issuance and notification

`RequestCredential` sends one key proof per holder key (more than one requests a batch), a key attestation when needed, and request and response encryption per `Config.Issuance.CredentialEncryption`. The credentials are checked under `CredentialRequest.Acceptance`, else the policy the grant carries from the start of the issuance, else `Config.CredentialAcceptance`, and stored unless the wallet is storeless. The library supplies the issuance context the policy needs (the Credential Issuer Identifier and the format), so a caller configures the acceptance of one issuance without verifying the credential again itself. `IssuanceResult` holds either `Credentials` or a pending `Deferred` transaction, and a `Notification` when the issuer asked to be notified. When the Token Response named `credential_identifiers` (§6.2), `IssuanceGrant.CredentialIdentifiers` keeps all of them, and `CredentialRequest.CredentialIdentifier` selects the Credential Dataset a request names (the first by default); request each dataset the holder wants with its own `RequestCredential`. An element of the `credentials` array is read by its `credential` member, whatever other members it has (§8.3). When the credentials are refused, the error comes with a result whose `Notification` lets the caller report `credential_failure`.

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

`DeferredIssuance.Interval` is the interval the issuer asked for, never shortened; the caller decides how long to wait. `NotifyIssuer` finds the `notification_endpoint` in the re-discovered metadata and sends `credential_accepted`, `credential_failure` or `credential_deleted`.

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

`Config.Issuance.CredentialEncryption` is the holder's policy for Credential Request (§8.1) and Credential Response (§8.2) encryption. Each of `Request` and `Response` is `CredentialEncryptionFollowIssuer` (encrypt what the issuer advertises, obey an issuer that requires it), `CredentialEncryptionRequired` (refuse an issuer that does not offer it, `ErrCredentialEncryptionUnavailable`) or `CredentialEncryptionDisabled` (send no encryption, also to an issuer that offers it with `encryption_required: false`, and refuse an issuer that requires it, `ErrCredentialEncryptionDisallowed`). Disabling either disables both. The response key is carried only inside an encrypted request, so requiring response encryption requires request encryption. A conflict is refused at `BeginIssuance` or `AuthorizePreAuthorizedIssuance`. The response decryption key is ephemeral and travels in `DeferredIssuance`. A plaintext response after encryption was requested is refused.

### Client authentication, DPoP and attestations

* **`private_key_jwt`:** `Config.ClientAuth` with `Method: receiverTypes.PrivateKeyJwt`, `ClientID` and `Key`. The package `clientconfig` loads it from a JSON registration file.
* **Attestation-Based Client Authentication:** `Config.Attestation.Client` (`attestation.ClientProvider`) supplies the Wallet Attestation of a Client Instance Key for the selected authorization server, and the PoP is signed with that key.
  * By default each flow gets an ephemeral P-256 Client Instance Key, as draft-ietf-oauth-attestation-based-client-auth §11.1 recommends against correlation across authorization servers. An Authorization Code Flow keeps the key of its Pushed Authorization Request in `IssuanceAuthorization.ClientInstanceKey` and binds it again at the token endpoint (§10.4).
  * `Config.Attestation.ClientKey` uses one configured key for every authorization server; `Config.Attestation.ClientKeyFromDPoP` opts in to attesting `Config.DPoP.Key`. They are exclusive.
  * The PoP carries the most recent Challenge: the one fetched from the `challenge_endpoint` for the request, else the `OAuth-Client-Attestation-Challenge` header of the latest response from the same server for the same key. A `use_attestation_challenge` error with a fresh Challenge is retried once with it.
* **Key attestation:** `Config.Attestation.Key` (`attestation.KeyProvider`).
* **DPoP:** proofs are signed with `Config.DPoP.Key`; a DPoP-bound grant must be presented with the same key (`ErrDPoPKeyMismatch`). One `use_dpop_nonce` retry is made when the server asks for it. The receiver keeps a server-provided DPoP nonce per origin, per role (authorization server or Credential Issuer, RFC 9449 §9) and per DPoP key, so a nonce is never sent to the other role or with another key. The DPoP-Nonce of a Nonce Response (§7.2) goes to the first key that asks the Credential Issuer. A receiver plugin takes the proofs as `types.DPoPProver` and the attestation headers as `types.ClientAttestationProver`, each carrying the key's RFC 7638 thumbprint.

The library never holds an attester's private key. Before an attestation is sent, it is authenticated under `Config.Attestation.Trust` (`attestation.TrustPolicy`): an attestation with `x5c` is verified with its leaf key, and the chain is validated when `TrustAnchors` or `RootCAs` are set; one without `x5c` needs `ResolveKey`. The `StaticClientAttester` and `StaticKeyAttester` of package `attestation` self-issue with a local key for tests and single-operator deployments; the wallet resolves their key itself. Under HAIP the attestation must carry a non-self-signed `x5c` leaf without the trust anchor, and its chain must reach `TrustAnchors` or `RootCAs`: without either, an attestation with `x5c` is refused rather than checked by its signature alone. A refused attestation is `attestation.ErrClientAttestationInvalid` or `attestation.ErrKeyAttestationInvalid`.

### Signed issuer metadata

`oid4vci.Oid4vciReceiver.IssuerMetadataSigning` configures OpenID4VCI 1.0 §12.2.3 signed Credential Issuer Metadata. `Request` sends the signed-metadata `Accept` header and has no effect without trust material; under HAIP (`Options.RequestSignedIssuerMetadata`) it is on whatever `IssuerMetadataSigning` says. `Require` rejects an unsigned document. The signer is authenticated from the `x5c` header against `TrustAnchors` or `RootCAs`, and `sub` and `credential_issuer` must both be the requested identifier. `RequireIssuerDNSBinding` and `ExpectedLeafDNSName` add a DNS binding of the leaf certificate. Every re-discovery applies this policy.

For Draft 13 (§11.2.3) the same trust material verifies the `signed_metadata` member of the JSON document: `iss`, `sub` (the requested identifier) and `iat` are required, `exp` is honoured, and no `typ` is required. The verified claims take precedence over the plain JSON values, so every Draft 13 stage uses the signed endpoints and `authorization_servers`. A `signed_metadata` that does not verify fails the discovery; without trust anchors the member is ignored, and `Require` demands it. `SignedMetadata` is set only for a verified signature.

Every rejection of a signed document satisfies `errors.Is(err, ErrIssuerMetadataSignatureInvalid)`; `ErrIssuerMetadataSubjectMismatch`, `ErrIssuerMetadataLeafDNSMismatch` and `ErrIssuerMetadataExpired` wrap it. `ErrIssuerMetadataSignatureRequired` is the `Require` outcome. `CredentialIssuerMetadata.MetadataSignature` records the accepted signer, and `RawDocument` keeps the accepted document.

### Draft 13

`w.Draft13()` runs OpenID4VCI Draft 13 with the same staged methods and state types; the states carry `profile.Draft13()` as their `Profile`. A Credential Offer is required, the `c_nonce` comes from the Token and Credential Responses, one key proof is sent, and there are no key attestations or credential encryption. `credential_identifiers` are optional after an `authorization_details` request (the request then names the format), the key proof binds the key by the first method of `cryptographic_binding_methods_supported` the wallet can produce (`jwk` or `did:key`, `ErrCryptographicBindingMethodUnsupported` otherwise), the access token must be Bearer or DPoP, and an `issuance_pending` without `interval` waits five seconds (§9.3). Credential Issuer Metadata comes from the Draft 13 §11.2.2 location only. `Config.Experimental.Hooks.KeyProof` rewrites the key proof for testing.

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

Package `acceptance` decides whether a received credential may be stored. It needs no wallet: `acceptance.NewAcceptor(profile, serializer, verifier)` (the profile the credential is issued under) returns an `Acceptor` whose `Verify(ctx, raw, policy, options)` applies an `acceptance.Policy`. `options.CredentialIssuer` is the Credential Issuer Identifier of the issuance. The wallet runs the same check, with the policy of the request or `Config.CredentialAcceptance`, before it returns or stores a credential.

The checks are:

* **Parse and header.** The credential parses, the issuer JWT carries an algorithm from `Policy.SigningAlgorithms` (default `acceptance.DefaultSigningAlgorithms()`, ES256) and, for SD-JWT VC, the `typ` `dc+sd-jwt` (SD-JWT VC -19 §2.2.1; `vc+sd-jwt` only under `profile.Draft13()`) and a `vct` (§2.2.2.3).
* **Issuer key.** The mechanism follows from the credential, never from the policy (SD-JWT VC -19 §2.5, §7.3). The policy only permits mechanisms; one it does not permit refuses the credential, and no other mechanism is tried in its place.
  * An `x5c` header is authenticated by its chain alone, against `IssuerX509` (anchors, CRL revocation, optional EKU). A chain that is not trusted refuses the credential. The Issuer is the subject of the leaf certificate (SD-JWT VC -19 §2.5), with or without `iss`. An `iss` beside the `x5c` must be an `https` URL whose host the leaf names, in a `dNSName` (exact, no wildcard) or in a `uniformResourceIdentifier` of the same scheme; otherwise the credential is refused with `ErrIssuerDNSBindingFailed`. A DID `iss` with `x5c` is refused: a DID issuer is authenticated by its DID document, so its credential carries no `x5c`. So is any other `iss`, except an `http` one bound the same way under `IssuerX509.Experimental.AllowHTTP` (for a local test issuer; a profile with `ForbidExperimental` refuses it).
  * Without `x5c`, an `https` `iss` is authenticated by JWT VC Issuer Metadata (SD-JWT VC -19 §4, SD-JWT VC only), through `IssuerKeys`, or by `Federation`: the keys of the `openid_credential_issuer` metadata of an OpenID Federation Trust Chain whose Entity Identifier is the `iss` (`acceptance.NewFederationIssuerKeys`).
  * Without `x5c`, a DID `iss` is resolved through `IssuerKeys` and accepted only when a DIF Well Known DID Configuration served by the Credential Issuer's origin links the DID (OpenID4VCI 1.0 §14.4).
  * Any other `iss`, or none, is refused.
* **Holder binding.** A `cnf.jwk` must match the holder key the credential was requested with; `RequireHolderBinding` also refuses a credential without `cnf`.
* **Validity.** The signature, `exp` / `nbf` (with `ClockSkew`), SD-JWT disclosure integrity, an `_sd_alg` the wallet implements (RFC 9901 §4.1.1, §7.1), no Disclosure of `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` or `status` (SD-JWT VC -19 §2.2.2.3), and `ExpectedSDJWTVCType` when set.
* **`ldp_vc`.** The `eddsa-rdfc-2022` Data Integrity proof is verified with a key of the credential's `issuer`, established as above (a DID through a DID Configuration, an `https` issuer through `Federation`), over the JSON-LD contexts pinned in `Policy.DataIntegrityContexts`. The `verificationMethod` must belong to the `issuer`, the validity period is `validFrom` / `validUntil`, and an issuance binds the holder through a `did:key` or `did:jwk` `credentialSubject.id`. `IssuerX509` does not apply.

`IssuerKeys` is an `*issuerkeys.Resolver`: its `Mechanisms` switch on JWT VC Issuer Metadata (and `jwks_uri`), the DID methods and the DID Configuration binding. The acceptor fills the `issuerkeys.Request` itself. `Resolver.Experimental` (`experimental.Transport`) is the only way to fetch over plain HTTP: SD-JWT VC -19 §3 requires HTTPS for every retrieval, and a profile with `ForbidExperimental` (HAIP) refuses a policy whose resolver sets it.

`acceptance.Verification` (also `SavedCredential.Verification`) records how the issuer was authenticated: `Issuer` (the authenticated identity: the leaf certificate's subject for `x5c`, the `iss` for every other mechanism), `ClaimedIssuer` (the `iss` the credential carries; for `x5c` it is what the leaf was bound to, not the authenticated identity), `Mechanism` (`issuerkeys.MechanismX5CTrustedChain`, `MechanismJWTVCIssuerMetadata`, `MechanismDIDConfigurationBinding` or `MechanismOpenIDFederation`), the issuer key, the certificate fingerprints and `IssuerCertificateSubject`, `IssuerDNSBound`, `DID`, `FederationTrustAnchor`, revocation counters and the holder-binding outcome. Failures wrap the sentinels of package `acceptance` (`ErrIssuerKeyUnresolved`, `ErrIssuerSignatureInvalid`, `ErrHolderBindingMismatch`, …); a failed resolution also carries the `*issuerkeys.UnresolvedError` or `*issuerkeys.DIDOnlyTrustError` with its diagnostics, and an untrusted or revoked chain arrives as `*x509.SigningChainError` or `*x509.CRLCheckError` of package `common/x509`.

### Fail-closed defaults

* Without a policy, no authorization is obtained and no credential is requested or stored (`ErrCredentialAcceptancePolicyRequired`).
* There is no policy that accepts a credential without authenticating its issuer.
* Under HAIP an SD-JWT VC requires `IssuerX509` (HAIP §6.1.1): it must carry `x5c` (`ErrIssuerX5CRequired`) without the trust anchor (`ErrIssuerX5CTrustAnchor`) and with a signing certificate that is not self-signed (`ErrIssuerCertificateSelfSigned`).
* `AllowUnadvertisedRevocation` keeps certificates that advertise no revocation mechanism (neither a CRL distribution point nor OCSP) on the trust path and reports them separately. OCSP is not consulted, so a certificate that advertises only OCSP is refused (`x509.CRLErrorUnsupported`) whether or not unadvertised revocation is allowed; accepting it would skip the mechanism its CA publishes.

## OpenID4VP 1.0 presentation {#openid4vp-10-presentation}

### Admitted requests

A presentation request is parsed and admitted once, then answered through the handle the parse returned. `*oid4vp.AdmittedRequest` records which presenter admitted the request and where the response goes; the endpoint is never taken from the caller, and a handle is answered only by the presenter that admitted it (`oid4vp.ErrRequestNotAdmittedHere`).

| Method | Purpose |
| --- | --- |
| `ParsePresentationRequest(ctx, uri)` | Parse and admit an Authorization Request URI, fetching `request_uri` itself. |
| `ParsePresentationRequestObject(ctx, requestObject, src)` | Authenticate a Request Object the caller already holds, as one passed by value. HAIP refuses it (`ErrRequestURIRequired`). |
| `ReadmitPresentationRequest(ctx, sealed, key)` | Re-admit a request from the sealed admission `h.Seal(key)` returned (see [Parsing now and presenting later](#parsing-now-and-presenting-later)). |
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

### Parsing now and presenting later {#parsing-now-and-presenting-later}

The handle is not serializable, and only the presenter that admitted a request answers it. A wallet that shows a consent screen in one call and presents in another, with no state kept in memory between them, carries the admission across in one of two ways.

**Sealed admission.** `h.Seal(key)` returns a `presenterTypes.SealedAdmission`: a record of what the first admission observed, sealed with HMAC-SHA256 under a key the caller holds. The record holds the Request Object as the library fetched it, the `request_uri` it came from, the delivery by reference, the `wallet_nonce` the library sent, the outer `client_id`, the instant the Request Object was authenticated at, the profile it was admitted under, in its text form (`profile.Profile.String`, which names every option), and, for a Draft 24 request, the Presentation Definition fetched from its `presentation_definition_uri`. `w.ReadmitPresentationRequest(ctx, sealed, key)` (`w.Draft24().ReadmitPresentationRequest` for a Draft 24 request) accepts the record only when the seal verifies under the same key, the record names the wallet's profile (compared by its text form) and the protocol version of the method, and it is younger than `MaxReadmitAge`. It then applies `RequestURIPolicy` to the recorded `request_uri` and authenticates the Request Object again: its signature, the client authentication its Client Identifier Prefix selects, the `wallet_nonce` echo and every profile option, as the Request Object delivered by reference. It does not fetch `request_uri` again. The result is an ordinary handle, answered by `SubmitPresentation` or `DeclinePresentation`, and can be sealed again, to the same record.

This is how a HAIP wallet answers in a later call: HAIP (`Options.RequireSignedRequestByReference`, §5.1) refuses a Request Object handed over by value, and a sealed admission is not one, since only the holder of the key can make a record the library accepts. Nothing changes on the wire.

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

// admit parses the request for the consent screen and seals the admission;
// the caller stores sealed with its pending presentation.
func admit(ctx context.Context, w *wallet.Wallet, uri string, key []byte) (presenterTypes.SealedAdmission, error) {
	request, err := w.ParsePresentationRequest(ctx, uri)
	if err != nil {
		return "", err
	}
	return request.Seal(key)
}

// answer re-admits the sealed request after the Holder's consent and sends
// the presentation, from a wallet built for this call.
func answer(ctx context.Context, w *wallet.Wallet, sealed presenterTypes.SealedAdmission, key []byte,
	p wallet.Presentation) (*presenterTypes.SubmitResult, error) {
	request, err := w.ReadmitPresentationRequest(ctx, sealed, key)
	if err != nil {
		return nil, err
	}
	return w.SubmitPresentation(ctx, request, p)
}
```

The rules:

* **Key.** At least `oid4vp.MinSealKeyBytes` (32) bytes, random, and secret to the wallet deployment; a shorter key is `oid4vp.ErrSealKeyTooShort`. The library does not store it. Rotating it invalidates the admissions sealed under the old key.
* **What can be sealed.** Only a request whose Request Object the library fetched from `request_uri` (`RequestObjectVerification.Delivery == "reference"`). A Request Object passed by value, plain parameters and a DC API request are `oid4vp.ErrAdmissionNotSealable`: they have no delivery fact to carry.
* **Refusals.** A malformed record, a version other than `v3`, a record or tag that is not canonical unpadded base64url, an altered record or tag, another key, a record for another profile (`profile.Final().With(profile.HAIPOptions())` is not `profile.Final()`) or another protocol version, a record older than `Oid4vpPresenter.MaxReadmitAge` (default `oid4vp.DefaultMaxReadmitAge`, 15 minutes), or one admitted after the presenter's clock is `oid4vp.ErrSealedAdmissionInvalid` (code `sealed_admission_invalid`), decided before anything is authenticated or fetched. A `request_uri` that `RequestURIPolicy` refuses is `ErrRequestURINotAssociated`, as it is before a fetch. A recorded Presentation Definition whose URI the re-authenticated Request Object does not name is `ErrSealedAdmissionInvalid` as well.
* **Clock.** The re-admission judges the Request Object's `iat`, `exp` and `nbf` at the instant of the first admission, so a consent that outlasts `exp` does not refuse the response; `MaxReadmitAge` bounds how long that lasts, and `RequestObjectVerification.ExpiresAt` reports `exp` for a wallet that wants a tighter limit. Everything else is judged on the current clock: the certificate chain and its validity, revocation (a revocation list is fetched again), a Verifier Attestation and an OpenID Federation Trust Chain. A certificate that expired or was revoked since the first admission refuses the re-admission.
* **Reuse.** The library keeps no state, so the same sealed value re-admits any number of times until `MaxReadmitAge`: whoever holds it and the key can answer the request again. A wallet that answers each request once sets `Oid4vpPresenter.ConsumeSealedAdmission(ctx, sealID, notAfter)`, which a successful re-admission calls last with the seal's identifier (its tag) and the instant it stops re-admitting anyway; the hook records the identifier atomically and returns an error for one it has seen, which refuses the re-admission with `oid4vp.ErrSealedAdmissionConsumed` (code `sealed_admission_consumed`). A re-admission that fails consumes nothing. Resealing a re-admitted handle yields the same seal, so the same identifier. The wallet's own presenter has no hook; inject an `Oid4vpPresenter` through `Config.Presenter` to set it.
* **Format.** `v3.` + base64url(JSON record) + `.` + base64url(HMAC-SHA256 tag), both canonical and unpadded. The tag covers a label naming the version and the record. The record is readable to whoever holds it: the seal protects its integrity, not its confidentiality, so store it where the Request Object may be stored.

**Kept Request Object.** Where the profile allows a Request Object passed by value (not under HAIP), the wallet may instead keep the Request Object (`h.RequestObject()`) and parse it again; the second parse authenticates the Request Object again, including its `exp` on the current clock.

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

// presentLater answers a request admitted earlier from its kept Request Object.
func presentLater(ctx context.Context, w *wallet.Wallet, requestObject, clientID string,
	p wallet.Presentation) (*presenterTypes.SubmitResult, error) {
	request, err := w.ParsePresentationRequestObject(ctx, requestObject, presenterTypes.RequestObjectSource{ClientID: clientID})
	if err != nil {
		return nil, err
	}
	return w.SubmitPresentation(ctx, request, p)
}
```

A request in plain parameters has no Request Object (`RequestObject()` is empty); parse its URI again instead. `RequestObjectSource` carries only the outer `client_id`: how a Request Object reached the wallet is something the library observes, never something a caller states. `RequestObjectVerification.Delivery` is `"reference"` only when the library fetched `request_uri` itself (or re-admitted a sealed admission of such a fetch), and `WalletNonce` is set only for the `wallet_nonce` it sent in that POST; a Request Object passed by value is always delivered by value. Under HAIP `ParsePresentationRequestObject` and the `request` parameter are therefore refused with `ErrRequestURIRequired` before any network access.

### Verifier authentication {#verifier-authentication}

`oid4vp.Oid4vpPresenter` authenticates the verifier from the Client Identifier Prefix:

| Prefix | Authentication |
| --- | --- |
| `x509_san_dns`, `x509_hash` | Signed Request Object required. The `x5c` chain must reach `RequestObjectValidation.TrustAnchors` / `RootCAs` (or `X509TrustChainRoots`), with CRL revocation checks. `x509_san_dns` binds a DNS SAN and the response endpoint; `x509_hash` binds the leaf certificate hash. HAIP requires `x509_hash`. |
| `redirect_uri` | Unsigned only; binds the response endpoint to the identifier. It authenticates nobody. |
| none (pre-registered) | The client must be in `PreRegisteredClients` or found by `ResolvePreRegisteredClient` (`oid4vp.ErrPreRegisteredClientUnknown`). Its `Metadata` replaces the request's metadata, and its `Metadata.RedirectURIs` are the only response endpoints accepted; a registration without them accepts no request. A signed Request Object is verified with the registered `JWKS`; `RequireSignedRequestObject` refuses an unsigned one. |
| `verifier_attestation` | Signed Request Object required; the Verifier Attestation JWT must be issued by one of `RequestObjectValidation.VerifierAttestationIssuers`, and the Request Object signed with its `cnf` key. |
| `openid_federation` | Signed Request Object required (OpenID Federation 1.0 §12.1.1). A Trust Chain to `RequestObjectValidation.Federation.TrustAnchors`; the Request Object is verified with the keys the derived `openid_credential_verifier` metadata publishes in `jwks`, `signed_jwks_uri` (signed with a Federation Entity Key of the Verifier) or `jwks_uri`, never with the Federation Entity Keys themselves (§12.1.1.1.2, §5.2.1; `federation.ErrVerifierKeysUnavailable`). |
| `decentralized_identifier` | Refused. |
| `origin` | Refused (`ErrClientIDPrefixReserved`). |

A prefix that requires a signature is refused in plain parameters with `ErrRequestObjectSignatureRequired`. `RequestObjectVerification` on the parsed request records what was authenticated (certificate fingerprints and a `Certificate` summary, revocation counters, the echoed `WalletNonce`, `Delivery`, `ExpiresAt`, and the `VerifierAttestation` or `Federation` evidence); no request parameter can populate it.

Every `client_metadata.jwks` member must carry a `kid` that no other member repeats (OpenID4VP 1.0 §5.1; `ErrClientMetadataJWKKeyIDMissing`, `ErrClientMetadataJWKKeyIDDuplicate`). `RequestObjectValidationOptions.RequestURIPolicy(clientID, requestURI)` lets a wallet in a trust framework tie a `request_uri` to its `client_id`; it runs before the fetch (and, on the re-admission of a sealed admission, on the recorded `request_uri`), and a refusal is `ErrRequestURINotAssociated`. `oid4vp.RequestURISameHost` is such a policy: it requires `https` and the host an `x509_san_dns`, `redirect_uri` or `openid_federation` Client Identifier names, and accepts the prefixes that name no host.

`client_metadata` members the request's version acts on (`jwks`, `encrypted_response_enc_values_supported`, `vp_formats_supported`; on Draft 24 `jwks`, `vp_formats` and the JARM members) must be well formed; any other member is kept only when well typed and never refuses the request (OpenID4VP 1.0 §5.1: "Other metadata parameters MUST be ignored"), the other version's formats member is not read, and an `openid_federation` request's `client_metadata` is not read at all (§5.9.3). A presentation whose Issuer-signed JWT or KB-JWT algorithm the Verifier's `sd-jwt_alg_values` / `kb-jwt_alg_values` do not list fails with `ErrVPFormatAlgUnsupported` before it is sent.

A `direct_post` or `direct_post.jwt` request that carries `redirect_uri` is `invalid_request` (`ErrRedirectURIWithDirectPost`, §8.2), also when a `redirect_uri` Client Identifier lets it omit `response_uri`.

`RequestObjectValidationOptions` holds the relying-party policy: `TrustAnchors` or `RootCAs`, `CRL`, `AllowUnadvertisedRevocation`, `CertificateKeyUsages`, `WalletAudience`, `SigningAlgorithms` (default ES256 and RS256), `RequireExpiry`, `MaxAge` (zero is unbounded in every profile), `Now` and `ClockSkew`. A Request Object whose `iat` lies in the future is refused, so set `ClockSkew` to the clock difference the verifiers you accept may have. `X509TrustChainRoots` alone accepts certificates that publish no revocation information, but not one that advertises only OCSP; it cannot be combined with anchors in `RequestObjectValidation`.

`Oid4vpPresenter.Experimental` (`experimental.Presenter`) carries relaxations no specification allows, for local verifiers and experiments only: `Transport.AllowHTTP` (plain HTTP verifier endpoints), `InsecureSkipX509Verify` (a Draft 24 `x509_san_dns` Request Object checked by binding and signature only, admitted without `RequestObjectVerification`; the OpenID4VP 1.0 path then refuses every signed Request Object) and `AcceptClientMetadataJWKsWithoutKeyID`. The zero value applies none, and a HAIP presenter refuses any of them on every entry point.

### DCQL

`SelectCredentials` evaluates `credential_sets` (`options`, `required`), `claims`, `claim_sets`, `values`, nested and array claim paths (OpenID4VP 1.0 §7), `multiple`, `meta` (`vct_values`, `type_values`) and `trusted_authorities` of type `aki` and `openid_federation`. An `openid_federation` value matches a credential when a Trust Chain from its issuer to a Trust Anchor of `RequestObjectValidation.Federation`, resolved under that configuration, includes the value (OpenID4VP 1.0 §6.1.1.3); without configured Trust Anchors it matches nothing. A caller that builds `oid4vp.DCQLCredentialCandidate` values itself sets `Issuer` and calls `AdmittedRequest.ResolveFederationTrustedAuthorities` before matching. It picks, for every required credential query, the credentials that satisfy it with the first claim set they satisfy; a request the store cannot answer is an `*oid4vp.AuthorizationRequestError` with code `access_denied`. Credentials without holder binding are excluded from a query that requires it. A `jwt_vc_json` or `ldp_vc` claim path starts at the credential (`["credentialSubject","given_name"]`).

A wallet whose holder chooses among candidates uses `oid4vp.ResolveDCQLClaimSets` and `oid4vp.ValidateDCQLMatches`; `SubmitPresentation` applies the same validation to the selection it is given (`oid4vp.ErrDCQLSelectionUnsatisfied`).

### `transaction_data`

`Config.SupportedTransactionDataTypes` (or `Oid4vpPresenter.SupportedTransactionDataTypes` on an injected presenter) lists the `transaction_data` types the wallet processes; with an empty list every request carrying `transaction_data` is refused with `invalid_transaction_data`. Each entry must reference credential queries of the request. Only a `dc+sd-jwt` presentation with a Key Binding JWT carries transaction data: a referenced `dc+sd-jwt` query must require holder binding, and an entry assigned to another format fails before anything is sent. Each entry is bound to the presented credential the Holder assigns it to (§5.1: "the Wallet MUST use only one of the referenced Credentials"): `CredentialSelection.TransactionData` lists the indexes of the entries a credential authorizes. Every entry must then be assigned, each to credentials that answer one and the same query of its `credential_ids`; several credentials of that query each carry it only when the assignment names each (`ErrTransactionDataAssignmentInvalid`). Without an assignment an entry goes to the first presented query of its `credential_ids`, and one that several presented credentials answer (`multiple: true`) fails with `ErrTransactionDataAssignmentRequired` instead of being bound into all of them. The hash algorithm comes from the entries' `transaction_data_hashes_alg` (`sha-256` by default). A Draft 24 request follows the same rules: `credential_ids` name input descriptors, and each must accept an SD-JWT VC (`vc+sd-jwt`).

### Response modes and encryption

A request URI or Request Object uses `direct_post` or `direct_post.jwt`; a DC API request uses `dc_api` or `dc_api.jwt`, and each path refuses the other's modes. HAIP requires `direct_post.jwt` and, for the DC API, `dc_api.jwt`. `direct_post.jwt` and `dc_api.jwt` require encryption keys in `client_metadata.jwks` (`ErrResponseEncryptionKeyMissing`). The key must name its `alg`, which is the JWE `alg` (OpenID4VP 1.0 §8.3); `authorization_encrypted_response_alg` never stands in for it. The response is an ECDH-ES family JWE with the `encrypted_response_enc_values_supported` value the wallet prefers (A256GCM first; A128GCM when the list is absent), and under HAIP the key must be ECDH-ES on P-256 and the verifier must list both A128GCM and A256GCM (`ErrResponseEncryptionEncMissing`). These checks run at parse time, before consent.

The response POST and the `request_uri` fetch do not follow redirects. A non-2xx response is an `*oid4vp.VerifierResponseError`.

### Error responses

`DeclinePresentation` answers an admitted request with an error response, encrypted under `direct_post.jwt` when the verifier metadata allows it (§8.3.1). A request that fails admission is not answered by default, because its endpoint was chosen by an unauthenticated request. `AuthorizationRequestError.SendErrorResponse(ctx, client)` sends the error response for a refused unsigned `redirect_uri` request whose `ResponseURI()` is set; `Oid4vpPresenter.SendParseErrorResponses` makes the presenter do so at parse time.

### Digital Credentials API

`ParseDCAPIRequest` admits a W3C Digital Credentials API invocation: `openid4vp-v1-unsigned`, `openid4vp-v1-signed` or `openid4vp-v1-multisigned`. The caller supplies the platform-authenticated origin, which is never read from the request; the admitted request carries it as `Request().Origin`. An unsigned request has no Client Identifier: its `client_id` and `expected_origins` are ignored and `ClientID` stays empty (Appendix A.2). A signed request is authenticated with the `x5c` chain of an `x509_san_dns` or `x509_hash` Client Identifier; `expected_origins` must contain the origin exactly, `aud` may be absent (an `aud` that is present must identify the wallet), and every signature of a multi-signed request must be typed `oauth-authz-req+jwt`. `SubmitPresentation` makes no HTTP call and returns the object to hand back to the platform: `{"vp_token": {...}}` for `dc_api`, or `{"response": <JWE>}` for `dc_api.jwt`. The Key Binding JWT `aud` is `origin:<origin>` (OpenID4VP 1.0 Appendix A.4).

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

`w.Draft24().ParsePresentationRequest` and `ParsePresentationRequestObject` admit OpenID4VP Draft 24 requests carrying a Presentation Exchange `presentation_definition`, by value or by `presentation_definition_uri`, which the library fetches once the request is authenticated (§5.5: `GET` without parameters, `https`, no redirects; `invalid_presentation_definition_uri` / `_reference`) and reports in `PresentationDefinition` and `RawPresentationDefinition`; a sealed admission carries the fetched definition to the re-admission. `w.Draft24().ReadmitPresentationRequest` re-admits a sealed admission of a Draft 24 request. The handle is answered with `SubmitPresentation` (a `vp_token` and `presentation_submission`) and `DeclinePresentation`. `SelectCredentials` picks the newest credential for every input descriptor, and `QueryIDs` name input descriptor ids. On an SD-JWT VC, key binding is always required and a non-nil `DisclosedClaims` limits disclosure. An input descriptor with `limit_disclosure` `required` limits the presentation to the claims its `fields` name. Each field is the first of its `path` entries the credential resolves, matched by its full JSONPath (`$.a.b`, `['a']`, `[0]`, `[*]`), never by claim name; there `DisclosedClaims` keeps a field only when it holds every disclosure the field needs. A credential that cannot disclose selectively, a disclosure no field needs, a path without a single position (recursive descent, filters), or a parent disclosure whose plaintext members no field covers fails with `ErrLimitDisclosureUnsatisfiable` before anything is sent, since a disclosure cannot be revealed in part. An input descriptor's `format` algorithm lists apply like `vp_formats`, unless `vp_formats` omits that format (§5.4). `Config.Experimental.Hooks.PresentationExchangeResponse` rewrites the response for testing.

**Protocol version.** The two versions share one request syntax, so the entry points decide by the query language before any rule of one version alone (`oid4vp.VersionMismatchError`, code `oid4vp_version_mismatch`). A request with `presentation_definition` or `presentation_definition_uri` and no `dcql_query` that reaches an OpenID4VP 1.0 entry point is refused naming Draft 24 - including a signed `request_uri` behind an outer `response_mode=direct_post.jwt`. A `dcql_query` request that reaches a Draft 24 entry point is refused naming 1.0: the library does not implement the Draft 24 DCQL response (§8.1). `w.AdmitPresentationRequestUnderVersion(ctx, err)` admits the refused request under the version the error names, without fetching `request_uri` again (the Request Object is authenticated as delivered by reference, with the `wallet_nonce` sent for it). A 1.0 request that also carries Presentation Exchange parameters ignores them (§5); a Draft 24 request with more than one query language is `invalid_request`.

The Draft 24 entry points apply the Draft 24 rules, not the 1.0 ones:

* **Client Identifier Schemes** (Draft 24 §5.10.4): `redirect_uri` (unsigned only; the Response URI is the Client Identifier, or defaults to it when omitted), an `https` OpenID Federation Entity Identifier, `verifier_attestation`, `x509_san_dns`, and a colon-less pre-registered client resolved in `PreRegisteredClients` / `ResolvePreRegisteredClient`, whose registered metadata takes precedence over `client_metadata` (§5.1). `did` and `x509_san_uri` are refused as unsupported (`ErrRequestObjectClientAuthUnsupported`), `web-origin` is reserved to the DC API (`ErrClientIDPrefixReserved`), and the 1.0 prefixes `x509_hash`, `decentralized_identifier`, `openid_federation` and `origin` are not Draft 24 schemes. A Request Object is never verified with a `client_metadata` key, and a pre-Draft 22 `client_id_scheme` parameter is ignored.
* **`request_uri`**: a POST sends a fresh `wallet_nonce`, which the Request Object must echo, and `WalletMetadata` when set (§5.11); `request_uri_method` is case-sensitive. With `OmitWalletNonce` the POST carries no `wallet_nonce` and no echo is checked, since the draft requires the echo only when the Wallet passed one.
* **Responses**: only `direct_post` and `direct_post.jwt` are answered. `direct_post.jwt` is an encrypted JARM response (§8.3) whose `vp_token` is a string for one compact presentation and JSON for an array or an `ldp_vp` object (§8.1): the JWE `alg` is `authorization_encrypted_response_alg` (required), the `enc` is `authorization_encrypted_response_enc` (A128CBC-HS256 when absent), and the key is a `client_metadata.jwks` key whose `use` is `enc` or absent and whose `alg`, if any, matches. `client_metadata.jwks` needs no `kid`, and HAIP never applies.

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

`NewWalletWithConfig` checks the configuration against `Config.Profiles`:

* `Config.Profiles` names exactly one 1.0 profile and each draft profile at most once (`ErrInvalidArgument`). A 1.0 profile with `Options.ForbidDraftProfiles` (HAIP) together with a draft profile is refused (`ErrProfileForbidsDraft`).
* A receiver or presenter plugin that implements `profile.Carrier` must report the wallet's 1.0 profile, options included (`ErrProfileMismatch`); a plugin reporting a draft profile is refused (`profile.ErrDraftProfile`). When the 1.0 profile carries options (HAIP, or Final strengthened with `With`), a plugin that does not implement `profile.Carrier` is refused (`ErrProfilePluginUnsupported`); under plain Final it is accepted.
* `Draft13()` methods return `ErrProfileForbidsDraft` unless `profile.Draft13()` is enabled, and `Draft24()` methods and Draft 24 handles unless `profile.Draft24()` is. `Experimental.Hooks` is refused unless a draft profile is enabled.
* `Experimental.Transport` and `Experimental.Hooks` are refused under a profile with `ForbidExperimental` (HAIP), and `Experimental.Transport` together with an injected `Receiver` or `Presenter`, which the wallet does not reconfigure (`ErrInvalidArgument`). An injected `oid4vci.Oid4vciReceiver` whose own `Experimental` its profile forbids is refused too (`Oid4vciReceiver.ValidateProfile`), and such a receiver sends nothing on any exchange.
* `Attestation.ClientKeyFromDPoP` without a DPoP key or together with `Attestation.ClientKey` is refused (`ErrInvalidArgument`).
* `Storeless` together with `CredStore`, `SupportedTransactionDataTypes` together with `Presenter`, and a `Presenter` plugin other than `*oid4vp.Oid4vpPresenter` are refused (`ErrInvalidArgument`).

The receiver and the presenter are checked once, here; the wallet has no method that replaces them later. Plugin fields must not change after the plugin is registered. HAIP further requires, each through its `profile.Options` field, among others: PAR, DPoP-bound access tokens, a client authentication mechanism, `scope` on every Credential Configuration, a Nonce Endpoint when a key attestation is needed, `x509_hash`, signed requests delivered by `request_uri`, the encrypted response modes, SD-JWT VC issuer `x5c`, and a Key Binding JWT for every SD-JWT VC that carries `cnf`. `Experimental.Transport` (on the wallet, the receiver, the issuer key resolver and the Status List checker) and any non-zero `Experimental` on the presenter, on every entry point, are refused.

`w.StatusListChecker(base)` returns a copy of a `statuslist.Checker` after checking that its `Profile` is the wallet's 1.0 profile (`ErrProfileMismatch` otherwise). A checker applies the options of its own profile, for HAIP 1.0 §6.1 the token key in `x5c`, no trust anchor in it and no self-signed leaf, so a checker left at the zero profile (Final) in a HAIP wallet is refused rather than run under weaker rules. The key hook `issuerkeys.Resolver.StatusListKeyFunc` accepts the leaf of a token `x5c` chain that reaches the configured anchors, since draft-ietf-oauth-status-list-21 §11.3 mandates no binding between the Status List Token signer and the credential's issuer; `profile.Options.RequireStatusListSignerBinding`, which no profile turns on, also requires the leaf to have the key or subject of the credential's issuer certificate (`X5CTrust.IssuerCertificate`), its issuing CA, or the host of its `iss`. An extended key usage is required only through `X5CTrust.KeyUsages`. Under `ForbidExperimental` a checker that sets `Experimental` is refused (`statuslist.ErrStatusListInsecureTransportForbidden`). Every HTTP client the library creates by default (the receiver's, the presenter's, the Federation resolver's, the issuer key resolver's, the Status List checker's and the CRL fetches') negotiates TLS 1.2 or later (FAPI 2.0 Security Profile §5.2.1, which HAIP 1.0 §4 applies; BCP 195); a client the caller injects keeps its own TLS configuration.

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
		return "configure Config.CredentialAcceptance or the Acceptance of the issuance request"
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

The observer sees each request with its credentials replaced by `observe.Redacted`: the `Authorization` value after its scheme, the `DPoP`, `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers, and the `pre-authorized_code`, `tx_code`, `code`, `code_verifier`, `client_assertion` and `refresh_token` parameters of a form body. The request sent is unchanged. `observe.UnredactedTransport` is the opt-in for an observer that must see them; it then holds bearer secrets.

## Experimental settings {#experimental}

Package `experimental` holds every setting that departs from the OpenID4VC specifications. They exist to test a peer and are not for production. A departure is reachable only through a type of this package carried by a field named `Experimental`, so code that relaxes a rule imports the package:

| Setting | Where | Effect |
| --- | --- | --- |
| `experimental.Transport{AllowHTTP}` | `Config.Experimental.Transport` (plugins the wallet builds), `oid4vci.Oid4vciReceiver.Experimental`, `issuerkeys.Resolver.Experimental`, `statuslist.Checker.Experimental`, `acceptance.IssuerX509TrustOptions.Experimental` | Accepts plain HTTP issuer endpoints and identifiers, metadata and Status List endpoints of a local test issuer, and binds an `http` `iss` to an `x5c` leaf by its host; the presenter the wallet builds gets it too. A client assertion still goes over plain HTTP only to a loopback host. |
| `experimental.Presenter{Transport, InsecureSkipX509Verify, AcceptClientMetadataJWKsWithoutKeyID}` | `oid4vp.Oid4vpPresenter.Experimental` | Plain HTTP verifier endpoints; a Draft 24 `x509_san_dns` Request Object without chain validation; `client_metadata.jwks` members without a unique `kid` on the 1.0 path (OpenID4VP 1.0 §5.1). |
| `experimental.Hooks{KeyProof, PresentationExchangeResponse}` | `Config.Experimental.Hooks` | Rewrites Draft 13 key proofs (`ProofTransform`, `ProofJWTContent`) and Draft 24 responses (`Draft24ResponseTransform`) after they were built. |

The zero value of every type is the conforming behavior. Nothing is read from the environment. A profile that forbids a departure refuses it rather than ignoring it: HAIP refuses `Transport` wherever it is carried and every non-zero `Presenter`, on every presenter entry point (OpenID4VP 1.0, Digital Credentials API, Draft 24 and re-admission), before any network access (the Status List checker with `statuslist.ErrStatusListInsecureTransportForbidden`, the others with an invalid-input or `invalid_request` error), and it refuses `Hooks`, which need a draft profile in any case.

## Environment variables

The variables are defined in `wallet/env/env.go`.

| Variable | Default | Description |
| :---- | :---- | :---- |
| `VCKNOTS_WALLET_DEBUG` | `false` (unset/empty) | Enables debug logging only. It does not relax HTTPS. |

`env.SetDebugMode(true)` sets it from test code. No environment variable allows plain HTTP; use [`experimental.Transport`](#experimental).

## Changes from the previous wallet API

This section lists the changes from the wallet API on upstream `main` (`51149d9`) to identifiers that exist there, and the behavior changes of their methods. Identifiers added by this version are described in the sections above. Every exported signature of upstream `main` is unchanged, except the `Wallet` methods and types removed or changed below and the removed `env` identifiers.

**Package `wallet`**

* `Config` is no longer comparable with `==`.
* `Config` has new fields: `Profiles`, `Storeless`, `CredentialAcceptance`, `SupportedTransactionDataTypes`, `Issuance`, `Attestation`, `Experimental`. `CredentialOfferGrant` has `IssuerState` and `AuthorizationServer`; `SavedCredential` has `Verification`.
* `NewWalletWithConfig` refuses an invalid `Profiles` set, a plugin whose profile differs from the wallet's, a plugin that does not implement `profile.Carrier` when the profile carries options, and `Experimental.Hooks` without a draft profile. It refuses `Storeless` with a `CredStore`, `SupportedTransactionDataTypes` with an injected `Presenter`, and a presenter plugin other than `*oid4vp.Oid4vpPresenter`. Its errors carry codes.
* `SetReceiver` was removed. Set `Config.Receiver`: `NewWalletWithConfig` checks its plugins against the wallet's profile and refuses a mismatch when the wallet is built.
* `VerifyCredential` was removed. `VerifyCredentialForAcceptance` runs the check issuance runs before storing; a bare signature check is `Verify` on a `verifier.VerificationDispatcher`, which accepts every registered algorithm, so the caller applies its own algorithm policy.
* `ReceiveCredential` and `ReceiveCredentialRequest` were removed. An issuance is `AuthorizePreAuthorizedIssuance` (or `BeginIssuance` and `AuthorizeIssuance`) followed by `RequestCredential`, for an OpenID4VCI 1.0 issuer on `Wallet` and for a Draft 13 issuer on `Draft13()`. The upstream method stored a credential it had only parsed; every issuance now needs an acceptance policy before its token request, and stores nothing its policy refuses. For a Draft 13 issuer the key proof carries the `c_nonce` of the Token Response, and no `nonce_endpoint` is called. The Draft 13 token request follows Draft 13 §6.1 instead of the OpenID4VCI 1.0 negotiation of `token_endpoint_auth_methods_supported`: it sends `Config.ClientAuth.ClientID` whenever one is set, an anonymous request (no `client_id`) needs `pre-authorized_grant_anonymous_access_supported: true` (absent means `false`), and the configured method is never dropped: `private_key_jwt` is used only when the server advertises it, and `none` only when the server lists `none`, publishes no `token_endpoint_auth_methods_supported` or declares anonymous access; any other combination is refused with `client_authentication_unavailable` before the request is sent. The Draft 13 authorization code flow and its PAR request follow the same rule. The offer's issuer may be plain HTTP only when the receiver plugin allows it (`HTTPSchemePolicy`).
* A pre-authorized_code token request to an authorization server that declares `pre-authorized_grant_anonymous_access_supported: true` and omits `token_endpoint_auth_methods_supported` is sent anonymously (no client authentication, no `client_id`, OpenID4VCI 1.0 §6.1 and §12.3) instead of being refused with `client_authentication_unavailable`. A published method list still decides as before.
* `PresentCredential`, `PresentCredentialWithOptions`, `PresentCredentialOptions` and `RedirectHandler` were removed. A presentation is `ParsePresentationRequest`, `SelectCredentials` and `SubmitPresentation`, with the holder's consent between the last two; the verifier's redirect URI is `SubmitResult.RedirectURI`, which the library never follows. Stored credentials are chosen by the DCQL query instead of taking the newest one, each answered query gets its own presentation, and a Key Binding JWT is attached as the query requires. The request is admitted under the rules of [Verifier authentication](#verifier-authentication).
* `FetchCredentialIssuerMetadata` takes a `context.Context` and the Credential Issuer Identifier. The `receivingType` argument, which selected nothing but OpenID4VCI, was removed. The metadata is read from the OpenID4VCI 1.0 §12.2.2 location under the wallet's 1.0 profile.
* `GetCredentialEntries` and `GetCredentialEntry` return `ErrNoCredentialStore` on a storeless wallet.
* Every error returned by a method of `Wallet` carries a code (`wallet.ErrorCode`).

**Plugins and sub-packages**

* `oid4vp.Oid4vpPresenter` is no longer comparable with `==`. `oid4vci.Oid4vciReceiver` and `oid4vp.Oid4vpPresenter` have new fields (`HTTPClient`, `Experimental` on the receiver, `Profile` and others) and new methods. `receiver.WithDefaultConfig`, `presenter.WithDefaultConfig` and `NewWallet` build plugins that require HTTPS; no environment variable changes that.
* `oid4vci.OID4VCICredentialFormatToSerializationFlavor` was removed; use `oid4vci.CredentialFormatFlavor` with the profile of the issuance. A Draft 13 issuance (`Draft13()`) reads the issuer metadata from the Draft 13 §11.2.2 location and maps formats by the Draft 13 table of `CredentialFormatFlavor(profile.Draft13(), …)` (`jwt_vc_json`, `ldp_vc`, `vc+sd-jwt`; `dc+sd-jwt` is refused with `oid4vci.ErrCredentialFormatUnsupported`). Upstream `ReceiveCredential` stored an unknown format as JWT VC; it is now refused.
* The receiver plugin refuses every HTTP redirect (`ErrHTTPRedirectNotAllowed`), bounds response bodies, and refuses Credential Issuer Metadata whose `credential_issuer` is not the requested identifier and authorization server metadata whose `issuer` is not the requested one.
* `Oid4vpPresenter.ParsePresentationRequest` authenticates the verifier as described in [Verifier authentication](#verifier-authentication): signed Request Objects are verified by the prefix's own mechanism and never with keys from `client_metadata`, `x509_*` prefixes require a signed Request Object, a colon-less `client_id` is a pre-registered client that must be registered, and a future `iat` is refused. `X509TrustChainRoots` keeps accepting certificates without revocation information, but refuses one that advertises only OCSP.
* `Oid4vpPresenter.AllowHTTP` and `InsecureSkipX509Verify` were removed; `Oid4vpPresenter.Experimental` (`experimental.Presenter`) sets them explicitly. The presenter `NewWallet` and `presenter.WithDefaultConfig` build no longer reads `VCKNOTS_WALLET_HTTP_ALLOWED`. `Oid4vpPresenter.RequireClientMetadataJWKKeyIDs` was removed: the OpenID4VP 1.0 entry points always require a unique `kid` unless `Experimental.AcceptClientMetadataJWKsWithoutKeyID` is set. `requestBuilder.WithHTTPAllowed` was removed.
* `issuerkeys.Resolver.AllowHTTP` and `statuslist.Checker.AllowHTTP` were replaced by `Experimental experimental.Transport`. A `statuslist.Checker` whose profile has `ForbidExperimental` now refuses `Experimental` with `statuslist.ErrStatusListInsecureTransportForbidden` instead of ignoring it, and passes the rule to its key hook in `KeyRequest.ForbidExperimental`, which `Resolver.StatusListKeys` applies to the resolver's own `Experimental`.
* `presenterTypes.RequestObjectSource.DeliveredByReference`, `RequestObjectSource.WalletNonce` and `oid4vp.RequestObjectVerification.DeliveryAttested` were removed: the library records the delivery and the `wallet_nonce` it observed itself, and HAIP refuses a Request Object passed by value.
* `oid4vp.FederationTrustOptions.AllowUnsignedRequests` was removed; an unsigned `openid_federation` request is always refused. A federation Request Object is verified with the `openid_credential_verifier` metadata keys, not the Federation Entity Keys.
* `oid4vp.OID4VPClientIDPrefixWebOrigin` was removed. An unsigned DC API request keeps an empty `ClientID`, and `CredentialPresentationRequest.Origin` carries the platform Origin. `profile.ResponseEncryptionRules.RequireJWKAlg` was removed, since OpenID4VP 1.0 always requires the JWK `alg`.
* The presenter no longer posts an error response when parsing fails; `SendParseErrorResponses` or `AuthorizationRequestError.SendErrorResponse` does it on request. The `request_uri` fetch and the response POST (`Present`) do not follow redirects, and a non-2xx response to `Present` is an `*oid4vp.VerifierResponseError`.
* `NewRequestBuilder` builds OpenID4VP 1.0 requests under `profile.Final()`; `WithProfile` selects another 1.0 profile.
* The SD-JWT VC serializer refuses an `_sd_alg` that is not a string or names a hash it does not implement, where it used to read it as `sha-256` (RFC 9901 §4.1.1, §7.1), and refuses a Disclosure of `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts` or `status`, or of one of their sub-claims (`serializerTypes.ErrRegisteredClaimDisclosed`, SD-JWT VC -19 §2.2.2.3).
* `receiver.ReceivingDispatcher` and `presenter.PresentationDispatcher` have new methods (`Plugins`, the transport and parse accessors). `sdjwtvc.SdJwtVcPresentationOptions` has `LimitDisclosureToSelectedClaims` and `RequireRootClaimMatch`. `presenterTypes.PresentationRequest` has `ResponseMode`. The metadata types in `receiver/types` have new fields.
* `env.IsHTTPAllowed`, `env.SetHTTPAllowed` and `env.HTTP_ALLOWED` are removed, and `VCKNOTS_WALLET_HTTP_ALLOWED` is no longer read. Plain HTTP for a local test is [`experimental.Transport`](#experimental).
* The sentinel errors of the component packages (`keystore`, `credstore`, `presenter/types`, `common` and others) carry codes; `errors.Is` still matches them.
* `receiverTypes.SignatureAlgorithm` keeps a COSE algorithm identifier without a JWA name as its decimal text instead of failing, so an unknown `credential_signing_alg_values_supported` entry no longer makes the Credential Issuer Metadata unreadable.

## 7. Notes

1. **Mock key entries must not be used in production (CRITICAL):**
    - The in-memory key shown in this tutorial (and `MockKeyEntry` in `wallet/examples/common/`) keeps the private key in plaintext on the Go heap. Use it for tests and demonstrations only.
    - In production, implement `IKeyEntry` so that `Sign` is delegated to an OS keystore (iOS Secure Enclave, Android Keystore) or an HSM and the private key is never loaded into the application's memory.

2. **GOPRIVATE configuration:**
    - If `go mod download` or `go build` fails, the most likely cause is a missing GOPRIVATE environment variable.

3. **Persistent storage (bbolt):**
    - `credstore.WithDefaultConfig()` persists credentials to `<user config dir>/vcknots/wallet/.local_credstore.db`. The process must be able to create and write this directory.

4. **HTTPS enforcement:**
    - The wallet requires HTTPS for issuer and verifier endpoints. [`experimental.Transport`](#experimental) relaxes it for the issuer and `experimental.Presenter` for the verifier, for local development only.

5. **Strict validation of OpenID4VP `client_id`:**
    - The wallet validates `client_id` strictly. Duplicate prefixes (for example `x509_san_dns:x509_san_dns:...`), malformed values and the wallet-only prefixes are rejected.
    - For `x509_san_dns`, the certificate is taken from the `x5c` header of the Request Object and one of its DNS Subject Alternative Names must equal the `client_id` value.

6. **`experimental.Presenter.InsecureSkipX509Verify`:**
    - It skips certificate chain validation on the Draft 24 entry points, where only the binding and the signature are checked. The OpenID4VP 1.0 path refuses signed Request Objects while it is set, and HAIP refuses it.
    - ⚠️ Use it only for conformance testing or local development.

## 8. Troubleshooting

* **Q: `go mod download` fails with `package ... is private` or `404 Not Found`.**
  * **A:** The GOPRIVATE environment variable is not configured. See "1. Prerequisites" (or use mise).

* **Q: Receiving or presenting fails with `connection refused` or `timeout`.**
  * **A:** The Issuer/Verifier server is not running. Start it with `pnpm -F @trustknots/server start` and confirm that http://localhost:8080 responds.

* **Q: Receiving fails with `credential issuer must use https scheme`.**
  * **A:** The wallet requires HTTPS. For the local HTTP sample server, set `Config.Experimental.Transport.AllowHTTP`, or the `Experimental` field of the receiver, presenter and issuer key resolver you construct (see [experimental](#experimental)).

* **Q: Receiving fails with `issuer_metadata_fetch_failed`.**
  * **A:** Run `curl http://localhost:8080/.well-known/openid-credential-issuer` and confirm that JSON metadata is returned, and that its `credential_issuer` equals the identifier in the offer. For an identifier with a path, a 1.0 issuance reads `/.well-known/openid-credential-issuer/<path>` and a Draft 13 issuance `<path>/.well-known/openid-credential-issuer`; no other location is tried.

* **Q: A pre-authorized issuance fails with `client_authentication_unavailable`.**
  * **A:** The wallet found no usable client authentication for the token request, and the error message says why: the authorization server metadata omits `token_endpoint_auth_methods_supported` without declaring anonymous access, or does not list the configured method (`none` by default), or it lists `none` but does not set `pre-authorized_grant_anonymous_access_supported` to `true` (its default is `false`) and the wallet has no `client_id`. Configure `Config.ClientAuth` with a method the server advertises, set `Config.ClientAuth.ClientID`, or have the server declare anonymous access.

* **Q: An issuance fails with `credential_acceptance_policy_required`.**
  * **A:** Set `Config.CredentialAcceptance`, or the `Acceptance` of the `IssuanceRequest` or `PreAuthorizedIssuanceRequest` that starts the issuance. A state read back from JSON needs its `Acceptance` set again when `AcceptanceOverridden` is true. The policy must permit a mechanism that authenticates the issuer: `IssuerX509` for a credential with `x5c`, `IssuerKeys` for JWT VC Issuer Metadata or a DID bound by a DID Configuration, `Federation` for an OpenID Federation Entity. A test issuer is authenticated the same way, for example with its test CA in `IssuerX509`.

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
