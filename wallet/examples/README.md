# vcknots-wallet Local Server Integration Test and Conformance Test Sample

The [public Wallet API driver](official_driver/README.md) is a separate program
that drives the staged OpenID4VCI 1.0 and OpenID4VP 1.0 API, for example against
the OpenID Foundation conformance suite.

This directory contains sample code that demonstrates two key testing scenarios for vcknots-wallet:

1. **Local server integration test mode**: Tests integration with a local vcknots server
2. **Conformance test mode**: Tests against external OpenID4VP conformance test services

Both modes are supported by the same program (`server_integration_sdjwt.go`) and are selected based on command-line arguments.
In local server integration test mode, the wallet obtains a credential through OpenID4VCI and then presents it through OpenID4VP.
Conformance test mode seeds a local credential and tests only the OpenID4VP presentation flow.

## Features Covered by the Samples

| Sample | OpenID4VCI credential issuance | OpenID4VP presentation | Key binding |
| --- | --- | --- | --- |
| `server_integration_jwtvc` | JWT-VC | JWT-VC | Not applicable |
| `server_integration_sdjwt` | SD-JWT VC (`dc+sd-jwt`) | Selective disclosure | KB-JWT, because the DCQL query requires holder binding by default |
| `server_integration_sdjwt+kbjwt` | SD-JWT VC (`dc+sd-jwt`) | Selective disclosure | With KB-JWT |

Regardless of the credential format shown above, every local server integration test mode sample uses `private_key_jwt` client authentication and DPoP.

## Wallet API used by the samples

The samples receive credentials with the OpenID4VCI 1.0 staged API (`ParseCredentialOfferURL` or `ResolveCredentialOffer`, `AuthorizePreAuthorizedIssuance` and `RequestCredential`, Pre-Authorized Code Flow) and present them with the OpenID4VP 1.0 staged API (`ParsePresentationRequest`, `SelectCredentials` and `SubmitPresentation`), which `common.PresentAll` runs in a row.
A wallet with a user asks for the holder's consent between `SelectCredentials` and `SubmitPresentation`, which the samples skip, and also uses `BeginIssuance` and `AuthorizeIssuance` for the Authorization Code Flow.
The [wallet guide](../../docs/en/wallet.md) describes that API, the supported protocols, the HAIP profile and the security defaults, and the [public Wallet API driver](official_driver/README.md) shows a complete configuration.

The samples set `Config.CredentialAcceptance` from `common.SampleIssuerAcceptance`, and `RequestCredential` stores a credential only after that policy authenticated its issuer.
The OpenID4VCI methods refuse to run without an acceptance policy.

## Prerequisites

Local server integration test mode requires Node.js and pnpm in addition to Go.
Conformance test mode does not require the local Node.js server.

### 1. Install mise

The wallet package uses [mise](https://mise.jdx.dev/) for development environment management.
If mise is not installed, please install it first.

Example:
```bash
# macOS
brew install mise

# Install via curl
curl https://mise.jdx.dev/install.sh | sh
```

### 2. Set up the environment

Move to the project directory and set up the environment:

```bash
cd /path/to/vcknots/wallet
mise install
```

This automatically installs Go 1.26.6 and configures the necessary environment variables based on `mise.toml`.
If you prefer not to use mise, install Go 1.26.6 manually and set the `GOPRIVATE` environment variable:

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 3. Install dependencies

Install Go module dependencies:

```bash
go mod download
```

## How to Run the Sample

`server_integration_sdjwt` is the sample that operates in two modes. The other two support the local server integration test mode only.

| Sample | Supported modes | Command-line arguments |
| --- | --- | --- |
| `server_integration_sdjwt` | Both modes | Positional OpenID4VP URI, `--credential-offer-uri`, `--tx-code` |
| `server_integration_jwtvc` | Local server integration test mode only | `--credential-offer-uri`, `--tx-code` |
| `server_integration_sdjwt+kbjwt` | Local server integration test mode only | None |

### Mode 1: Local Server Integration Test Mode (Recommended for First Run)

Tests integration with a local vcknots server.

#### Step 1: Start the Issuer, Authorization Server, and Verifier

The local server runs as **a single process** and provides all three roles together at `http://localhost:8080`. You do not need to start them separately.

| Role | Responsibility | Main endpoints |
| --- | --- | --- |
| Issuer | Issues credentials | `/configurations/:configuration/offer`, `/credentials`, `/.well-known/openid-credential-issuer`, `/.well-known/jwt-vc-issuer` |
| Authorization Server | Issues access tokens | `/token`, `/.well-known/oauth-authorization-server` |
| Verifier | Verifies presented credentials | `/request`, `/request-object`, `/request.jwt/:request-object-Id`, `/callback` |

Move to the repository root and start it:

```bash
# From the wallet directory, move to the vcknots root (/path/to/vcknots)
cd ../

# Install dependencies (if not done yet)
pnpm install

# Build the issuer+verifier module
pnpm -F @trustknots/vcknots build

# Build the server-core module
pnpm -F @trustknots/server-core build

# Build the server module
pnpm -F @trustknots/server build

# Start the server
pnpm -F @trustknots/server start
```

#### Confirm the server is running

When the server starts, you should see output similar to:

```
> @trustknots/server@0.1.0 start /path/to/vcknots/server/single
> tsx src/example.ts

POST  /configurations/:configuration/offer
        [handler]
POST  /credentials
        [handler]
GET   /.well-known/openid-credential-issuer
        [handler]
GET   /.well-known/jwt-vc-issuer
        [handler]
POST  /token
        [handler]
GET   /.well-known/oauth-authorization-server
        [handler]
POST  /request
        [handler]
POST  /callback
        [handler]
POST  /request-object
        [handler]
GET   /request.jwt/:request-object-Id
        [handler]
Server is running on http://localhost:8080
Verifier metadata initialized for http://localhost:8080
Issuer metadata initialized
Authz metadata initialized
```

By default the server listens on `http://localhost:8080`.
The test scripts also use this URL.

#### Client authentication in local server integration test mode

The local server integration test mode samples use `private_key_jwt` for client authentication and enable DPoP. The token request therefore includes:

| Location | Name | Value |
| --- | --- | --- |
| Form parameter | `client_id` | `test-client-id` |
| Form parameter | `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| Form parameter | `client_assertion` | An ES256-signed JWT |
| HTTP header | `DPoP` | A DPoP proof JWT (RFC 9449) |

The samples read this registration from `examples/config/`, which the wallet loads with the `wallet/clientconfig` package:

| File | Contents |
| --- | --- |
| `examples/config/wallet-clients.json` | Client metadata: `client_id`, `token_endpoint_auth_method`, `token_endpoint_auth_signing_alg`, `client_assertion_audience`, and the public `jwks` |
| `examples/config/client-private.sample.jwks.json` | The matching private JWK used to sign the `client_assertion` |

```go
import (
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/clientconfig"
)

func newClientWallet() (*wallet.Wallet, error) {
	clientAuth, err := clientconfig.Load(
		"../config/wallet-clients.json",
		clientconfig.WithClientID("test-client-id"),
		clientconfig.WithPrivateJWKFile("../config/client-private.sample.jwks.json"),
	)
	if err != nil {
		return nil, err
	}
	return wallet.NewWalletWithConfig(wallet.Config{ClientAuth: clientAuth})
}
```

The two files are kept apart on purpose. OpenID Connect Dynamic Client Registration 1.0 states that a `jwks` member MUST NOT contain private key values, so `wallet-clients.json` holds public keys only and can be handed to the authorization server as-is. `clientconfig.Load` rejects a `jwks` that carries a private key, and requires the private JWK file to be mode `0600`.

The public key in `examples/config/wallet-clients.json` is the one registered for `test-client-id` in `server/samples/oauth-clients.json`. The authorization server metadata in `server/samples/authorization_metadata.json` explicitly advertises both `private_key_jwt` and ES256; the wallet uses this authentication method only when both are advertised.

Configuring the wallet in Go is equally supported: `clientconfig.Load` returns a `wallet.ClientAuthConfig`, which you pass through `wallet.Config.ClientAuth` yourself. Keys that cannot be exported into a file, such as those held in an HSM or a secure enclave, are supplied with `clientconfig.WithKeyEntry`.

> ⚠️ **Warning**: The sample private key is committed so that the examples run straight after a clone, which is also why they pass `clientconfig.AllowInsecureFilePermissions()`. It is for this local sample only. In a real deployment generate a separate key, keep it out of the repository with mode `0600`, and register its public JWK with the authorization server.

#### Step 2: Run the integration test script (no arguments)

Open a new terminal, navigate to each test directory, and run the local server integration test mode script:

```bash
# JWT-VC integration test
cd /path/to/vcknots/wallet/examples/server_integration_jwtvc
go run server_integration_jwtvc.go

# SD-JWT integration test (key binding from the DCQL query)
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go

# SD-JWT integration test (with kb-jwt)
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt+kbjwt
go run server_integration_sdjwt_kbjwt.go
```

Set `VCKNOTS_SERVER_URL` when the server is not running on `http://localhost:8080`:

```bash
VCKNOTS_SERVER_URL=http://localhost:18080 go run server_integration_sdjwt.go
```

To run against an offer URI created separately, pass it via `--credential-offer-uri`. If the offer requires a transaction code, also pass `--tx-code` (`--tx_code` is also accepted).

```bash
OFFER_URI='openid-credential-offer://?...'
go run server_integration_sdjwt.go --credential-offer-uri "$OFFER_URI" --tx-code 123456
```



#### Step 3: Check the results

If everything works, you should see output similar to:

```
time=2025-11-27T14:03:25.066+09:00 level=INFO msg="Starting server integration check..."
time=2025-11-27T14:03:25.066+09:00 level=INFO msg="Fetching credential offer from server..."
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Received offer URL" url="openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%220d6386e621c740d1a02771312039efeb%22%7D%7D%7D"
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Decoded offer" offer="{\"credential_issuer\":\"http://localhost:8080\",\"credential_configuration_ids\":[\"UniversityDegreeCredential\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"0d6386e621c740d1a02771312039efeb\"}}}"
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Parsed credential offer" issuer=http://localhost:8080 configs=[UniversityDegreeCredential] grants=1
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Successfully imported demo credential via wallet.RequestCredential" entry_id=0909df8b-cecb-4432-a047-a1a9c2dfc720 raw_length=808
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="=== Received Credential Details ==="
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential Entry ID" id=0909df8b-cecb-4432-a047-a1a9c2dfc720
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential MimeType" mime_type=application/vc+jwt
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential Received At" received_at=2025-11-27T14:03:25.143+09:00
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential Raw Content" raw=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC92Yy83ZWE5MjI1YmMxZDM0ZmUxOWJkYmYwOWU4NjhkYjRmMSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJpc3N1YW5jZURhdGUiOiIyMDI1LTExLTI3VDA1OjAzOjI1LjE0MloiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSIsImdpdmVuX25hbWUiOiJ0ZXN0IiwiZmFtaWx5X25hbWUiOiJ0YXJvIiwiZGVncmVlIjoiNSIsImdwYSI6InRlc3QifX0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInN1YiI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.Qd1dNQbpoRvpfkWF8m2z-EVvo8dZ3IM4gtlN2JTvoqnh8TDoXegh0OBC6gO6FwpODxf7m_IO_PhR1WnhztHC2Q
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Stored credentials" count=2 total=2
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Verifier Details" URL=http://localhost:8080
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Using received credential for presentation" credential_id=0909df8b-cecb-4432-a047-a1a9c2dfc720
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Decoding received credential JWT"
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Decoded credential" credential="map[iss:http://localhost:8080 sub:did:key:zDnaeYiwHNeMYaj21Wo9jPCowtnBrY8he8UCK8ZZN1mhhx8PM vc:map[@context:[https://www.w3.org/2018/credentials/v1] credentialSubject:map[degree:5 family_name:taro given_name:test gpa:test id:did:key:zDnaeYiwHNeMYaj21Wo9jPCowtnBrY8he8UCK8ZZN1mhhx8PM] id:http://localhost:8080/vc/7ea9225bc1d34fe19bdbf09e868db4f1 issuanceDate:2025-11-27T05:03:25.142Z issuer:http://localhost:8080 type:[VerifiableCredential UniversityDegreeCredential]]]"
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential analysis" types="[VerifiableCredential UniversityDegreeCredential]" subject_fields="[gpa id given_name family_name degree]"
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Generated presentation definition" json="{\n\t\t\"query\": {\n\t\t\t\"presentation_definition\": {\n\t\t\t\"id\": \"dynamic-presentation-UniversityDegreeCredential\",\n\t\t\t\"input_descriptors\": [\n\t\t\t{\n\t\t\t\t\"id\": \"credential-request\",\n\t\t\t\t\"name\": \"UniversityDegreeCredential\",\n\t\t\t\t\"purpose\": \"Verify credential\",\n\t\t\t\t\"format\": {\n\t\t\t\t\"jwt_vc_json\": {\n\t\t\t\t\t\"alg\": [\"ES256\"]\n\t\t\t\t}\n\t\t\t\t},\n\t\t\t\t\"constraints\": {\n\t\t\t\t\"fields\": [\n\t\t{\n\t\t\t\"path\": [\"$.type\"],\n\t\t\t\"filter\": {\n\t\t\t\t\"type\": \"array\",\n\t\t\t\t\"contains\": {\"const\": \"UniversityDegreeCredential\"}\n\t\t\t}\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.gpa\"],\n\t\t\t\"intent_to_retain\": false\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.given_name\"],\n\t\t\t\"intent_to_retain\": false\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.family_name\"],\n\t\t\t\"intent_to_retain\": false\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.degree\"],\n\t\t\t\"intent_to_retain\": false\n\t\t}\n\t]\n\t\t\t\t}\n\t\t\t}\n\t\t\t]\n\t\t}\n\t\t},\n\t\t\"state\": \"example-state\",\n\t\t\"base_url\": \"http://localhost:8080\",\n\t\t\"is_request_uri\": true,\n\t\t\"response_uri\": \"http://localhost:8080/callback\",\n\t\t\"client_id\": \"x509_san_dns:localhost\"\n\t}"
time=2025-11-27T14:03:25.155+09:00 level=INFO msg="Authorization RequestURI" status="200 OK" body="openid4vp:?client_id=x509_san_dns%3Alocalhost&request_uri=http%3A%2F%2Flocalhost%3A8080%2Frequest.jwt%2F9855a937fda74c3f8de9d7f92537206e"
time=2025-11-27T14:03:25.155+09:00 level=INFO msg="Request URI is valid" scheme=openid4vp
time=2025-11-27T14:03:25.174+09:00 level=INFO msg="Credential presented successfully"
```

If `Credential presented successfully` appears, the sample succeeded.
Reaching this point also means that the authorization server accepted the client assertion and DPoP proof used to obtain the access token.

---

For SD-JWT VC, `SubmitPresentation` attaches a Key Binding JWT when the answered DCQL query requires cryptographic holder binding (`require_cryptographic_holder_binding`, default `true`) or when `SdJwtVcPresentationOptions.RequireKeyBinding` is set; the options cannot remove a required one. A query that requires holder binding is not answered with a credential that has no `cnf`.

### Mode 2: Conformance Test Mode (External URL)

Tests against external OpenID4VP conformance test services.
The conformance test URI can be obtained from the [OIDF Conformance Testing for OpenID for Verifiable Presentations](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/) page.
Click the `Testing a wallet` button to proceed.

#### How to Run

```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go "openid4vp:?client_id=...&request_uri=..."
```

**Important**: Providing an OpenID4VP URI as an argument automatically uses Conformance Test mode.

#### Differences in Behavior

Conformance Test mode automatically applies the following settings:

- **Credential**: The SD-JWT VC in `example_sd_jwt.txt` is stored and presented
- **Certificate Verification**: The system root certificate pool is set as `X509TrustChainRoots`
- **Trust anchors**: The system roots plus the PEM file named by `VCKNOTS_CONFORMANCE_CA_PATH`, if set. Point it at the suite's root certificate so signed Request Objects are authenticated against it.
- **Selected Claims**: `given_name`
- **Key Binding**: Required (`RequireKeyBinding: true`)
- **Audience/Nonce**: Taken from the request
- **OpenID4VCI Client Authentication and DPoP**: Not configured; this mode tests the OpenID4VP presentation flow only


### OpenID4VCI Conformance Test (`conformance_sdjwt`)

Tests the flow that receives an SD-JWT VC against an external OpenID4VCI conformance test service. This is a separate program from the two modes above and targets the OIDF Conformance Suite test plan `OpenID for Verifiable Credential Issuance 1.0 Final/HAIP: Test a Wallet`.

#### Test Plan Settings

Select the test plan variants as follows.

| Variant | Value |
| --- | --- |
| `credential_format` | `sd_jwt_vc` |
| `vci_grant_type` | `pre_authorization_code` |
| `vci_authorization_code_flow_variant` | `issuer_initiated` |
| `vci_credential_offer_variant` | `by_value` or `by_reference` |
| `client_auth_type` | `private_key_jwt` |
| `sender_constrain` | `dpop` or `none` |

Under `client` in the configuration, register the same `client_id` and public key as `config/wallet-clients.json`.

```json
"client": {
  "client_id": "test-client-id",
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": "client-key-1",
        "x": "ezZgKwMueAyZLHUgSpzNkbOWDgjJXTAOJn8MftOnayQ",
        "y": "Fy_U4KyZQf-9jKpFJtH6OFFRXmwAcveyfuoDp1hSOFo"
      }
    ]
  }
}
```

#### How to Run

When you start a test module, the suite displays an offer URI beginning with `openid-credential-offer://`. Pass it as the argument.

```bash
cd /path/to/vcknots/wallet/examples/conformance_sdjwt
OID4VCI_CLIENT_CONFIG=../config/wallet-clients.json \
OID4VCI_CLIENT_PRIVATE_JWK=../config/client-private.sample.jwks.json \
OID4VCI_CLIENT_ASSERTION_AUDIENCE= \
OID4VCI_ALLOW_INSECURE_KEY_PERMS=1 \
OID4VCI_DPOP=1 \
go run conformance_sdjwt.go "openid-credential-offer://?credential_offer=..."
```

| Environment variable | Required | Description |
| :---- | :---- | :---- |
| `OID4VCI_CLIENT_CONFIG` | Yes | Client registration file. When unset, the authentication method defaults to `none`, and because the suite accepts only `private_key_jwt`, the wallet stops with an error before sending the Token Request. |
| `OID4VCI_CLIENT_PRIVATE_JWK` | Yes | Private key file used to sign the `client_assertion`. |
| `OID4VCI_CLIENT_ASSERTION_AUDIENCE` | Yes, as an empty string, when using the sample configuration | `config/wallet-clients.json` pins `client_assertion_audience` to `https://authz.example.com` for local testing. An empty string removes that override, so `aud` becomes the suite's issuer. Without it, the token endpoint reports `aud mismatch`. |
| `OID4VCI_ALLOW_INSECURE_KEY_PERMS` | Yes, unless the key file is mode 0600 | The private key file must be mode 0600 by default. The sample key checked out from the repository is 0644, so set this to `1` or run `chmod 600`. |
| `OID4VCI_DPOP` | When `sender_constrain=dpop` | Set to `1` to enable DPoP. Leave it unset for a `none` test plan. |
| `OID4VCI_CLIENT_ID` | No | Selects a client when the configuration file lists more than one. The sample has one, so it is not needed. |
| `OID4VCI_TX_CODE` | No | Specifies the `tx_code` (the second argument also works). The suite's offer includes `<123456>` in its description, so it is normally extracted automatically. |

> ⚠️ **Warning**: The private key in `config/client-private.sample.jwks.json` is public in this repository. Use it only for conformance tests and local testing.

#### Checking the Results

A successful run ends as **FINISHED / PASSED** in the suite. Check the individual behaviours in the JSON log exported from the suite (point `F` at that file).

```bash
F=test-log-oid4vci-1_0-wallet-test-credential-issuance-<test id>.json

# 1. The order of the endpoints that were reached
jq -r '.results[]|select(.incoming_path!=null)|.incoming_path|sub(".*/";"")' "$F" | nl

# 2. The DPoP nonce decision at the credential endpoint
jq -r '.results[]|select(.src=="ValidateResourceEndpointDpopProofNonce")|[(.result//"NO-RESULT"),.msg]|@tsv' "$F"

# 3. The nonce each request carried in its DPoP proof
jq -r '.results[]|select(.src=="ExtractDpopProofFromHeader")|.claims|[(.htu|sub(".*/";"")),(.nonce//"(none)")]|@tsv' "$F"

# 4. The claims of the key proof in the Credential Request
jq -r '.results[]|select(.src=="VCIExtractCredentialRequestProof")|(.proof_jwts//empty)[].claims' "$F"

# 5. The final state of the module
jq -r '.testInfo|[.status,(.result//"null")]|@tsv' "$F"
```

A successful run with `sender_constrain=dpop` looks like this.

| # | Expected output |
| :---- | :---- |
| 1 | The last five lines are `token`, `token`, `nonce`, `credential`, `credential` (the earlier ones are the offer and metadata fetches). After the 401 (`use_dpop_nonce`) the credential endpoint is retried at `/credential`. Going back to `/nonce` means the DPoP nonce is taken from the wrong place |
| 2 | The third line is `SUCCESS` / `Resource endpoint DPoP nonce matches expected value` |
| 3 | Two `credential` lines, the second carrying the same value as the `DPoP-Nonce` of the 401 response |
| 4 | `aud` (the Credential Issuer Identifier including its trailing slash), `iss` (the `client_id`), `iat`, `nonce` |
| 5 | `FINISHED` / `PASSED` |

- The first `/credential` is rejected at the DPoP layer, so the suite never validates the key proof and the `c_nonce` is not consumed. The retry can therefore send the same key proof unchanged.
- The suite checks the `aud` of the key proof but not its `iss`. Confirm `iss` in the output of 4.
- If the wallet stops before sending the Token Request, the reason does not appear in the suite's log. It appears only in the wallet's output (`Failed to obtain an access token`).

---

## OpenID4VP Conformance Test (Independent of OpenID4VCI, Recommended)

This uses `conformance_sdjwt/conformance_sdjwt.go`. It does **not require running the
OpenID4VCI test first**, so OpenID4VP can be verified on its own.

### Before You Start

`conformance_sdjwt.go` switches behaviour on the scheme of its first argument.

| Argument | Behaviour |
|---|---|
| `openid-credential-offer://...` | OpenID4VCI: receive a credential and store it |
| `openid4vp://...` | OpenID4VP: present a stored credential |
| anything else | Treated as a path to an SD-JWT VC and loaded into the store |

The credential store persists at `$(os.UserConfigDir())/vcknots/wallet/.local_credstore.db`.
Load it once and every module of the test plan can use it.

> **Note**: `server_integration_sdjwt` deletes this credential store on startup.
> Load the credential again after running it.

### Step 1: Create the Test Plan

On the [OIDF Conformance Suite](https://www.certification.openid.net/), create a
`OpenID for Verifiable Presentations 1.0 Final: Test a wallet` plan with these variants.

| Field | Value | Reason |
|---|---|---|
| Credential Format | `sd_jwt_vc` | |
| Client Id Prefix | `x509_san_dns` | This example verifies the signed Request Object's certificate against the configured CA. |
| Request Method | `request_uri_signed` | Fetches the signed Request Object from `request_uri`. |
| VP Profile | `plain_vp` | |
| Response Mode | `direct_post` | This example accepts a URI and posts the response over HTTP. Digital Credentials API calls use separate entrypoints. |

### Step 2: Configure the Test Plan JSON

```json
{
    "alias": "<your plan name>",
    "description": "vcknots Wallet OID4VP SD-JWT VC conformance test",
    "server": {
        "authorization_endpoint": "openid4vp://authorize"
    },
    "client": {
        "dcql": {
            "credentials": [
                {
                    "id": "pid_credential",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["<vct of the credential you present>"] },
                    "claims": [
                        { "path": ["given_name"] },
                        { "path": ["family_name"] },
                        { "path": ["birthdate"] }
                    ]
                }
            ]
        },
        "jwks": { "keys": [ "<JWK with the private d and an x5c, generated below>" ] }
    }
}
```

**Leave `client.client_id` unset.** The suite then derives `x509_san_dns:<hostname>` from
the response_uri hostname. A value that already carries the prefix makes it appear twice,
and the wallet rejects it with `invalid client_id: duplicate prefix detected`.

**`client.jwks` is required and must contain a private key.** The suite signs the Request
Object with it, so a public-only key stops at `ValidateClientJWKsPrivatePart`. With
`x509_san_dns`, the dNSName SAN of the x5c leaf certificate must also match the client_id.

Create a test CA and a separate signing certificate for the suite's hostname. The wallet rejects a self-signed signing certificate.

```bash
cat > vp_client.cnf <<'CNF'
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = <suite hostname>
[v3]
subjectAltName = DNS:<suite hostname>
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
CNF

openssl ecparam -name prime256v1 -genkey -noout -out vp_client_key.pem
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout vp_ca_key.pem -out vp_ca_cert.pem -days 3650 -subj '/CN=VP Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -new -key vp_client_key.pem -out vp_client.csr -config vp_client.cnf
openssl x509 -req -in vp_client.csr -CA vp_ca_cert.pem -CAkey vp_ca_key.pem \
  -CAcreateserial -out vp_client_cert.pem -days 365 -extfile vp_client.cnf -extensions v3
```

Convert it to a JWK for `client.jwks`. Note that `x5c` alone is standard base64, not base64url.

```bash
b64url() { xxd -r -p | base64 | tr '+/' '-_' | tr -d '=\n'; }
txt=$(openssl ec -in vp_client_key.pem -text -noout 2>/dev/null)
hexpriv=$(printf '%s\n' "$txt" | sed -n '/priv:/,/pub:/p' | grep -v 'priv:\|pub:' | tr -d ' :\n')
hexpub=$(printf '%s\n' "$txt" | sed -n '/pub:/,/ASN1 OID/p' | grep -v 'pub:\|ASN1' | tr -d ' :\n')
[ ${#hexpriv} -eq 66 ] && hexpriv=${hexpriv:2}

echo "x   = $(printf '%s' "${hexpub:2:64}" | b64url)"
echo "y   = $(printf '%s' "${hexpub:66:64}" | b64url)"
echo "d   = $(printf '%s' "$hexpriv" | b64url)"
echo "x5c = $(openssl x509 -in vp_client_cert.pem -outform DER | base64 | tr -d '\n')"
```

Combine those with `kty: EC` / `crv: P-256` / `alg: ES256` / `use: sig` / `kid: <any>`
into a single JWK.

> ⚠️ **Warning**: This key and certificate are for conformance testing only.
> They contain the private key `d`, so never commit them to the repository.

### Step 3: Load a Credential into the Credential Store

```bash
cd /path/to/vcknots/wallet
go run ./examples/conformance_sdjwt ./examples/server_integration_sdjwt/example_sd_jwt.txt
```

`example_sd_jwt.txt` works as is because its `cnf` holds the public key of
`common.NewMockKeyEntry()`. **Any other credential needs that same key, or the Key Binding
JWT fails.**

The wallet selects credentials and disclosures matching DCQL. Match the test plan's `vct` and claims to the imported credential.

### Step 4: Run the Module

Start `oid4vp-1final-wallet-happy-flow` in the test plan. It moves to `WAITING` and shows an
`openid4vp://authorize?...` URI. Copy it and run:

```bash
cd /path/to/vcknots/wallet
VCKNOTS_CONFORMANCE_CA_PATH=/path/to/vp_ca_cert.pem \
  go run ./examples/conformance_sdjwt "openid4vp://authorize?client_id=...&request_uri=..."
```

**Always quote the URI** since it contains `?` and `&`.

The run logs the `vct` and the disclosure names of the stored credential. Align the
test plan's dcql with those values. The list is flat, so a nested claim appears under its
own name (`18` sits under `age_equal_or_over`, `locality` under `place_of_birth`). Use a
top-level name in the dcql, or give a nested one its full path, such as
`["place_of_birth", "locality"]`.

```
level=INFO msg="Stored credential" id=... vct=urn:eu.europa.ec.eudi:pid:1 disclosures="[family_name given_name birthdate ...]"
level=INFO msg="=== Credential Presented ==="
```

### Verification scope

This example verifies signed Request Objects and responds with credentials and disclosures matching DCQL.
Set `VCKNOTS_CONFORMANCE_CA_PATH` to the test CA and put its separately signed leaf certificate
in the `x5c` of `client.jwks`. Test certificates without revocation endpoints are accepted;
their certificate chain is still verified. Check each external suite module's result in its run log.

---

## File Layout and Usage

### Integration Test Program

`server_integration_sdjwt/server_integration_sdjwt.go` operates in two modes:

**Mode 1: Local server integration test mode (no arguments)**
```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go
VCKNOTS_SERVER_URL=http://localhost:18080 go run server_integration_sdjwt.go
go run server_integration_sdjwt.go --credential-offer-uri "$OFFER_URI" --tx-code 123456
```
- Tests integration with a local vcknots server
- Strict certificate verification (uses a specific certificate file)
- Server must be running on http://localhost:8080
- `--tx-code` is optional and is forwarded to the OpenID4VCI token request as `tx_code`
- `--credential-offer-uri` skips fetching a new offer and uses the provided OpenID4VCI offer URI

**Mode 2: Conformance test mode (with OpenID4VP URI argument)**
```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go "openid4vp:?..."
```
- Tests against external OpenID4VP conformance test services
- Uses system root certificate pool
- Signed Request Objects are authenticated against the system roots and `VCKNOTS_CONFORMANCE_CA_PATH`

### File Structure

```
examples/
├── common/                            # Shared sample setup (wallet construction, mock key)
├── config/
│   ├── wallet-clients.json            # Client authentication metadata (public keys only)
│   └── client-private.sample.jwks.json # Sample client_assertion signing key (local use only)
├── server_integration_jwtvc/
│   └── server_integration_jwtvc.go   # JWT-VC integration test
├── server_integration_sdjwt/
│   ├── server_integration_sdjwt.go   # SD-JWT integration test (key binding from the DCQL query)
│   └── example_sd_jwt.txt            # Sample SD-JWT credential
├── server_integration_sdjwt+kbjwt/
│   ├── server_integration_sdjwt_kbjwt.go # SD-JWT integration test with kb-jwt
│   └── example_sd_jwt.txt                 # Sample SD-JWT credential
├── conformance_sdjwt/
│   └── conformance_sdjwt.go          # OpenID4VCI conformance test (receiving an SD-JWT VC)
├── custom_dispatcher/                 # Example: custom dispatcher implementation
├── custom_plugin/                     # Example: custom plugin implementation
├── official_driver/                   # Public Wallet API driver (staged API, JSON in/out)
├── README.md                          # This file
└── README.ja.md                       # Japanese version
```

**Note**: The certificate file and SD-JWT sample file are loaded using relative paths from each test directory. By default:
- Certificate: `../../../server/samples/certificate-openid-test/certificate_openid.pem`
- SD-JWT sample: `example_sd_jwt.txt` (in server_integration_sdjwt/)

For KB-JWT verification, use the `server_integration_sdjwt+kbjwt` sample. It requests `dc+sd-jwt`, posts to `http://localhost:8080/callback-kbjwt`, and includes a fixed nonce plus KB-JWT audience matching `x509_san_dns:localhost`.

If you need to use a different certificate, set the `VCKNOTS_CERT_PATH` environment variable:

```bash
cd /path/to/vcknots/wallet/examples/server_integration_jwtvc
VCKNOTS_CERT_PATH=/path/to/custom/cert.pem go run server_integration_jwtvc.go
```

### Issuer authentication

The wallet stores a received credential only once its issuer is authenticated by a mechanism the specifications define (`common.SampleIssuerAcceptance`). The local sample server publishes JWT VC Issuer Metadata at `/.well-known/jwt-vc-issuer`, which authenticates its SD-JWT VCs. A credential that carries `x5c` is authenticated by its certificate chain only: set `VCKNOTS_ISSUER_CA_PATH` to a PEM file of the issuer's certificate authorities (the conformance suite's issuer, for `conformance_sdjwt`). JWT VC Issuer Metadata is defined for SD-JWT VC only, so a `jwt_vc_json` credential (`server_integration_jwtvc`) needs `x5c`, a DID bound by a DID Configuration, or OpenID Federation; without one it is refused.

### Wallet Runtime Environment Variables

In addition to `VCKNOTS_CERT_PATH`, the wallet reads the environment variables defined in `wallet/env/env.go`.

| Variable | Default | Description |
| :---- | :---- | :---- |
| `VCKNOTS_WALLET_DEBUG` | `false` (unset/empty) | Enables debug logging only. It does not relax the HTTPS requirement. |

No environment variable allows plain HTTP. The local server integration test mode samples build their wallet with `common.NewOID4VPRuntime(certPath, true)`, which sets `experimental.Transport{AllowHTTP: true}` on the OpenID4VCI receiver and the issuer key resolver, and `experimental.Presenter{Transport: ...}` on the OpenID4VP presenter. The package `github.com/trustknots/vcknots/wallet/experimental` holds every such test-only departure from the specifications. A client assertion is still sent over plain HTTP only to a loopback host.

> ⚠️ **Security warning**: Do not allow plain HTTP in production. HAIP refuses it.

---

## Troubleshooting

### `client_id` Validation Errors (Conformance Test Mode)

The conformance test suite intentionally sends malformed `client_id` values to test the wallet's validation logic.

- **Example errors**:
  - `invalid client_id: duplicate prefix detected` (e.g., `x509_san_dns:x509_san_dns:...`)
  - `SAN of the certificate and client_id did not match`
- These errors are **expected behavior** and indicate the wallet is correctly enforcing security checks.

### `x509: certificate is not standards compliant` Error

Conformance test servers may use self-signed or non-standard certificate structures for testing purposes.

- **When running local server integration test mode (no arguments)**: Check that the certificate file is correctly placed at `../../../server/samples/certificate-openid-test/certificate_openid.pem`, or specify it via `VCKNOTS_CERT_PATH`.
- **When running conformance test mode (with URI argument)**: set `VCKNOTS_CONFORMANCE_CA_PATH` to the suite's root certificate so its signed Request Objects are trusted.

### `Couldn't find DPoP Proof header` (Conformance Test Mode)

Running against a `sender_constrain=dpop` test plan without setting `OID4VCI_DPOP=1` makes the token endpoint report `ExtractDpopProofFromHeader: Couldn't find DPoP Proof header`, and the test ends as INTERRUPTED.

- The wallet does not notice that it sent no DPoP and reports no error, so this is visible only in the suite's log.
- Re-run with `OID4VCI_DPOP=1`. For a `sender_constrain=none` test plan, leave it unset instead.
