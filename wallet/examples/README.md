# vcknots-wallet Server Integration and Conformance Test Sample

This directory contains sample code that demonstrates two key testing scenarios for vcknots-wallet:

1. **Server Integration Test**: Tests integration with a local vcknots server
2. **Conformance Test**: Tests against external OID4VP conformance test services

Both modes are supported by the same program (`server_integration_sdjwt.go`) and are selected based on command-line arguments.
Both follow the same flow: seed credential → build wallet → get OID4VP request URI → present.

## Prerequisites

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

This automatically installs Go 1.24.5 and configures the necessary environment variables based on `mise.toml`.
If you prefer not to use mise, install Go 1.24.5 manually and set the `GOPRIVATE` environment variable:

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 3. Install dependencies

Install Go module dependencies:

```bash
go mod download
```

## How to Run the Sample

This sample program operates in two distinct modes:

### Mode 1: Server Integration Test (Recommended for First Run)

Tests integration with a local vcknots server.

#### Step 1: Start the Issuer and Verifier servers

The verifier server must be running to execute the sample. Move to the server directory and start the server:

```bash
# From the wallet directory, move to the vcknots root (/path/to/vcknots)
cd ../

# Install dependencies (if not done yet)
pnpm install

# Build the issuer+verifier module
pnpm -F @trustknots/vcknots build

# Build the server module
pnpm -F @trustknots/server build

# Start the server
pnpm -F @trustknots/server start
```

### Confirm the server is running

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

#### Step 2: Run the integration test script (no arguments)

Open a new terminal, navigate to each test directory, and run the server integration script:

```bash
# JWT-VC integration test
cd /path/to/vcknots/wallet/examples/server_integration_jwtvc
go run server_integration_jwtvc.go

# SD-JWT integration test
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go
```



### Step 3: Check the results

If everything works, you should see output similar to:

```
time=2025-11-27T14:03:25.066+09:00 level=INFO msg="Starting server integration check..."
time=2025-11-27T14:03:25.066+09:00 level=INFO msg="Fetching credential offer from server..."
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Received offer URL" url="openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%220d6386e621c740d1a02771312039efeb%22%7D%7D%7D"
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Decoded offer" offer="{\"credential_issuer\":\"http://localhost:8080\",\"credential_configuration_ids\":[\"UniversityDegreeCredential\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"0d6386e621c740d1a02771312039efeb\"}}}"
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Parsed credential offer" issuer=http://localhost:8080 configs=[UniversityDegreeCredential] grants=1
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Successfully imported demo credential via controller.ReceiveCredential" entry_id=0909df8b-cecb-4432-a047-a1a9c2dfc720 raw_length=808
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
time=2025-11-27T14:03:25.155+09:00 level=INFO msg="Authorization RequestURI" status="200 OK" body="openid4vp://authorize?client_id=x509_san_dns%3Alocalhost&request_uri=http%3A%2F%2Flocalhost%3A8080%2Frequest.jwt%2F9855a937fda74c3f8de9d7f92537206e"
time=2025-11-27T14:03:25.155+09:00 level=INFO msg="Request URI is valid" scheme=openid4vp
time=2025-11-27T14:03:25.174+09:00 level=INFO msg="Credential presented successfully"
```

If `Credential presented successfully` appears, the sample succeeded.

---

### Mode 2: Conformance Test (External URL)

Tests against external OID4VP conformance test services.
The conformance test URI can be obtained from the [OIDF Conformance Testing for OpenID for Verifiable Presentations](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/) page.
Click the `Testing a wallet` button to proceed.

#### How to Run

```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go "openid4vp://authorize?client_id=...&request_uri=..."
```

**Important**: Providing an OID4VP URI as an argument automatically uses Conformance Test mode.

#### Differences in Behavior

Conformance Test mode automatically applies the following settings:

- **Certificate Verification**: Uses system root certificate pool
- **Certificate Chain Verification Skip**: `InsecureSkipX509Verify: true` is automatically set, enabling communication with conformance test servers that use self-signed or non-standard certificates
- **Selected Claims**: Selects `given_name` and `family_name`
- **Key Binding**: Required (`RequireKeyBinding: true`)
- **Audience/Nonce**: Automatically extracted from the request URI

> ⚠️ **Warning**: `InsecureSkipX509Verify: true` should only be used in conformance tests and local development. **Never** use this in production environments.

---

## File Layout and Usage

### Integration Test Program

`server_integration_sdjwt/server_integration_sdjwt.go` operates in two modes:

**Mode 1: Server Integration Test (no arguments)**
```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go
```
- Tests integration with a local vcknots server
- Strict certificate verification (uses a specific certificate file)
- Server must be running on http://localhost:8080

**Mode 2: Conformance Test (with OID4VP URI argument)**
```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go "openid4vp://authorize?..."
```
- Tests against external OID4VP conformance test services
- Uses system root certificate pool
- `InsecureSkipX509Verify: true` is automatically set (supports non-standard certificates)

### File Structure

```
examples/
├── server_integration_jwtvc/
│   └── server_integration_jwtvc.go   # JWT-VC integration test
├── server_integration_sdjwt/
│   ├── server_integration_sdjwt.go   # SD-JWT integration test
│   └── example_sd_jwt.txt            # Sample SD-JWT credential
├── custom_dispatcher/                 # Example: custom dispatcher implementation
├── custom_plugin/                     # Example: custom plugin implementation
└── README.md                          # This file
```

**Note**: The certificate file and SD-JWT sample file are loaded using relative paths from each test directory. By default:
- Certificate: `../../../server/samples/certificate-openid-test/certificate_openid.pem`
- SD-JWT sample: `example_sd_jwt.txt` (in server_integration_sdjwt/)

If you need to use a different certificate, set the `VCKNOTS_CERT_PATH` environment variable:

```bash
cd /path/to/vcknots/wallet/examples/server_integration_jwtvc
VCKNOTS_CERT_PATH=/path/to/custom/cert.pem go run server_integration_jwtvc.go
```

---

## Troubleshooting

### `client_id` Validation Errors (Conformance Test)

The conformance test suite intentionally sends malformed `client_id` values to test the wallet's validation logic.

- **Example errors**:
  - `invalid client_id: duplicate prefix detected` (e.g., `x509_san_dns:x509_san_dns:...`)
  - `SAN of the certificate and client_id did not match`
- These errors are **expected behavior** and indicate the wallet is correctly enforcing security checks.

### `x509: certificate is not standards compliant` Error

Conformance test servers may use self-signed or non-standard certificate structures for testing purposes.

- **When running server integration test (no arguments)**: Check that the certificate file is correctly placed at `../../../server/samples/certificate-openid-test/certificate_openid.pem`, or specify it via `VCKNOTS_CERT_PATH`.
- **When running conformance test (with URI argument)**: `InsecureSkipX509Verify: true` is set automatically, so this error should not appear.
