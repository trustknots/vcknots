# vcknots-wallet Server Integration and Conformance Test Sample

This directory contains sample code that demonstrates two key testing scenarios for vcknots-wallet:

1. **Server Integration Test**: Tests integration with a local vcknots server
2. **Conformance Test**: Tests against external OID4VP conformance test services

Both modes are supported by the same program (`server_integration_sdjwt.go`) and are selected based on command-line arguments.

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
time=2025-11-27T14:03:25.066+09:00 level=INFO msg="=== Server Integration Test Mode ==="
time=2025-11-27T14:03:25.066+09:00 level=INFO msg="Starting server integration check...
...
time=2025-11-27T14:03:25.174+09:00 level=INFO msg="Credential presented successfully"
```

If `Credential presented successfully` appears, the sample succeeded.

---

### Mode 2: Conformance Test (External URL)

Tests against external OID4VP conformance test services.

#### How to Run

```bash
cd /path/to/vcknots/wallet
go run examples/server_integration_sdjwt/server_integration_sdjwt.go "openid4vp://authorize?client_id=...&request_uri=..."
```

**Important**: Providing an OID4VP URI as an argument automatically uses Conformance Test mode.

#### Differences in Behavior

Conformance Test mode automatically applies the following settings:

- **Certificate Verification**: Uses system root certificate pool with relaxed verification (`InsecureSkipX509Verify: true`)
- **Selected Claims**: Selects `given_name` and `family_name`
- **Key Binding**: Required (`RequireKeyBinding: true`)
- **Audience/Nonce**: Automatically extracted from the request URI

---

## About OID4VP Conformance Tests

### Enhanced client_id Validation

This wallet library implements strict `client_id` validation to comply with OID4VP conformance tests (https://openid.net/certification/).

#### Implemented Validation Logic

1. **Early Validation**
   - Validates `client_id` format **before** fetching the request object from `request_uri`
   - Returns an error immediately if invalid format is detected, without sending network requests
   - This prevents unnecessary network traffic and enhances security

2. **Duplicate Prefix Detection**
   - Rejects invalid formats like `x509_san_dns:x509_san_dns:demo.example.com`
   - Error message: `"invalid client_id: duplicate prefix detected"`

3. **Trailing Whitespace Trimming**
   - Normalizes `client_id` containing URL-encoded spaces (`%20`)
   - Example: `"x509_san_dns:demo.example.com "` → `"x509_san_dns:demo.example.com"`

4. **Certificate SAN Matching**
   - For `x509_san_dns:` scheme, extracts certificates from request JWT's `x5c` header
   - Matches certificate's Subject Alternative Name (SAN) DNS field with `client_id` value
   - Returns error on mismatch: `"SAN of the certificate and client_id did not match"`

5. **Certificate Verification Flexibility (for Conformance Tests)**
   - `InsecureSkipX509Verify` option allows skipping certificate chain verification in test environments
   - Supports conformance tests with self-signed certificates or non-standard certificate structures
   - ⚠️ **Warning**: This option should **NEVER** be used in production environments

#### Conformance Test Compliance

Conformance tests intentionally send invalid `client_id` values to test wallet validation logic:

```
client_id=x509_san_dns:x509_san_dns:demo.certification.openid.net 
```

In this example:
- The prefix `x509_san_dns:` is repeated twice
- Trailing whitespace (`%20`) is included

The updated wallet **correctly rejects** such invalid `client_id` values, thereby passing conformance tests.

#### Implementation Files

- Validation Logic: [internal/presenter/plugins/oid4vp/oid4vp.go](../internal/presenter/plugins/oid4vp/oid4vp.go)
  - `parseOID4VPClientID()` function (lines 528-565)
  - Early validation (lines 33-41): `client_id` validation before `request_uri` fetch
  - `x509_san_dns` validation (lines 339-410)
- Test Code: [internal/presenter/plugins/oid4vp/oid4vp_test.go](../internal/presenter/plugins/oid4vp/oid4vp_test.go)
  - `TestOid4vpPresenter_ClientIDParsingAndRedirectMismatch()`

#### Running Conformance Tests

To run conformance tests (https://openid.net/certification/):

1. Navigate to the wallet directory:
```bash
cd /path/to/vcknots/wallet
```

2. Run with the OID4VP URI obtained from the conformance test site:
```bash
go run examples/server_integration_sdjwt/server_integration_sdjwt.go "openid4vp://authorize?request_uri=https://demo.certification.openid.net/test/a/...&client_id=..."
```

**Note:** Providing an OID4VP URI as an argument automatically uses Conformance Test mode. Running without arguments uses Server Integration Test mode.

3. **Expected Behavior (Negative Test):**
   - For invalid `client_id` (e.g., duplicate prefix), the wallet immediately returns an error
   - Example error message: `invalid client_id in initial request: invalid client_id: duplicate prefix detected`
   - No network requests are sent
   - Conformance test confirms the wallet correctly rejected the request and marks it as PASS

#### Conformance Test Troubleshooting

##### `CheckIfClientIdInX509CertSanDns` Test Failure

**Error:**
```
FAILURE CheckIfClientIdInX509CertSanDns: x509_san_dns client_id is not present in the x5c certificate SAN
```

**Cause:**
- `X509TrustChainRoots` was set to `nil`
- Certificate verification was skipped, unable to detect invalid certificates

**Solution:**
Implemented in the `conformanceTestMode` function in [server_integration_sdjwt/server_integration_sdjwt.go](server_integration_sdjwt/server_integration_sdjwt.go):
```go
// Use system root certificate pool
systemRoots, err := x509.SystemCertPool()
if err != nil {
    logger.Warn("Failed to load system cert pool, creating empty pool", "error", err)
    systemRoots = x509.NewCertPool()
}

p := &oid4vp.Oid4vpPresenter{
    X509TrustChainRoots:    systemRoots,  // Use system roots, not nil
    InsecureSkipX509Verify: true,          // Relax certificate verification for conformance tests
}
```

**Note**: Use `InsecureSkipX509Verify: true` only in conformance test environments. Always set to `false` (or omit this field) in production.

##### Non-Standards Compliant Certificate Error

**Symptom:**
```
x509: "OIDF Test" certificate is not standards compliant
```

**Cause:**
- Conformance test server uses self-signed certificates
- Certificate structure does not strictly comply with x509 standards (for testing purposes)

**Solution:**
1. Enable `InsecureSkipX509Verify` option to skip certificate chain verification
2. This setting extracts certificates directly from x5c header and only validates SANs
3. ⚠️ **Warning**: Never use this setting in production environments

**How it Works:**
- `InsecureSkipX509Verify: false` (default): Full certificate chain verification using Go standard library
- `InsecureSkipX509Verify: true` (test only): Parse certificates directly from x5c, only validate SAN against `client_id`

##### Test Timeout or 400 Error

**Symptom:**
```
FAILURE: Got an HTTP request to '' that wasn't expected
INTERRUPTED: Test was interrupted before it could complete
```

**Cause:**
- Test session expired
- Ran the same URI multiple times

**Solution:**
1. Start a **new test session** on the conformance test site
2. Obtain a new URI with a new `request_uri`
3. Re-run the test with the new URI

---

## File Layout

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
