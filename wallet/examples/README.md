# vcknots-wallet Server Integration Sample

This directory contains sample code that demonstrates how to integrate vcknots-wallet with the verifier server.

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

### Step 1: Start the Issuer and Verifier servers

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
The test script below also uses this URL.

### Step 2: Run the integration test script

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
...
time=2025-11-27T14:03:25.174+09:00 level=INFO msg="Credential presented successfully"
```

If `Credential presented successfully` appears, the sample succeeded.

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
