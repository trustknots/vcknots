# Google Cloud Server

Single-tenant server implementation with Google Cloud / Firebase integration. Provides a server that integrates Issuer, Authorization Server, and Verifier functionality using the VCKnots library.

Shared app/routes/server/util implementations are provided by `@trustknots/server-core`.

## Overview

This server is implemented based on the OID4VCI (OpenID for Verifiable Credential Issuance) and OID4VP (OpenID for Verifiable Presentations) specifications.

It uses Firebase Admin SDK and Firestore provider integration (`@trustknots/google-cloud`) for backend storage.

## Actual API Specifications

For **actual API specifications, parameters, type definitions, and usage examples** for Issuer, Authorization Server, and Verifier, please refer to the following official documentation:

- **Issuer**: [Issuer Setup and Usage Guide](https://trustknots.github.io/vcknots/docs/issuer)
- **Verifier**: [Verifier Setup and Usage Guide](https://trustknots.github.io/vcknots/docs/verifier)

The endpoint list in this README is an overview of the paths used in this sample server. Detailed request/response formats and error codes follow the above documentation.

## Directory Structure

```text
google-cloud/
├─ src/
│  └─ example.ts      # Google Cloud / Firebase startup entrypoint (uses createServer from @trustknots/server-core)
├─ .env.example       # Sample environment variable configuration
├─ package.json
└─ tsconfig.json
```

Shared implementation lives in `server/core`

## Compilation and Server Startup

To start this server, follow the steps below.

### Prerequisites

- Node.js is installed
- pnpm is installed
- Dependencies are installed in the VCKnots root directory
- Google Cloud / Firebase credentials are available

### Steps

1. **Configure Environment Variables**

   ```bash
   # Navigate to server/google-cloud directory
   cd server/google-cloud

   # Copy .env.example to create .env
   cp .env.example .env
   ```

   Required variables for `src/example.ts`:

   - `GOOGLE_PROJECT_ID`
   - `GOOGLE_PROJECT_LOCATION`
   - `FIREBASE_PRIVATE_KEY`
   - `FIREBASE_CLIENT_EMAIL`

   Optional variables:

   - `FIRESTORE_DATABASE_ID`
   - `BASE_URL` (e.g., `http://localhost:8080`)
   - `PORT` (default: `8080`)
   - `PRIVATE_KEY_PATH`
   - `CERTIFICATE_PATH`

2. **Install Dependencies** (Run from root directory)

   ```bash
   # Navigate to vcknots root directory
   cd /path/to/vcknots

   # Install dependencies (if not already done)
   pnpm install
   ```

3. **Build Modules**

   ```bash
   # Build issuer+verifier module
   pnpm -F @trustknots/vcknots build

   # Build shared server core module
   pnpm -F @trustknots/server-core build

   # Build Google Cloud module
   pnpm -F @trustknots/google-cloud build

   # Build Google Cloud server module
   pnpm -F @trustknots/server-google-cloud build
   ```

4. **Start Server (Google Cloud variant)**

   ```bash
   # Start the Google Cloud / Firebase-backed server
   pnpm -F @trustknots/server-google-cloud start
   ```

### Server Startup Confirmation

When the server starts successfully, you will see output similar to the following:

```text
> @trustknots/server-google-cloud@0.1.0 start /path/to/vcknots/server/google-cloud
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

The server starts on `http://localhost:8080` by default.

## Notes

- `server/google-cloud` depends on the workspace package `@trustknots/server-core`.
- After changing workspace packages/dependencies, run `pnpm install` at the repository root to refresh links.

## Endpoints

> For detailed API specifications (parameters, types, errors), please refer to the official documentation for [Issuer](https://trustknots.github.io/vcknots/docs/issuer) and [Verifier](https://trustknots.github.io/vcknots/docs/verifier).

### Endpoint List

#### Issuer

- [`POST /configurations/:configuration/offer`](../single/README.md#post-configurationsconfigurationoffer) - Create credential offer
- [`POST /credentials`](../single/README.md#post-credentials) - Issue credential
- [`GET /.well-known/openid-credential-issuer`](../single/README.md#get-well-knownopenid-credential-issuer) - Get Issuer metadata
- [`GET /.well-known/jwt-vc-issuer`](../single/README.md#get-well-knownjwt-vc-issuer) - Get JWT VC Issuer metadata

#### Authorization Server

- [`POST /token`](../single/README.md#post-token) - Token endpoint
- [`GET /.well-known/oauth-authorization-server`](../single/README.md#get-well-knownoauth-authorization-server) - Get Authorization Server metadata

#### Verifier

- [`POST /request`](../single/README.md#post-request) - Create authorization request
- [`POST /request-object`](../single/README.md#post-request-object) - Create authorization request (by reference)
- [`GET /request.jwt/:request-object-Id`](../single/README.md#get-requestjwtrequest-object-id) - Get Request Object JWT
- [`POST /callback`](../single/README.md#post-callback) - VP verification endpoint
- [`POST /callback-kbjwt`](../single/README.md#post-callback-kbjwt) - VP verification endpoint using Key Binding JWT for dc+sd-jwt format
- [`GET /verified`](../single/README.md#get-verified) - Redirect endpoint after VP verification completion
