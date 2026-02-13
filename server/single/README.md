# Single Server

Single-tenant server implementation. Provides a server that integrates Issuer, Authorization Server, and Verifier functionality using the VCKnots library.

## Overview

This server is implemented based on the OID4VCI (OpenID for Verifiable Credential Issuance) and OID4VP (OpenID for Verifiable Presentations) specifications.

## Actual API Specifications

For **actual API specifications, parameters, type definitions, and usage examples** for Issuer, Authorization Server, and Verifier, please refer to the following official documentation:

- **Issuer**: [Issuer Setup and Usage Guide](https://trustknots.github.io/vcknots/docs/issuer)
- **Verifier**: [Verifier Setup and Usage Guide](https://trustknots.github.io/vcknots/docs/verifier)

The endpoint list in this README is an overview of the paths used in this sample server. Detailed request/response formats and error codes follow the above documentation.

## Directory Structure

```
single/
├── src/
│   ├── app.ts          
│   ├── example.ts      
│   ├── routes/
│   │   ├── authz.ts    # Authorization Server endpoints
│   │   ├── issue.ts    # Issuer endpoints
│   │   └── verify.ts   # Verifier endpoints
│   └── utils/
│       └── error-handler.ts  # Error handling utility
├── .env.example        # Sample environment variable configuration
├── package.json        
└── tsconfig.json       
```

## Compilation and Server Startup

To start this server, follow the steps below.

### Prerequisites

- Node.js is installed
- pnpm is installed
- Dependencies are installed in the VCKnots root directory

### Steps

1. **Configure Environment Variables**

   ```bash
   # Navigate to server/single directory
   cd server/single
   
   # Copy .env.example to create .env
   cp .env.example .env
   
   # Edit .env file and set appropriate values
   # BASE_URL: Server base URL (e.g., http://localhost:8080)
   # PORT: Server port number (default: 8080)
   # PRIVATE_KEY_PATH: Path to private key file (default: ../samples/certificate-openid-test/private_key_openid.pem)
   # CERTIFICATE_PATH: Path to certificate file (default: ../samples/certificate-openid-test/certificate_openid.pem)
   ```

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
   
   # Build server module
   pnpm -F @trustknots/server build
   ```

4. **Start Server**

   ```bash
   # Start the server
   pnpm -F @trustknots/server start
   ```

### Server Startup Confirmation

When the server starts successfully, you will see output similar to the following:

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

The server starts on `http://localhost:8080` by default.

## Endpoints

> For detailed API specifications (parameters, types, errors), please refer to the official documentation for [Issuer](https://trustknots.github.io/vcknots/docs/issuer) and [Verifier](https://trustknots.github.io/vcknots/docs/verifier).

### Endpoint List

#### Issuer
- [`POST /configurations/:configuration/offer`](#post-configurationsconfigurationoffer) - Create credential offer
- [`POST /credentials`](#post-credentials) - Issue credential
- [`GET /.well-known/openid-credential-issuer`](#get-well-knownopenid-credential-issuer) - Get Issuer metadata
- [`GET /.well-known/jwt-vc-issuer`](#get-well-knownjwt-vc-issuer) - Get JWT VC Issuer metadata

#### Authorization Server
- [`POST /token`](#post-token) - Token endpoint
- [`GET /.well-known/oauth-authorization-server`](#get-well-knownoauth-authorization-server) - Get Authorization Server metadata

#### Verifier
- [`POST /request`](#post-request) - Create authorization request
- [`POST /request-object`](#post-request-object) - Create authorization request (by reference)
- [`GET /request.jwt/:request-object-Id`](#get-requestjwtrequest-object-id) - Get Request Object JWT
- [`POST /callback`](#post-callback) - VP verification endpoint
- [`POST /callback-kbjwt`](#post-callback-kbjwt) - VP verification endpoint using Key Binding JWT for dc+sd-jwt format
- [`GET /verified`](#get-verified) - Redirect endpoint after VP verification completion

---

### Issuer

<a id="post-configurationsconfigurationoffer"></a>
#### `POST /configurations/:configuration/offer`

Create credential offer

**Path Parameters:**
- `configuration` (string) - Credential configuration ID

**Response:**
- `200 OK` - Text in the format `openid-credential-offer://?credential_offer={encoded_offer}`

<a id="post-credentials"></a>
#### `POST /credentials`

Issue credential

**Request Headers:**
- `Authorization: Bearer {access_token}` (required) - Access token

**Request Body (JSON):**
```json
{
  "credential_identifier"?: string,
  "format"?: "jwt_vc_json" | "jwt_vc_json-ld" | "ldp_vc",
  "credential_definition": {
    "type": string[],
    "credentialSubject"?: Record<string, string>
  },
  "proof"?: {
    "proof_type": "jwt" | "ldp_vp",
    "jwt"?: string,
    "ldp_vp"?: {
      "holder"?: string,
      "proof": {
        "domain": string,
        "challenge": string
      }
    }
  },
  "credential_response_encryption"?: {
    "jwk": string,
    "alg": string,
    "enc": string
  }
}
```

**Response:**
- `200 OK` - Issued credential (JSON format)
- `401 Unauthorized` - Access token is invalid or missing

<a id="get-well-knownopenid-credential-issuer"></a>
#### `GET /.well-known/openid-credential-issuer`

Get Issuer metadata

**Response:**
- `200 OK` - Issuer metadata (JSON format)
- `404 Not Found` - Metadata not found

<a id="get-well-knownjwt-vc-issuer"></a>
#### `GET /.well-known/jwt-vc-issuer`

Get JWT VC Issuer metadata

**Response:**
- `200 OK` - JWT VC Issuer metadata (JSON format)
- `404 Not Found` - Metadata not found

### Authorization Server

<a id="post-token"></a>
#### `POST /token`

Token endpoint

**Request (application/x-www-form-urlencoded):**

Pre-Authorized Code Grant:
```
grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
pre-authorized_code={pre_authorized_code}
```

**Response:**
```json
{
  "access_token": string,
  "token_type": string,
  "expires_in": number,
  "refresh_token"?: string,
  "scope"?: string,
  "c_nonce"?: string,
  "c_nonce_expires_in"?: number
}
```

<a id="get-well-knownoauth-authorization-server"></a>
#### `GET /.well-known/oauth-authorization-server`

Get Authorization Server metadata

**Response:**
- `200 OK` - Authorization Server metadata (JSON format)
- `404 Not Found` - Metadata not found

```json
{
  "issuer": "https://authz.example.com",
  "authorization_endpoint": "https://authz.example.com/authorize",
  "token_endpoint": "https://authz.example.com/token",
  "scopes_supported": ["openid"],
  "response_types_supported": ["code"],
  "pre-authorized_grant_anonymous_access_supported": true
}
```

### Verifier

<a id="post-request"></a>
#### `POST /request`

Create authorization request. Generates an authorization request containing a Presentation Definition and returns a URI with the `openid4vp://` scheme.

**Request Body (JSON):**
```json
{
  "credentialId": string (required, example: "UniversityDegreeCredential"),
  "client_id"?: string (optional, default: "x509_san_dns:localhost")
}
```

**`client_id` format:**
- `redirect_uri:{uri}` - Redirect URI-based identifier
- `x509_san_dns:{dns_name}` - X.509 certificate SAN DNS name-based identifier
- Default: `"x509_san_dns:localhost"`

**Response:**
- `200 OK` - Text in the format `openid4vp://authorize?{encoded_params}`
- `400 Bad Request` - Invalid request (e.g., `credentialId` not specified)

<a id="post-request-object"></a>
#### `POST /request-object`

Create Request Object in JAR format.

**Request Body (JSON, can be empty):**
```json
{
  "query"?: { "presentation_definition": object },
  "state"?: string,
  "base_url"?: string,
  "is_request_uri"?: boolean,
  "is_transaction_data"?: boolean,
  "response_uri"?: string,
  "client_id"?: string
}
```

**Response:**
- `200 OK` - Text in the format `openid4vp://authorize?{encoded_params}`
- `400 Bad Request` - Invalid request

<a id="post-callback"></a>
#### `POST /callback`

Authorization response callback. Receives Verifiable Presentation sent from Wallet and verifies it.

**Request:** `application/json` or `application/x-www-form-urlencoded`

- `vp_token` (required), `presentation_submission` (optional), `state` (optional)

**Response:**
- `200 OK` - `{ "redirect_uri": "{baseUrl}/verified" }`
- `400 Bad Request` - Invalid request or verification error

<a id="post-callback-kbjwt"></a>
#### `POST /callback-kbjwt`

Callback using Key Binding JWT.

**Request (application/x-www-form-urlencoded):** `vp_token`, `presentation_submission`, `state`

**Response:**
- `200 OK` - `{ "redirect_uri": "{baseUrl}/verified" }`
- `400 Bad Request` - Invalid request or verification error

<a id="get-verified"></a>
#### `GET /verified`

Redirect endpoint after verification completion.

**Response:** `200 OK` - `{ "message": "DONE!!" }`

<a id="get-requestjwtrequest-object-id"></a>
#### `GET /request.jwt/:request-object-Id`

Get Request Object JWT.

**Path Parameters:** `request-object-Id` (string)

**Response:**
- `200 OK` - Request Object JWT (Content-Type: application/oauth-authz-req+jwt)
- `400 Bad Request` - Request Object not found
