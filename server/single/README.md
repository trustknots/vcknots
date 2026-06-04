# Single Server

Single-tenant server implementation. Provides a server that integrates Issuer, Authorization Server, and Verifier functionality using the VCKnots library.
Shared app/routes/server/util implementations are provided by `@trustknots/server-core`.

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
├─ src/
│  └─ example.ts      # In-memory provider startup entrypoint (uses createServer from @trustknots/server-core)
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

   Configure the DPoP mode (`off` / `optional` / `required`) in `authorization_server.default_client` / `authorization_server.anonymous_client` in `server/samples/oauth-server.json`.

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

   # Build single server module
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
POST  /nonce
        [handler]
GET   /nonce/:nonce
        [handler]
DELETE  /nonce/:nonce
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

- `server/single` depends on the workspace package `@trustknots/server-core`.
- After changing workspace packages/dependencies, run `pnpm install` at the repository root to refresh links.

## Endpoints

> For detailed API specifications (parameters, types, errors), please refer to the official documentation for [Issuer](https://trustknots.github.io/vcknots/docs/issuer) and [Verifier](https://trustknots.github.io/vcknots/docs/verifier).

### Endpoint List

#### Issuer
- [`POST /configurations/:configuration/offer`](#post-configurationsconfigurationoffer) - Create credential offer
- [`POST /credentials`](#post-credentials) - Issue credential
- [`GET /.well-known/openid-credential-issuer`](#get-well-knownopenid-credential-issuer) - Get Issuer metadata
- [`GET /.well-known/jwt-vc-issuer`](#get-well-knownjwt-vc-issuer) - Get JWT VC Issuer metadata
- [`POST /nonce`](#post-nonce) - Create nonce (c_nonce)
- [`GET /nonce/:nonce`](#get-noncenonce) - Validate nonce
- [`DELETE /nonce/:nonce`](#delete-noncenonce) - Revoke nonce

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

**Request Body (JSON):**
- Optional. Include a body only when using `tx_code`.
- If the body is empty or omitted, no `tx_code` is created.
```json
{
  "tx_code"?: {
    "input_mode"?: 'numeric' | 'text',
    "length"?: number,
    "description"?: string
  }
}
```

**Response:**
- `200 OK` - Text in the format `openid-credential-offer://?credential_offer={encoded_offer}`

<a id="post-credentials"></a>
#### `POST /credentials`

Issue credential

**Request headers (depends on the OAuth policy DPoP mode and token type):**
- **Bearer:** `Authorization: Bearer {access_token}` — for access tokens without sender binding when the DPoP mode is not `required`.
- **DPoP:** `Authorization: DPoP {access_token}` and `DPoP: {compact_jwt}` (RFC 9449 DPoP Proof) — required when the DPoP mode is `required`, or when the token contains `cnf.jkt` (even in `optional` mode, Bearer-only is rejected).
- Error responses may include `WWW-Authenticate: Bearer` or `WWW-Authenticate: DPoP` (see the Issuer docs on the credential endpoint and DPoP: [Issuer Setup and Usage](https://trustknots.github.io/vcknots/docs/issuer)).

**Request Body (JSON):**
```json
{
  "credential_identifier"?: string,
  "credential_configuration_id"?: string,
  "proofs"?: {
    "jwt"?: string[],
    "di_vp"?: {
      "holder"?: string,
      "proof": {
        "domain": string,
        "challenge": string
      }
    }[],
    "attestation"?: string[]
  },
  "credential_response_encryption"?: {
    "jwk": string,
    "alg": string,
    "zip"?: string
  }
}
```

**Response:**
- `200 OK` - Issued credential (JSON)
- `401 Unauthorized` - Access token or DPoP verification failed (`invalid_token` / `invalid_dpop_proof` / `use_dpop_nonce`; distinguish via response body and `WWW-Authenticate` when present)

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

<a id="post-nonce"></a>
#### `POST /nonce`

Create a nonce (c_nonce). Corresponds to the OID4VCI [nonce endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint). Used when a Wallet obtains a c_nonce before sending credential requests. When requesting multiple credentials, the same nonce can be reused within its validity period.

**Response Headers:**
- `Cache-Control: no-store` - Disable caching
- `DPoP-Nonce: <nonce>` - A DPoP nonce returned when the OAuth policy DPoP mode is not `off`

**Response:**
- `200 OK` - `{ "c_nonce": string }` (nonce validity is 2 minutes)
- `400 Bad Request` / `500 Internal Server Error` - On error

The JSON body `c_nonce` and the `DPoP-Nonce` response header are different values. `c_nonce` is used for credential proofs, while `DPoP-Nonce` is used for DPoP Proofs presented to the token endpoint. Since they have different purposes, their TTLs are managed separately.

<a id="get-noncenonce"></a>
#### `GET /nonce/:nonce`

Validate the specified nonce. Useful for debugging or Wallet pre-validation.

**Path Parameters:**
- `nonce` (string) - The nonce value to validate

**Response:**
- `200 OK` - `{ "valid": boolean }`
- `400 Bad Request` / `500 Internal Server Error` - On error

<a id="delete-noncenonce"></a>
#### `DELETE /nonce/:nonce`

Revoke (delete) the specified nonce.

**Path Parameters:**
- `nonce` (string) - The nonce value to revoke

**Response:**
- `200 OK` - `{ "deleted": true }`
- `404 Not Found` - Nonce not found (`{ "error": "not_found", "error_description": "Nonce not found." }`)
- `400 Bad Request` / `500 Internal Server Error` - On error

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
  "scope"?: string
}
```

The DPoP mode is configured by the OAuth policy in `server/samples/oauth-server.json` and by per-client sender constraint settings in `server/samples/oauth-clients.json`. `anonymous_client` applies to token requests without `client_id` / `client_assertion`; `default_client` applies when a registered client has no sender constraint setting and as the credential / nonce endpoint default.

| DPoP mode | token endpoint | credential endpoint |
|-------------|----------------|---------------------|
| `off` | DPoP is not used. The server issues a Bearer access token. | DPoP is not used. `Authorization: DPoP` or a `DPoP` header is rejected. |
| `optional` | If the `DPoP` header is absent, the server issues a Bearer access token. If the `DPoP` header is present, the server verifies the proof and issues a DPoP-bound access token. | Tokens without sender binding may use `Authorization: Bearer`. Tokens carrying `cnf.jkt` require `Authorization: DPoP` and a `DPoP` header. |
| `required` | The `DPoP` header is required. | `Authorization: DPoP` and a `DPoP` header are required. Bearer-only requests are rejected. |

DPoP nonce errors are handled with `use_dpop_nonce` and a `DPoP-Nonce` response header, not as `invalid_request` or `invalid_dpop_proof`. Nonce-unrelated malformed proofs or signature verification failures are returned as `invalid_request` or `invalid_dpop_proof`, depending on the endpoint.

At the token endpoint, if the DPoP Proof has no `nonce`, or the nonce is invalid, the server returns **HTTP 400** with a **`DPoP-Nonce` header** and JSON `use_dpop_nonce`. The token endpoint response does **not** include `WWW-Authenticate` in the current implementation.

```http
HTTP/1.1 400 Bad Request
DPoP-Nonce: <nonce>
Content-Type: application/json
```

```json
{
  "error": "use_dpop_nonce",
  "error_description": "Authorization server requires nonce in DPoP proof."
}
```

At the credential endpoint, if the DPoP Proof has no `nonce`, or the nonce is invalid, the server returns **HTTP 401** with a **`DPoP-Nonce` header**, `WWW-Authenticate: DPoP`, and JSON `use_dpop_nonce`.

```http
HTTP/1.1 401 Unauthorized
DPoP-Nonce: <nonce>
WWW-Authenticate: DPoP realm="http://localhost:8080", error="use_dpop_nonce", error_description="Credential issuer requires nonce in DPoP proof."
Content-Type: application/json
```

```json
{
  "error": "use_dpop_nonce",
  "error_description": "Credential issuer requires nonce in DPoP proof."
}
```

When DPoP Proof verification succeeds, `token_type` is `DPoP`. The issued access token contains `cnf.jkt`, the JWK Thumbprint of the public key from the DPoP Proof JOSE header.

```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 86400
}
```

#### OAuth clients and private_key_jwt

OAuth clients are configured in `server/samples/oauth-clients.json`. If the token request body contains `client_id`, that value is used first. If it is absent, the client id is derived from the `client_assertion` JWT `iss` / `sub`. If neither source yields a client id, the `anonymous_client` policy is applied.

For a registered client with `token_endpoint_auth_method: "private_key_jwt"`, the token request must include these form fields:

```text
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<compact JWT>
```

The private_key_jwt verifier checks that `iss` / `sub` match the registered `client_id`, that `aud` matches the registered `client_assertion_audience` or the Authorization Server token endpoint / issuer, that `exp` / `iat` / `jti` are present, that `alg` is an allowed asymmetric signing algorithm, and that the signature verifies with a public key from the registered `jwks.keys`. A client assertion with the same `jti` cannot be reused.

Each client may override the DPoP mode with `senderConstrainedAccessToken`. If it is omitted, the `authorization_server.default_client` policy is used. The authenticated client id is included in the issued access token payload as `client_id`.

<a id="get-well-knownoauth-authorization-server"></a>
#### `GET /.well-known/oauth-authorization-server`

Get Authorization Server metadata

**Response:**
- `200 OK` - Authorization Server metadata (JSON format)
- `404 Not Found` - Metadata not found

The following illustrates typical fields on the single server. During initialization, **`issuer`**, **`authorization_endpoint`**, and **`token_endpoint`** are set according to **`BASE_URL`** (e.g. `http://localhost:8080`); your deployment may differ.
```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/authorize",
  "token_endpoint": "http://localhost:8080/token",
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
