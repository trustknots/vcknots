---
sidebar_position: 12
---


# How to Set Up and Use the Verifier Feature

This guide explains how to set up and use the Verifier feature of VCKnots.

## 1. Prerequisites

- Supports OpenID for Verifiable Presentations 1.0 ([OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html))  
The following items are not implemented yet and are planned for future support:
  - `response_mode` supports `direct_post`, but `direct_post.jwt` is not supported yet (planned for future support).
- Assumes the cross-device flow
- Node.js v22 or later is installed
- TypeScript is configured
- This document explains the implementation based on the server sample
- Uses the Hono web framework, but can also be used with other frameworks
- The currently supported client_id_prefix values are x509_san_dns and redirect_uri
- For the currently supported formats, VP uses jwt_vp_json and VC uses jwt_vc_json. Also, dc+sd-jwt is supported.
- If the `state` parameter is passed to `createAuthzRequest`, the library automatically validates the `state` in the response when `verifyPresentations` is called. It can be omitted in flows that do not use `state` (such as `dc_api`).

## 2. Initial Setup

### Installing Required Dependencies

```bash
npm install @trustknots/vcknots
npm install hono @hono/node-server
```

### Preparing to Use the Library

```typescript
import { Hono } from 'hono'
import { initializeContext } from '@trustknots/vcknots'
import { initializeVerifierFlow, VerifierMetadata, VerifierClientId, VerifierAuthorizationResponse } from '@trustknots/vcknots/verifier'

const app = new Hono();

// Creates VcknotsContext
const context = initializeContext({
  debug: process.env.NODE_ENV !== "production",
});

// Create VerifierFlow instance
const verifierFlow = initializeVerifierFlow(context);

```

## 3. Sample Implementation of the Verifier Feature

Introduction:
- The Verifier metadata is pre-registered when the server starts. ([initializeVerifierMetadata](#initializeVerifierMetadata))
- `vpAudTx` in the sample code is a sample utility that maps `state` to `transactionId`. In your actual application, manage this using sessions or a database.



### 1. Creating an Authorization Request

The Verifier generates an authorization request (openid4vp://authorize?...) to ask the Wallet to present credentials.

#### 1-1. Basic Authorization Request

This endpoint uses an authorization request format compliant with OAuth 2.0.

- **Endpoint**: `POST /request`
- **Request body (JSON)**
  - `credentialId` (string, required): Specifies the type of VC being requested. Example: `UniversityDegreeCredential`. If not specified, an error occurs.
  - `state` (string, required): Identifier that links the authorization request to the response. Must be a random, hard-to-predict value.
  - `client_id` (string, optional): Specifies the Verifier's client_id in `prefix:value` format. Defaults to `redirect_uri:localhost` if omitted.
- **Response**
  - `200 OK`: Returns an authorization request URL in the `openid4vp://authorize?...` format as text.
  - `400 Bad Request`: For example, when `credentialId` or `state` is not specified.

- **Actual code**
```typescript
verifyApp.post('/request', async (c) => {
  try {
    const verifierId = VerifierClientId(baseUrl)
    type Payload = Record<string, unknown>
    const body: Payload = await c.req.json<Payload>().catch(() => ({}))
    const credentialId = ('credentialId' in body ? body.credentialId : undefined) as
      | string
      | undefined
    if (!credentialId) {
      return c.json(
        {
          error: 'invalid_request',
          error_description: 'credentialId is required.',
        },
        400
      )
    }
    const state =
      typeof body.state === 'string' && body.state.trim() !== '' ? body.state.trim() : undefined
    if (state === undefined) {
      return c.json(
        {
          error: 'invalid_request',
          error_description: 'state is required.',
        },
        400
      )
    }
    const client_id = validateClientIdScheme(
      (body.client_id as string) ?? 'redirect_uri:localhost'
    )
    const query = {
      dcql_query: {
        credentials: [
          {
            id: randomUUID(),
            format: 'jwt_vc_json',
            meta: {
              type_values: [[credentialId]],
            },
          },
        ],
      },
    }
    const reserved = vpAudTx.reserve(state)
    if (!reserved.ok) {
      return c.json(reserved.error, 400)
    }
    const { request, transactionId: verifierTxId } = await verifierFlow
      .createAuthzRequest(verifierId, 'vp_token', client_id, 'direct_post', query, false, {
        state,
        response_uri: `${baseUrl}/callback`,
        base_url: baseUrl,
      })
      .catch((err: unknown) => {
        vpAudTx.consume(state)
        throw err
      })
    vpAudTx.register(state, verifierTxId)

    const encoded = Object.entries({ ...request, state })
      .map(([key, value]) => {
        const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
        return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
      })
      .join('&')
      return c.text(`openid4vp://authorize?${encoded}`)
  } catch (err) {
    const errorResponse = handleError(err)
    const status = errorResponse.error === 'internal_server_error' ? 500 : 400
    return c.json(errorResponse, status)
  }
})
```


**Example**

**Request**

```bash
curl --location 'http://localhost:8080/request' \
--header 'Content-Type: application/json' \
--data ' {
 "credentialId": "UniversityDegreeCredential",
 "state": "example-state"
}'
```
**Response**

```
openid4vp://authorize?response_type=vp_token&client_id=redirect_uri%3Alocalhost&state=example-state&client_metadata=...&nonce=cf0736e6f68d4bf094b38850169e8c04&response_mode=direct_post&response_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%220d67e47b-a5f0-48ae-b880-60b94c61fbfd%22%2C%22require_cryptographic_holder_binding%22%3Atrue%2C%22multiple%22%3Afalse%2C%22format%22%3A%22jwt_vc_json%22%2C%22meta%22%3A%7B%22type_values%22%3A%5B%5B%22UniversityDegreeCredential%22%5D%5D%7D%7D%5D%7D
```


#### 1-2. JAR (JWT Authorization Request) Format Request

This endpoint uses a JWT Authorization Request (JAR) to generate and store a Request Object and returns an authorization request URI for the Wallet to retrieve it.

- **Endpoint**: `POST /request-object`
- **Request body (JSON)** (all fields optional)
  - `query` (object, optional): Specifies the DCQL query. Defaults to a `jwt_vc_json` query if omitted.
  - `state` (string, optional): Identifier that links the authorization request to the response. A random value is generated if omitted.
  - `client_id` (string, optional): Specify as `redirect_uri:<URL>` or `x509_san_dns:<hostname>`. Defaults to `x509_san_dns:localhost` if omitted.
  - `is_request_uri` (boolean, optional): If `true`, returns in request_uri format (default: `true`).
  - `is_transaction_data` (boolean, optional): If `true`, attaches transaction_data (default: `false`).
  - `response_uri` (string, optional): Callback URI for the Wallet to send the response. Defaults to `${baseUrl}/callback` if omitted.
- **Response**
  - `200 OK`: Returns an authorization request URL in the `openid4vp://authorize?...` format as text (including `request_uri` information).
  - `400 Bad Request`: When the JSON is invalid or when there is an issue with the request content.

- Actual code
```typescript
verifyApp.post('/request-object', async (c) => {
  const dcqlQuery = {
    dcql_query: {
      credentials: [
        {
          id: randomUUID(),
          format: 'jwt_vc_json',
          meta: {
            type_values: [['VerifiableCredential']],
          },
        },
      ],
    },
  }
  const raw = await c.req.text()
  let parsed: unknown = {}
  if (raw.trim()) {
    try {
      parsed = JSON.parse(raw)
    } catch (e) {
      return c.json(
        { error: 'invalid_request', error_description: 'Request body must be valid JSON' },
        400
      )
    }
  }
  const input = parsed && typeof parsed === 'object' ? (parsed as RequestObjectInput) : {}
  const requestObject: RequestObjectShape = {
    query:
      typeof input.query === 'object' && input.query !== null && !Array.isArray(input.query)
        ? input.query
        : dcqlQuery,
    state:
      typeof input.state === 'string' && input.state.trim() !== ''
        ? input.state
        : randomUUID().replaceAll('-', ''),
    base_url:
      typeof input.base_url === 'string' && input.base_url.trim() !== ''
        ? input.base_url
        : baseUrl,
    is_request_uri: typeof input.is_request_uri === 'boolean' ? input.is_request_uri : true,
    is_transaction_data:
      typeof input.is_transaction_data === 'boolean' ? input.is_transaction_data : false,
    response_uri:
      typeof input.response_uri === 'string' && input.response_uri.trim() !== ''
        ? input.response_uri
        : undefined,
    client_id:
      typeof input.client_id === 'string' && input.client_id.trim() !== ''
        ? validateClientIdScheme(input.client_id)
        : 'x509_san_dns:localhost',
  }
  let reserved: ReturnType<typeof vpAudTx.reserve> | undefined
  try {
    reserved = vpAudTx.reserve(requestObject.state)
    if (!reserved.ok) {
      return c.json(reserved.error, 400)
    }
    const verifierId = VerifierClientId(baseUrl)
    const { request, transactionId: verifierTxId } = await verifierFlow.createAuthzRequest(
      verifierId,
      'vp_token',
      requestObject.client_id,
      'direct_post',
      requestObject.query,
      requestObject.is_request_uri,
      {
        state: requestObject.state,
        base_url: baseUrl,
        response_uri: requestObject.response_uri ?? `${baseUrl}/callback`,
        request_uri: `${baseUrl}/request.jwt`,
        ...(requestObject.is_transaction_data
          ? { transaction_data: { type: 'sample_type' } }
          : {}),
      }
    )
    vpAudTx.register(requestObject.state, verifierTxId)
    console.log('[verify] direct_post transaction_id:', verifierTxId)
    const encoded = Object.entries(request)
      .map(([key, value]) => {
        const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
        return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
      })
      .join('&')

    return c.text(`openid4vp://authorize?${encoded}`)
  } catch (err) {
    if (reserved?.ok) {
      vpAudTx.consume(requestObject.state)
    }
    const errorResponse = handleError(err)
    const status = errorResponse.error === 'internal_server_error' ? 500 : 400
    return c.json(errorResponse, status)
  }
})

```

**Example**

**Request**

```bash
curl --location 'http://localhost:8080/request-object' \
--header 'Content-Type: application/json' \
--data '{
  "query": {
    "dcql_query": {
      "credentials": [
        {
          "id": "example_sd_jwt",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": ["urn:eudi:pid:1"]
          },
          "claims": [
            { "path": ["family_name"] },
            { "path": ["given_name"] },
            { "path": ["age_equal_or_over", "18"] }
          ]
        }
      ]
    }
  },
  "state": "example-state",
  "client_id": "x509_san_dns:localhost",
  "is_transaction_data": false,
  "response_uri": "http://localhost:8080/callback-kbjwt"'
```

**Response**
```
openid4vp://authorize?client_id=x509_san_dns%3Alocalhost&request_uri=http%3A%2F%2Flocalhost%3A8080%2Frequest.jwt%2F98feadd6e5d94254b91b132f4de0782e
```



### 2. Retrieving the Request Object

This is an endpoint for Wallets and other clients to retrieve the Request Object (JWT) that was stored when the JAR was generated.

- **Endpoint**: `GET /request.jwt/:request-object-Id`
- **Path parameter**
  - `request-object-Id`: Specify the ID at the end of the `request_uri` returned in the response from `createAuthzRequest`.
- **Response**
  - `200 OK`: Returns the JWT body with `Content-Type: application/oauth-authz-req+jwt`.
  - `400 Bad Request`: When the ID is invalid or an internal error occurs.

- Actual code
```typescript
verifyApp.get('/request.jwt/:request-object-Id', async (c) => {
  try {
    const verifierId = VerifierClientId(baseUrl)
    const requestObjectId = VerifierRequestObjectId(c.req.param('request-object-Id'))
    const jar = await verifierFlow.findRequestObject(verifierId, requestObjectId)
    return c.body(jar, 200, {
      'Content-Type': 'application/oauth-authz-req+jwt',
    })
  } catch (err) {
    const errorResponse = handleError(err)
    const status = errorResponse.error === 'internal_server_error' ? 500 : 400
    return c.json(errorResponse, status)
  }
})
```

**Example**

**Request**

```bash
curl --location 'http://localhost:8080/request.jwt/98feadd6e5d94254b91b132f4de0782e'
```
**Response**
```
eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJ4NWMiOlsiXG5NSUlDSGpDQ0FjT2dBd0lCQWdJVVpYOUJTNUNET0pSVzJ0MUZLMVVETXQvUXdNRXdDZ1lJS29aSXpqMEVBd0l3XG5JVEVMTUFrR0ExVUVCaE1DUjBJeEVqQVFCZ05WQkFNTUNVOUpSRVlnVkdWemREQWVGdzB5TkRFeE1qVXdPRE0yXG5NRFJhRncwek5ERXhNak13T0RNMk1EUmFNQ0V4Q3pBSkJnTlZCQVlUQWtkQ01SSXdFQVlEVlFRRERBbFBTVVJHXG5JRlJsYzNRd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFUVC9kTHNkNTFMTEJyR1Y2UjIzbzZ2XG55bVJ4SFhlRkJvSTh5cTMxeTVrRlYyVlYwZ2k5eDVaekVGaXE4RE1pQUh1Y0xBQ0ZuZHhMdFpvckNoYTl6em5RXG5vNEhZTUlIVk1CMEdBMVVkRGdRV0JCUzVjYmRnQWVNQmk1d3hwYnB3SVNHaFNoQVdFVEFmQmdOVkhTTUVHREFXXG5nQlM1Y2JkZ0FlTUJpNXd4cGJwd0lTR2hTaEFXRVRBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUlHQkJnTlZIUkVFXG5lakI0Z2hCM2QzY3VhR1ZsYm1GdUxtMWxMblZyZ2gxa1pXMXZMbU5sY25ScFptbGpZWFJwYjI0dWIzQmxibWxrXG5MbTVsZElJSmJHOWpZV3hvYjNOMGdoWnNiMk5oYkdodmMzUXVaVzF2WW1sNExtTnZMblZyZ2lKa1pXMXZMbkJwXG5aQzFwYzNOMVpYSXVZblZ1WkdWelpISjFZMnRsY21WcExtUmxNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNQXG5ibkx4Q0krV1IxdmhPVytBOEt6bkFXdjFNSm8rWUViMU1JNDVOS1cvVlFJaEFMenNxb3g4VnVCUndOMmRsNUxrXG5wbnhQNG9IOXA2SDBBT1ptS1ArWTduWFNcbiJdfQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X3Nhbl9kbnM6bG9jYWxob3N0Iiwic3RhdGUiOiIwMzg0NzViMDEyNmI0Njg0YTIyNmJjODBlYWM5MzRiNiIsImNsaWVudF9tZXRhZGF0YSI6eyJjbGllbnRfbmFtZSI6IlNhbXBsZSBWZXJpZmllciBBcHAiLCJjbGllbnRfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsIngiOiIwXzNTN0hlZFN5d2F4bGVrZHQ2T3I4cGtjUjEzaFFhQ1BNcXQ5Y3VaQlZjIiwieSI6IlpWWFNDTDNIbG5NUVdLcndNeUlBZTV3c0FJV2QzRXUxbWlzS0ZyM1BPZEEiLCJjcnYiOiJQLTI1NiJ9XX0sInZwX2Zvcm1hdHMiOnsiand0X3ZwIjp7ImFsZyI6WyJFUzI1NiJdfX0sImNsaWVudF9pZF9zY2hlbWUiOiJyZWRpcmVjdF91cmkiLCJhdXRob3JpemF0aW9uX3NpZ25lZF9yZXNwb25zZV9hbGciOiJFUzI1NiJ9LCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdmVyaWZpZXJzL2h0dHAlM0ElMkYlMkZsb2NhbGhvc3QlM0E4MDgwL2NhbGxiYWNrIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiYXVkIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92MiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiODkyMGVjMGUtZDc3YS00MmJlLTk4OWQtZTU1MTBjZmFhNjlkIiwibmFtZSI6IlRlc3QgTmFtZSIsInB1cnBvc2UiOiJUZXN0IFB1cnBvc2UiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiI4ZjJmZWM3ZC1hMmI5LTRhZTEtYTdmMi1mMGJmMTgyMWYzY2UiLCJmb3JtYXQiOnsiand0X3ZjX2pzb24iOnsicHJvb2ZfdHlwZSI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjLnR5cGUiXSwiZmlsdGVyIjp7InR5cGUiOiJhcnJheSIsImNvbnRhaW5zIjp7ImNvbnN0IjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwifX19XX19XX0sImlhdCI6MTc2MTkwMTAzOCwibm9uY2UiOiI0YTVhYTQ1ZjllMWQ0N2FmOTkzNWY5OWEyM2M5ZDNlNiJ9.Kc4FFI1cNXJCO5nI8Yy0jnlYtLFDL-Wr-AoWtq8sasI0grzP1Zco8Zw9Ug2zybtMnn_o6XLDnnRj8jb2g0Y0TQ
```



### 3. Receiving and Verifying vp_token

This is an endpoint where the Verifier receives the `vp_token` returned from the Wallet and performs verification (VP verification).

- **Endpoint**: `POST /callback`
- **Request body**
  - `Content-Type: application/x-www-form-urlencoded`
  - Form fields carry `vp_token` (a JSON object) and `state` (same as a Wallet `direct_post` response).
  - `vp_token` is a DCQL-format JSON object mapping credential query IDs to arrays of VP strings.
  - Values are validated and parsed into `VerifierAuthorizationResponse`.
- **Response**
  - `200 OK`: JSON body `{ "redirect_uri": "<baseUrl>/verified" }` (sample server; adjust to your app).
  - `400 Bad Request` / `500 Internal Server Error`: OAuth-style JSON from `handleError` (`error`, `error_description`) when validation or VP verification fails.

- **Related endpoint**: `POST /callback-kbjwt` — used in the sample when the authorization request uses `x509_san_dns` and SD-JWT with a Key Binding JWT. It calls `verifyPresentations` with `isKbJwt: true`. The `client_id` (used to verify the KB-JWT `aud` claim) is automatically retrieved by the library from the transaction.

- Code example
```typescript
verifyApp.post('/callback', async (c) => {
  try {
    const contentType = normalizeContentType(c.req.header('content-type') ?? '')
    if (contentType !== 'application/x-www-form-urlencoded') {
      return c.json(
        {
          error: 'invalid_request',
          error_description: 'content-type must be application/x-www-form-urlencoded',
        },
        400
      )
    }
    const formData = await c.req.formData()
    const parsed = parseFormPayload(formData)
    if (!parsed.ok) {
      return c.json(parsed.error, 400)
    }
    const authorizationResponse = VerifierAuthorizationResponse(parsed.payload)
    const resolved = vpAudTx.resolve(authorizationResponse.state)
    if (!resolved.ok) {
      return c.json(resolved.error, 400)
    }
    const vpPayload = await verifierFlow.verifyPresentations(
      authorizationResponse,
      resolved.transactionId
    )
    vpAudTx.consume(authorizationResponse.state ?? '')
    console.log('Verified VP Payload:', vpPayload)
    return c.json({ redirect_uri: `${baseUrl}/verified` }, 200)
  } catch (err) {
    const errorResponse = handleError(err)
    console.log('error Response:', errorResponse)
    const status = errorResponse.error === 'internal_server_error' ? 500 : 400
    return c.json(errorResponse, status)
  }
})
```

**Example**

**Request**

```bash
curl --location 'http://localhost:8080/callback' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'vp_token={"sample-id":["eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."]}' \
--data-urlencode 'state=example-state'
```

> **Note**: `vp_token` is a DCQL-format JSON object (credential query ID → array of VP strings).

**Response** (`200 OK`)

```json
{
  "redirect_uri": "http://localhost:8080/verified"
}
```


## 4. Registering Verifier Metadata {#initializeVerifierMetadata}

- The code in this guide registers verifier metadata at startup according to the steps in this section. For production use or your own development environment, adjust `BASE_URL` and the metadata/certificate files as appropriate.

Metadata file (external JSON):
- Location: `vcknots/server/samples/verifier_metadata.json`
- Example (contents):
```json
{
	"vp_formats_supported": {
		"jwt_vc_json": {
			"alg_values": ["ES256"]
		},
		"dc+sd-jwt": {
			"sd-jwt_alg_values": ["ES256", "ES384"],
			"kb-jwt_alg_values": ["ES256", "ES384"]
		}
	}
}
```

Locations of certificate files:
- Private key: `vcknots/server/samples/certificate-openid-test/private_key_openid.pem`
- Certificate: `vcknots/server/samples/certificate-openid-test/certificate_openid.pem`


```typescript
// Initialize metadata with BASE_URL applied
const baseUrl = process.env.BASE_URL ?? 'http://localhost:8080'

// Use the sample verifier metadata (JSON) that has been read (e.g., verifierMetadataConfig)
await initializeVerifierMetadata(baseUrl, verifierMetadataConfig)
```

```typescript
// Read the certificate/private key and register the metadata
async function initializeVerifierMetadata(verifierId: string, metadata: VerifierMetadata) {
  try {
    const clientId = VerifierClientId(verifierId)

    const verifier = await verifierFlow.findVerifierMetadata(clientId)
    if (verifier) {
      console.log('Verifier metadata already exists, skipping initialization')
      return true
    }
    const defaultPrivateKeyPath = join(
      __dirname,
      '../../samples/certificate-openid-test/private_key_openid.pem'
    )
    const defaultCertPath = join(
      __dirname,
      '../../samples/certificate-openid-test/certificate_openid.pem'
    )
    const privateKeyPath = process.env.PRIVATE_KEY_PATH
      ? resolve(process.env.PRIVATE_KEY_PATH)
      : defaultPrivateKeyPath
    const certificatePath = process.env.CERTIFICATE_PATH
      ? resolve(process.env.CERTIFICATE_PATH)
      : defaultCertPath
    const privateKeyEnv = process.env.PRIVATE_KEY?.replace(/\\n/g, '\n')
    const certificateEnv = process.env.CERTIFICATE?.replace(/\\n/g, '\n')
    const privateKey = privateKeyEnv ?? readFileSync(privateKeyPath, 'utf-8')
    const certificate = certificateEnv ?? readFileSync(certificatePath, 'utf-8')
    const option = { privateKey, certificate, format: 'pem', alg: 'ES256' } as const
    await verifierFlow.createVerifierMetadata(clientId, metadata, option)
    console.log(`Verifier metadata initialized for ${clientId}`)
    return true
  } catch (error) {
    console.error('Error initializing verifier metadata:', error)
    return false
  }
}
```


## 6. Explanation of Type Definitions

### VerifierClientId {#VerifierClientId}
Represents the identifier of the Verifier. This value is the combination of the ClientIdScheme and a verifier identifier, and it is used to uniquely identify a Verifier.

For the definition, see [issuer+verifier/src/client-id.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/client-id.types.ts).


### VerifierMetadata {#VerifierMetadata}
Defines the metadata of a Verifier. It includes information such as the client name, URI, supported VP formats, redirect URI, and so on.

For the definition, see [issuer+verifier/src/verifier-metadata.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier-metadata.types.ts).


### VerifierAuthorizationResponse {#Verifierauthorizationresponse}
Contains the VP token and presentation submission information and is used for presentation verification.

For the definition, see [issuer+verifier/src/authorization-response.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/authorization-response.types.ts).


### VpTokenPayload {#VpTokenPayload}
Represents the verified payload returned from `verifyPresentations`.
This is a union type whose shape depends on the VP format (for example, `jwt_vp_json` or `dc+sd-jwt`).

For the definition, see [issuer+verifier/src/presentation.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/presentation.types.ts).

## 7. Methods of VerifierFlow

### createVerifierMetadata
Creates and stores the Verifier metadata.

```typescript
createVerifierMetadata(
  verifierId: VerifierClientId,
  metadata: VerifierMetadata,
  options?: CreateVerifierMetadataOptions
): Promise<void>
```

**Parameters**:
- `verifierId`: Identifier of the Verifier ([VerifierClientId](#VerifierClientId))
- `metadata`: Verifier metadata ([VerifierMetadata](#VerifierMetadata))
- `options`: Options such as certificates and private keys ([CreateVerifierMetadataOptions](#CreateVerifierMetadataOptions))

**Return value**:
- None

**Error cases**:
- `duplicate_verifier`: Metadata with the same `verifierId` is already registered
- `internal_server_error`: `options.alg` is not specified (required when specifying a public key/certificate)
- `invalid_certificate`: The provided certificate is invalid

#### CreateVerifierMetadataOptions {#CreateVerifierMetadataOptions}

Defines the options used when creating verifier metadata. It allows configuration of certificates or public keys.

For detailed type definitions, see [verifier.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts).


### createAuthzRequest
Creates an authorization request.

```typescript
createAuthzRequest(
  verifierId: ClientId,
  response_type: 'vp_token',
  client_id: `${ClientIdScheme}:${string}`,
  response_mode: 'direct_post' | 'query' | 'fragment' | 'dc_api.jwt' | 'dc_api',
  query: DeepPartialUnknown<Dcql>,
  isRequestUri: boolean,
  options: CreateAuthzRequestOptions
): Promise<{ request: AuthorizationRequest, transactionId: string }>
```


**Parameters**:
- `verifierId`: Identifier of the Verifier ([VerifierClientId](#VerifierClientId))
- `response_type`: Response type ('vp_token')
- `client_id`: Client ID (see [OpenID for Verifiable Presentations 5.2 Existing Parameters, client_id](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.2))
- `response_mode`: Response mode ('direct_post' | 'query' | 'fragment' | 'dc_api.jwt' | 'dc_api')
- `query`: DCQL query ([6. Digital Credentials Query Language (DCQL)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l))
- `isRequestUri`: Flag indicating whether to use a request URI
  - `isRequestUri = true` → Request URI format (stores the Request Object externally)
  - `isRequestUri = false` → Direct format (includes parameters directly in the authorization request)
- `options`: Options for creating the request ([CreateAuthzRequestOptions](#CreateAuthzRequestOptions))

**Return value**:
- Returns `{ request: AuthorizationRequest, transactionId: string }`.
  - `request` ([AuthorizationRequest](#AuthorizationRequest)): takes one of the following forms:

    - **Request URI format** (when `isRequestUri = true`):
    ```typescript
    {
      client_id: string,
      request_uri: string
    }
    ```

    - **Direct format** (when `isRequestUri = false`):
    ```typescript
    {
      client_id: string,
      response_uri: string,
      response_type: 'vp_token',
      response_mode: 'direct_post' | 'query' | 'fragment' | 'dc_api.jwt' | 'dc_api',
      client_metadata: VerifierMetadata,
      nonce: string,
      // dcql_query
    }
    ```

  - `transactionId` (string): Required when calling `verifyPresentations`. Store it alongside session/state so it can be looked up when the Wallet posts back.

**Error cases**:
- `unsupported_client_id_prefix`: An unsupported client_id_prefix was specified
- `certificate_not_found`: Certificate is not registered when using x509_san_dns
- `invalid_request`: options.base_url is not specified even though isRequestUri = true
- `verifier_vp_formats_not_supported`: A VP format specified in the query is not listed in the Verifier's metadata



#### CreateAuthzRequestOptions {#CreateAuthzRequestOptions}
Defines the options used when creating an authorization request.

For detailed type definitions, see [verifier.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts).


**Notes**:
- When `isRequestUri` is `true`, `base_url` is required.
- If `response_uri` is not specified, `${verifierId}/post` is used by default.
- For security reasons, it is recommended to use a random, hard-to-predict value for `state`.

#### AuthorizationRequest (response type of createAuthzRequest) {#AuthorizationRequest}

This is the response type returned by `createAuthzRequest`. It is combined with the DCQL schema, either as a "Request URI format" using `request_uri`, or as a "direct format" that includes the parameters directly.

For detailed type definitions, see [authorization-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/authorization-request.types.ts).


### findRequestObject
When the response from createAuthzRequest is in JAR format, this method retrieves the JAR-format request object.

```typescript
findRequestObject(
  verifierId: ClientId,
  objectId: RequestObjectId,
  options?: FindRequestObjectOptions
): Promise<string>
```

**Parameters**:
- `verifierId`: Identifier of the Verifier ([VerifierClientId](#VerifierClientId))
- `objectId`: Request Object ID ([RequestObjectId](#RequestObjectId))
- `options`: Retrieval options ([FindRequestObjectOptions](#FindRequestObjectOptions))

**Return value**:
- Returns a JWT-formatted Request Object string. This string has the following format:
```
{base64url(header)}.{base64url(payload)}.{signature}
```
**Error cases**:
- `verifier_not_found`: The specified Verifier does not exist
- `request_object_not_found`: The specified Request Object does not exist
- `provider_not_found`: Provider for the Authorization Request JAR cannot be found
- `authz_verifier_key_not_found`: Signing key provider for the specified algorithm cannot be found
- `internal_server_error`: Failed to generate the signature for the Request Object

**Notes**:
- A Request Object can be retrieved only once.
- Calling with the same Request Object ID multiple times results in an error.



#### RequestObjectId {#RequestObjectId}

A unique identifier for a Request Object (authorization request JAR).

For detailed type definitions, see [request-object-id.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/request-object-id.types.ts).


#### FindRequestObjectOptions {#FindRequestObjectOptions}

Defines the options used when retrieving a Request Object.

For detailed type definitions, see [verifier.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts).



### verifyPresentations
Verifies the VP token.

```typescript
verifyPresentations(
  response: AuthorizationResponse,
  transactionId: string,
  options?: VerifyPresentationOptions
): Promise<Record<string, VpTokenPayload[]>>
```

**Parameters**:

- `response`: Information used for verification ([Verifierauthorizationresponse](#Verifierauthorizationresponse))
- `transactionId`: The `transactionId` returned by `createAuthzRequest`. Used to look up the original DCQL query for the authorization request.
- `options`: [VerifyPresentationOptions](#VerifyPresentationOptions)

#### VerifyPresentationOptions {#VerifyPresentationOptions}

Options passed from your verifier application into VP / credential-format–specific checks. Defined in [`verifier.flows.ts`](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts).

> **Note**: `expectedAud` (`client_id`) is stored in the transaction at `createAuthzRequest` time and automatically retrieved by the library inside `verifyPresentations`. You do not need to pass it separately.

| Field | Required | Description |
| ----- | -------- | ----------- |
| `isKbJwt` | No | For `dc+sd-jwt`: if `true`, validate the Key Binding JWT (nonce, `aud`, `sd_hash`, etc.). If omitted, KB-JWT validation is skipped. |
| `expectedTransactionDataHashes` | No | For `transaction_data` usage. Expected hash list contained in the KB-JWT. |

**Return value**:
- Returns `Record<string, VpTokenPayload[]>`: a map from DCQL credential query ID to an array of verified VP token payloads.
- Each payload is a union type for the supported VP format (for example, `jwt_vp_json` or `dc+sd-jwt`).

  - Example payload (`jwt_vp_json`):
  ```typescript
  {
    iss?: string,
    vp: {
      type: string[],
      verifiableCredential: (string | object)[]
    },
    nonce: string
  }
  ```

  - Example payload (`dc+sd-jwt`):
  ```typescript
  {
    iss?: string,
    vct: string
    // may include _sd, cnf, status, and other SD-JWT payload claims
  }
  ```

- **Implementer responsibility**: This library **does not** automatically persist or manage verified payloads. Binding to sessions or databases, retention, and whether to write audit logs must be **designed and implemented by your (integrator) application** in line with business requirements.

**Error cases**:
- `verifier_not_found`: The Verifier does not exist
- `transaction_id_not_found`: No transaction found for the given `transactionId` (already consumed or invalid)
- `illegal_argument`: Missing/invalid arguments (for example, unknown credential query ID, or VP provider rejects options)
- `unsupported_vp_token`: Unsupported `vp_token` shape or format (for example, non-string VP)
- `INVALID_REQUEST`: The `state` in the response does not match the `state` stored in the transaction
- `invalid_vp_token`: Required DCQL credentials missing, or VP structure invalid
- `invalid_nonce`: The authorization request `nonce` is missing from the VP or does not match
- `invalid_credential`: Invalid embedded VC (for example, `jwt_vp_json` path) or issuer/JWKS resolution failure
- `invalid_sd_jwt` / `holder_binding_failed`: SD-JWT or Key Binding verification failures

**Notes**:
- `client_id` (`expectedAud`) is automatically retrieved from the transaction. The `aud` claim the Wallet sets on the VP or KB-JWT must match the `client_id` passed to `createAuthzRequest`.
- If `state` was passed to `createAuthzRequest` via `options.state`, the library automatically validates that `response.state` matches. A mismatch results in an `INVALID_REQUEST` error.
- The `transactionId` is consumed after a successful call. Calling with the same `transactionId` again will result in an error.



### findVerifierCertificate
Retrieves the Verifier's certificate.

```typescript
findVerifierCertificate(id: ClientId): Promise<Certificate | null>
```

**Parameters**:
- `id`: Identifier of the Verifier ([VerifierClientId](#VerifierClientId))

**Return value**:
- Certificate object ([Certificate](#Certificate)), or `null` if it does not exist


#### Certificate {#Certificate}

Type that represents the certificate chain held by the Verifier (an array of PEM-formatted strings). Each element must have passed PEM format validation.

For detailed type definitions, see [signature-key.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/signature-key.types.ts).


Note:
- The recommended chain order is "leaf → intermediate → root".
- Invalid PEMs result in an error.


## 8. Notes

1. **Certificate management**: When configuring the Verifier metadata, you must provide appropriate certificates and private keys.
   - The order of the certificate chain is important (leaf certificate → intermediate certificate → root certificate).
   - In production environments, use valid certificates.

2. **Security**: In production environments, be sure to implement proper authentication and authorization mechanisms.
   - Pay particular attention to the management of private keys.
   - Use HTTPS to encrypt communications.

3. **URL encoding**: If the verifier ID contains characters that require URL encoding (for example, `:` or `/`), make sure they are properly encoded.

## 9. Troubleshooting


- **Q: Certificate-related error**: `invalid_certificate`
  - **A:** Check that the path to the certificate file is correct and that the file exists. Also verify that the certificate is valid.

- **Q: Metadata validation error**:
  - **A:** Check that the provided metadata conforms to the VerifierMetadata schema.

- **Q: Error when creating authorization request**: `invalid_request`
  - **A:** Verify that all required parameters have been provided.

- **Q: Error retrieving request object**: `request_object_not_found`
  - **A:** A request object can be retrieved only once. Calling with the same Request Object ID multiple times results in an error.

- **Q: Nonce verification error for vp_token**: fails with `invalid_nonce` – nonce is not valid.
  - **A:** Check the following possible causes and solutions.
  - **Causes**:
    - The nonce in `vp_token` does not match the one generated at the time of the authorization request
    - The nonce has already been used
    - The nonce has expired
  - **Solutions**:
    - Confirm that the nonce in `vp_token` matches the nonce generated at the time of the authorization request
    - Check that multiple authentications are not being attempted with the same nonce
    - Confirm that nonce generation and storage processing are functioning correctly
    - Make sure clocks are synchronized (for expiration checks)
