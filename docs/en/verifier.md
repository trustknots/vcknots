---
sidebar_position: 3
---


# How to Set Up and Use the Verifier Feature

This guide explains how to set up and use the Verifier feature of VCKnots.

## 1. Prerequisites

- Supports OpenID for Verifiable Presentations - draft 24 ([OpenID for Verifiable Presentations - draft 24](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html))
- Assumes the cross-device flow
- Node.js v14 or later is installed
- TypeScript is configured
- This document explains the implementation based on the server sample
- Uses the Hono web framework, but can also be used with other frameworks
- The currently supported client_id_schema values are x509_san_dns and redirect_uri
- For the currently supported formats, VP uses jwt_vp and VC uses jwt_vc (jwt_vc_json)
- The state parameter must be implemented under the responsibility of the implementer

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

### 1. Creating an Authorization Request

The Verifier generates an authorization request (openid4vp://authorize?...) to ask the Wallet to present credentials.

#### 1-1. Basic Authorization Request

This endpoint uses an authorization request format compliant with OAuth 2.0.

- **Endpoint**: `POST /verify/request`
- **Request body (JSON)**
  - `credentialId` (string, required): Specifies the type of VC being requested. Example: `UniversityDegreeCredential`. If not specified, an error occurs.
- **Response**
  - `200 OK`: Returns an authorization request URL in the `openid4vp://authorize?...` format as text.
  - `400 Bad Request`: For example, when `credentialId` is not specified.

- **Actual code**
```typescript
app.post('/verify/request', async (c) => {
  try {
    const verifierId = VerifierClientId(baseUrl)
    const { credentialId } = (await c.req.json()) ?? {};

    if (!credentialId) throw err("INVALID_REQUEST");
    const client_id = 'x509_san_dns:localhost'

    const query = {
      presentation_definition: {
        id: randomUUID(),
        name: 'Test Name',
        purpose: 'Test Purpose',
        input_descriptors: [
          {
            id: credentialId,
            format: {
              jwt_vc_json: {
                proof_type: ['ES256'],
              },
            },
            constraints: {
              fields: [
                {
                  path: ['$.vc.type'],
                  filter: {
                    type: 'array',
                    contains: {
                      const: 'VerifiableCredential',
                    },
                  },
                },
              ],
            },
          },
        ],
      },
    }

    const request = await verifierFlow.createAuthzRequest(
      verifierId,
      'vp_token',
      client_id,
      'direct_post',
      query,
      false,
      {
        response_uri: `${baseUrl}/verifiers/${encodeURIComponent(verifierId)}/callback`,
        base_url: baseUrl,
      }
    )

    const encoded = Object.entries(request)
      .map(([key, value]) => {
        const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
        return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
      })
      .join('&')

    return c.text(`openid4vp://authorize?${encoded}`)
  } catch (error) {
    return c.json({ error: 'internal_server_error' }, 400)
  }
})
```


**Example**

**Request**

```bash
curl --location 'http://localhost:8080/verify/request' \
--header 'Content-Type: application/json' \
--data ' {
 "credentialId": "UniversityDegreeCredential"
}'
```
**Response**

```
openid4vp://authorize?response_type=vp_token&client_id=x509_san_dns%3Alocalhost&client_metadata=%7B%22client_name%22%3A%22Sample%20Verifier%20App%22%2C%22client_uri%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22jwks%22%3A%7B%22keys%22%3A%5B%7B%22kty%22%3A%22EC%22%2C%22x%22%3A%220_3S7HedSywaxlekdt6Or8pkcR13hQaCPMqt9cuZBVc%22%2C%22y%22%3A%22ZVXSCL3HlnMQWKrwMyIAe5wsAIWd3Eu1misKFr3POdA%22%2C%22crv%22%3A%22P-256%22%7D%5D%7D%2C%22vp_formats%22%3A%7B%22jwt_vp%22%3A%7B%22alg%22%3A%5B%22ES256%22%5D%7D%7D%2C%22client_id_scheme%22%3A%22redirect_uri%22%2C%22authorization_signed_response_alg%22%3A%22ES256%22%7D&nonce=5cf220cd62d3453192b1af4f6ba88b87&response_mode=direct_post&response_uri=http%3A%2F%2Flocalhost%3A8080%2Fverifiers%2Fhttp%253A%252F%252Flocalhost%253A8080%2Fcallback&client_id_scheme=x509_san_dns&presentation_definition=%7B%22id%22%3A%2243bff439-6929-4843-931f-5b7530ed8010%22%2C%22name%22%3A%22Test%20Name%22%2C%22purpose%22%3A%22Test%20Purpose%22%2C%22input_descriptors%22%3A%5B%7B%22id%22%3A%22UniversityDegreeCredential%22%2C%22format%22%3A%7B%22jwt_vc_json%22%3A%7B%22proof_type%22%3A%5B%22ES256%22%5D%7D%7D%2C%22constraints%22%3A%7B%22fields%22%3A%5B%7B%22path%22%3A%5B%22%24.vc.type%22%5D%2C%22filter%22%3A%7B%22type%22%3A%22array%22%2C%22contains%22%3A%7B%22const%22%3A%22VerifiableCredential%22%7D%7D%7D%5D%7D%7D%5D%7D
```


#### 1-2. JAR (JWT Authorization Request) Format Request

This endpoint uses a JWT Authorization Request (JAR) to generate and store a Request Object and returns an authorization request URI for the Wallet to retrieve it.

- **Endpoint**: `POST /verify/request-object`
- **Request body (JSON)**
  - Includes the following fields:
      - `query.presentation_definition`
      - `state`
      - `response_uri`
      - `client_id`: specify as `redirect_uri:<URL>` or `x509_san_dns:<hostname>`
- **Response**
  - `200 OK`: Returns an authorization request URL in the `openid4vp://authorize?...` format as text (including `request_uri` information).
  - `400 Bad Request`: When the JSON is invalid or when there is an issue with the request content.

- Actual code
```typescript
  verifyApp.post('/verify/request-object', async (c) => {
    try {
      const verifierId = VerifierClientId(baseUrl)

      const body = await c.req.json()
      if (!body) throw err('INVALID_REQUEST')
      const {
        client_id: clientId,
        state,
        response_uri: responseUri,
        query: presentationDefinition,
      } = body
      const request = await verifierFlow.createAuthzRequest(
        verifierId,
        'vp_token',
        clientId,
        'direct_post',
        presentationDefinition,
        true,
        {
          state: state,
          base_url: baseUrl,
          response_uri: responseUri,
        }
      )
      const encoded = Object.entries(request)
        .map(([key, value]) => {
          const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
          return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
        })
        .join('&')

      return c.text(`openid4vp://authorize?${encoded}`)
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })

```

**Example**

**Request**

```bash
curl --location 'http://localhost:8080/verify/request-object' \
--header 'Content-Type: application/json' \
--data '{
 "query": {
  "presentation_definition": {
    "id": "example",
    "name": "",
    "purpose": "",
    "submission_requirements": [],
    "input_descriptors": [
      {
        "id": "University Degree Credentials",
        "name": "Example",
        "purpose": "to verify your UniversityDegree Credential",
        "format": {
            "jwt_vp":{
                "alg":["RS256"]
            }
        },
        "constraints": {
          "fields": [
            {
              "path": ["$.type"],
              "filter": {
                "type": "array",
                "cotains":{
                    "type":"string",
                    "const":"UniversityDegreeCredential"
                }
              }
            }
          ]
        }
      }
    ]
  }
  },
  "state": "example-state",
  "response_uri": "http://localhost:8080/verify/callback",
  "client_id": "x509_san_dns:localhost"
}'
```

**Response**
```
openid4vp://authorize?client_id=x509_san_dns%3Alocalhost&request_uri=http%3A%2F%2Flocalhost%3A8080%2Fverifiers%2Fhttp%253A%252F%252Flocalhost%253A8080%2Frequest.jwt%2F0aab8b5062b0410ba96f1afaf3925f93
```



### 2. Retrieving the Request Object

This is an endpoint for Wallets and other clients to retrieve the Request Object (JWT) that was stored when the JAR was generated.

- **Endpoint**: `GET /verify/request.jwt/:request-object-Id`
- **Path parameter**
  - `request-object-Id`: Specify the ID at the end of the `request_uri` returned in the response from `createAuthzRequest`.
- **Response**
  - `200 OK`: Returns the JWT body with `Content-Type: application/oauth-authz-req+jwt`.
  - `400 Bad Request`: When the ID is invalid or an internal error occurs.

- Actual code
```typescript
verifyApp.get('/verify/request.jwt/:request-object-Id', async (c) => {
  try {
    const verifierId = VerifierClientId(baseUrl)
    const requestObjectId = RequestObjectId(c.req.param('request-object-Id'))
    const jar = await verifierFlow.findRequestObject(verifierId, requestObjectId)
    return c.body(jar, 200, {
      'Content-Type': 'application/oauth-authz-req+jwt',
    })
  } catch (err) {
    return c.json(handleError(err), 400)
  }
})
```

**Example**

**Request**

```bash
curl --location 'http://localhost:8080/verify/request.jwt/fca442d1b80a43c7bb3faeb13e9a3b73'
```
**Response**
```
eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJ4NWMiOlsiXG5NSUlDSGpDQ0FjT2dBd0lCQWdJVVpYOUJTNUNET0pSVzJ0MUZLMVVETXQvUXdNRXdDZ1lJS29aSXpqMEVBd0l3XG5JVEVMTUFrR0ExVUVCaE1DUjBJeEVqQVFCZ05WQkFNTUNVOUpSRVlnVkdWemREQWVGdzB5TkRFeE1qVXdPRE0yXG5NRFJhRncwek5ERXhNak13T0RNMk1EUmFNQ0V4Q3pBSkJnTlZCQVlUQWtkQ01SSXdFQVlEVlFRRERBbFBTVVJHXG5JRlJsYzNRd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFUVC9kTHNkNTFMTEJyR1Y2UjIzbzZ2XG55bVJ4SFhlRkJvSTh5cTMxeTVrRlYyVlYwZ2k5eDVaekVGaXE4RE1pQUh1Y0xBQ0ZuZHhMdFpvckNoYTl6em5RXG5vNEhZTUlIVk1CMEdBMVVkRGdRV0JCUzVjYmRnQWVNQmk1d3hwYnB3SVNHaFNoQVdFVEFmQmdOVkhTTUVHREFXXG5nQlM1Y2JkZ0FlTUJpNXd4cGJwd0lTR2hTaEFXRVRBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUlHQkJnTlZIUkVFXG5lakI0Z2hCM2QzY3VhR1ZsYm1GdUxtMWxMblZyZ2gxa1pXMXZMbU5sY25ScFptbGpZWFJwYjI0dWIzQmxibWxrXG5MbTVsZElJSmJHOWpZV3hvYjNOMGdoWnNiMk5oYkdodmMzUXVaVzF2WW1sNExtTnZMblZyZ2lKa1pXMXZMbkJwXG5aQzFwYzNOMVpYSXVZblZ1WkdWelpISjFZMnRsY21WcExtUmxNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNQXG5ibkx4Q0krV1IxdmhPVytBOEt6bkFXdjFNSm8rWUViMU1JNDVOS1cvVlFJaEFMenNxb3g4VnVCUndOMmRsNUxrXG5wbnhQNG9IOXA2SDBBT1ptS1ArWTduWFNcbiJdfQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X3Nhbl9kbnM6bG9jYWxob3N0Iiwic3RhdGUiOiIwMzg0NzViMDEyNmI0Njg0YTIyNmJjODBlYWM5MzRiNiIsImNsaWVudF9tZXRhZGF0YSI6eyJjbGllbnRfbmFtZSI6IlNhbXBsZSBWZXJpZmllciBBcHAiLCJjbGllbnRfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsIngiOiIwXzNTN0hlZFN5d2F4bGVrZHQ2T3I4cGtjUjEzaFFhQ1BNcXQ5Y3VaQlZjIiwieSI6IlpWWFNDTDNIbG5NUVdLcndNeUlBZTV3c0FJV2QzRXUxbWlzS0ZyM1BPZEEiLCJjcnYiOiJQLTI1NiJ9XX0sInZwX2Zvcm1hdHMiOnsiand0X3ZwIjp7ImFsZyI6WyJFUzI1NiJdfX0sImNsaWVudF9pZF9zY2hlbWUiOiJyZWRpcmVjdF91cmkiLCJhdXRob3JpemF0aW9uX3NpZ25lZF9yZXNwb25zZV9hbGciOiJFUzI1NiJ9LCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdmVyaWZpZXJzL2h0dHAlM0ElMkYlMkZsb2NhbGhvc3QlM0E4MDgwL2NhbGxiYWNrIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiYXVkIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92MiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiODkyMGVjMGUtZDc3YS00MmJlLTk4OWQtZTU1MTBjZmFhNjlkIiwibmFtZSI6IlRlc3QgTmFtZSIsInB1cnBvc2UiOiJUZXN0IFB1cnBvc2UiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiI4ZjJmZWM3ZC1hMmI5LTRhZTEtYTdmMi1mMGJmMTgyMWYzY2UiLCJmb3JtYXQiOnsiand0X3ZjX2pzb24iOnsicHJvb2ZfdHlwZSI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjLnR5cGUiXSwiZmlsdGVyIjp7InR5cGUiOiJhcnJheSIsImNvbnRhaW5zIjp7ImNvbnN0IjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwifX19XX19XX0sImlhdCI6MTc2MTkwMTAzOCwibm9uY2UiOiI0YTVhYTQ1ZjllMWQ0N2FmOTkzNWY5OWEyM2M5ZDNlNiJ9.Kc4FFI1cNXJCO5nI8Yy0jnlYtLFDL-Wr-AoWtq8sasI0grzP1Zco8Zw9Ug2zybtMnn_o6XLDnnRj8jb2g0Y0TQ
```



### 3. Receiving and Verifying vp_token

This is an endpoint where the Verifier receives the `vp_token` returned from the Wallet and performs verification (VP verification).

- **Endpoint**: `POST /verify/callback`
- **Request body (JSON)**
  - JSON containing OpenID4VP Authorization Response fields such as `vp_token` and `presentation_submission`.
  - Validation is performed using the `VerifierAuthorizationResponse` schema.
- **Response**
  - `200 OK`: Returns a JSON response containing `message` and the verified `authorization_response`.
  - `400 Bad Request`: Returned when validation fails or a verification error occurs.

- Actual code
```typescript
verifyApp.post('/verify/callback', async (c) => {
  try {
    const verifierId = VerifierClientId(baseUrl)
    const json = await c.req.json()

    const authorizationResponse = VerifierAuthorizationResponse(json)

    await verifierFlow.verifyPresentations(verifierId, authorizationResponse)

    return c.json({
      message: 'Callback received successfully',
      authorization_response: authorizationResponse,
    })
  } catch (err) {
    return c.json(handleError(err), 400)
  }
})
```

**Example**

**Request**

```bash
curl --location 'http://localhost:8080/verify/callback' \
--data '{
	"vp_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlWWl3SE5lTVlhajIxV285alBDb3d0bkJyWThoZThVQ0s4WlpOMW1oaHg4UE0iLCJub25jZSI6ImUzMDNhYzUzMWM1YjQ3ODM4OWRkN2M0NzQ0MDRlM2I5IiwidnAiOnsidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUoyWXlJNmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNKZExDSnBaQ0k2SW1oMGRIQnpPaTh2YldWa1lXeGliMjlyTFdSbGRpMWhjSEF0YVhOemRXVnlMbmRsWWk1aGNIQXZZM0psWkdWdWRHbGhiSE12UzJNME1GcG1XblIwVlVwV1pGRnJORk5JYm5ZaUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpVFdWa1lXeENiMjlyVFdWa1lXd2lMQ0pOUkVJME1EUXlZek5sTWpWaU9UUTBOV0UwT0RobU1EbGhPRE00WVRNME9EVTROeUpkTENKcGMzTjFaWElpT2lKb2RIUndjem92TDIxbFpHRnNZbTl2YXkxa1pYWXRZWEJ3TFdsemMzVmxjaTUzWldJdVlYQndMMmx6YzNWbGNuTXZXVzlsZVRsSVJtcFVXVkI1WTIxa2NYZGFWVk1pTENKcGMzTjFZVzVqWlVSaGRHVWlPaUl5TURJMExURXlMVEkwVkRBeE9qTTRPalF6TGpZek1sb2lMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKcFpDSTZJbVJwWkRwclpYazZla1J1WVdWWmFYZElUbVZOV1dGcU1qRlhiemxxVUVOdmQzUnVRbkpaT0dobE9GVkRTemhhV2s0eGJXaG9lRGhRVFNJc0ltMWxaR0ZzYVhOMFQyWWlPbnNpYm1GdFpTSTZXM3NpZG1Gc2RXVWlPaUozYjI1a1pYSnNZVzVrSWl3aWJHOWpZV3hsSWpvaWFtRXRTbEFpZlYwc0ltUmxjMk55YVhCMGFXOXVJanBiZXlKMllXeDFaU0k2SW5kdmJtUmxjbXhoYm1RaUxDSnNiMk5oYkdVaU9pSnFZUzFLVUNKOVhTd2liRzluYnlJNlczc2lkbUZzZFdVaU9uc2lkWEpwSWpvaWFIUjBjSE02THk5emRHOXlZV2RsTG1kdmIyZHNaV0Z3YVhNdVkyOXRMMjFsWkdGc1ltOXZheTFrWlhZdVlYQndjM0J2ZEM1amIyMHZhWE56ZFdWeUpUSkdkakVsTWtacGMzTjFaWEp6SlRKR1dXOWxlVGxJUm1wVVdWQjVZMjFrY1hkYVZWTWxNa1pqY21Wa1pXNTBhV0ZzY3lVeVJrSndkR3RYZFcxSFFVUXlNWHBUTm5WU2JUSmhMbkJ1WnlKOUxDSnNiMk5oYkdVaU9pSnFZUzFLVUNKOVhYMTlmU3dpYVhOeklqb2lhSFIwY0hNNkx5OXRaV1JoYkdKdmIyc3RaR1YyTFdGd2NDMXBjM04xWlhJdWQyVmlMbUZ3Y0M5cGMzTjFaWEp6TDFsdlpYazVTRVpxVkZsUWVXTnRaSEYzV2xWVElpd2libUptSWpveE56TTFNREEwTXpJek5qTXlMQ0p6ZFdJaU9pSmthV1E2YTJWNU9ucEVibUZsV1dsM1NFNWxUVmxoYWpJeFYyODVhbEJEYjNkMGJrSnlXVGhvWlRoVlEwczRXbHBPTVcxb2FIZzRVRTBpZlEuX1dlOUEyalJnR3VrYzg5MnpXVFpxLUFTcnBQM3dZeHhXOFM4XzdwT3ZqQldZbTVQa1U5UlhoUWY2SmlzTGxPT1NhNVFaX3JBNGxmNEU3dDZubG9FaHciXSwiaG9sZGVyIjoiZGlkOmtleTp6RG5hZVlpd0hOZU1ZYWoyMVdvOWpQQ293dG5Cclk4aGU4VUNLOFpaTjFtaGh4OFBNIn19.5Mjnb7Y_1CJWEL5LgiFIZypeZthwrAODPrL5TcAy-lw95797Z_-L2hvyxvDf5HV1CIaqt3xfRdy7nJMZYTKnTw",
	"presentation_submission": {
		"id": "BptkWumGAD21zS6uRm2a",
		"definition_id": "3cf37e60-e6e4-4d67-acff-3623586a7c4c",
		"descriptor_map": [
			{
				"id": "BptkWumGAD21zS6uRm2a",
				"format": "jwt_vp",
				"path": "$",
				"path_nested": {
					"id": "BptkWumGAD21zS6uRm2a",
					"format": "jwt_vc",
					"path": "$.verifiableCredential[0]"
				}
			}
		]
	},
	"state": "tEoHpMJo1896FnkXJxVu"
}'
```

**Response**

```
{
    "message": "Callback received successfully",
    "authorization_response": {
        "vp_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.eyJpc3MiOiJkaWQ6a2V5OnpEbmFlWWl3SE5lTVlhajIxV285alBDb3d0bkJyWThoZThVQ0s4WlpOMW1oaHg4UE0iLCJub25jZSI6ImUzMDNhYzUzMWM1YjQ3ODM4OWRkN2M0NzQ0MDRlM2I5IiwidnAiOnsidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUoyWXlJNmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNKZExDSnBaQ0k2SW1oMGRIQnpPaTh2YldWa1lXeGliMjlyTFdSbGRpMWhjSEF0YVhOemRXVnlMbmRsWWk1aGNIQXZZM0psWkdWdWRHbGhiSE12UzJNME1GcG1XblIwVlVwV1pGRnJORk5JYm5ZaUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpVFdWa1lXeENiMjlyVFdWa1lXd2lMQ0pOUkVJME1EUXlZek5sTWpWaU9UUTBOV0UwT0RobU1EbGhPRE00WVRNME9EVTROeUpkTENKcGMzTjFaWElpT2lKb2RIUndjem92TDIxbFpHRnNZbTl2YXkxa1pYWXRZWEJ3TFdsemMzVmxjaTUzWldJdVlYQndMMmx6YzNWbGNuTXZXVzlsZVRsSVJtcFVXVkI1WTIxa2NYZGFWVk1pTENKcGMzTjFZVzVqWlVSaGRHVWlPaUl5TURJMExURXlMVEkwVkRBeE9qTTRPalF6TGpZek1sb2lMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKcFpDSTZJbVJwWkRwclpYazZla1J1WVdWWmFYZElUbVZOV1dGcU1qRlhiemxxVUVOdmQzUnVRbkpaT0dobE9GVkRTemhhV2s0eGJXaG9lRGhRVFNJc0ltMWxaR0ZzYVhOMFQyWWlPbnNpYm1GdFpTSTZXM3NpZG1Gc2RXVWlPaUozYjI1a1pYSnNZVzVrSWl3aWJHOWpZV3hsSWpvaWFtRXRTbEFpZlYwc0ltUmxjMk55YVhCMGFXOXVJanBiZXlKMllXeDFaU0k2SW5kdmJtUmxjbXhoYm1RaUxDSnNiMk5oYkdVaU9pSnFZUzFLVUNKOVhTd2liRzluYnlJNlczc2lkbUZzZFdVaU9uc2lkWEpwSWpvaWFIUjBjSE02THk5emRHOXlZV2RsTG1kdmIyZHNaV0Z3YVhNdVkyOXRMMjFsWkdGc1ltOXZheTFrWlhZdVlYQndjM0J2ZEM1amIyMHZhWE56ZFdWeUpUSkdkakVsTWtacGMzTjFaWEp6SlRKR1dXOWxlVGxJUm1wVVdWQjVZMjFrY1hkYVZWTWxNa1pqY21Wa1pXNTBhV0ZzY3lVeVJrSndkR3RYZFcxSFFVUXlNWHBUTm5WU2JUSmhMbkJ1WnlKOUxDSnNiMk5oYkdVaU9pSnFZUzFLVUNKOVhYMTlmU3dpYVhOeklqb2lhSFIwY0hNNkx5OXRaV1JoYkdKdmIyc3RaR1YyTFdGd2NDMXBjM04xWlhJdWQyVmlMbUZ3Y0M5cGMzTjFaWEp6TDFsdlpYazVTRVpxVkZsUWVXTnRaSEYzV2xWVElpd2libUptSWpveE56TTFNREEwTXpJek5qTXlMQ0p6ZFdJaU9pSmthV1E2YTJWNU9ucEVibUZsV1dsM1NFNWxUVmxoYWpJeFYyODVhbEJEYjNkMGJrSnlXVGhvWlRoVlEwczRXbHBPTVcxb2FIZzRVRTBpZlEuX1dlOUEyalJnR3VrYzg5MnpXVFpxLUFTcnBQM3dZeHhXOFM4XzdwT3ZqQldZbTVQa1U5UlhoUWY2SmlzTGxPT1NhNVFaX3JBNGxmNEU3dDZubG9FaHciXSwiaG9sZGVyIjoiZGlkOmtleTp6RG5hZVlpd0hOZU1ZYWoyMVdvOWpQQ293dG5Cclk4aGU4VUNLOFpaTjFtaGh4OFBNIn19.5Mjnb7Y_1CJWEL5LgiFIZypeZthwrAODPrL5TcAy-lw95797Z_-L2hvyxvDf5HV1CIaqt3xfRdy7nJMZYTKnTw",
        "presentation_submission": {
            "id": "BptkWumGAD21zS6uRm2a",
            "definition_id": "3cf37e60-e6e4-4d67-acff-3623586a7c4c",
            "descriptor_map": [
                {
                    "id": "BptkWumGAD21zS6uRm2a",
                    "format": "jwt_vp",
                    "path": "$",
                    "path_nested": {
                        "id": "BptkWumGAD21zS6uRm2a",
                        "format": "jwt_vc",
                        "path": "$.verifiableCredential[0]"
                    }
                }
            ]
        },
        "state": "tEoHpMJo1896FnkXJxVu"
    }
}
```


## 4. Registering Verifier Metadata{#initializeVerifierMetadata}

- The code in this guide registers verifier metadata at startup according to the steps in this section. For production use or your own development environment, adjust `BASE_URL` and the metadata/certificate files as appropriate.

Metadata file (external JSON):
- Location: `vcknots/server/samples/verifier_metadata.json`
- Example (contents):
```json
{
  "client_name": "My Verifier App",
  "client_uri": "http://localhost:8080",
  "vp_formats": {
    "jwt_vp": {
      "alg": ["ES256"]
    }
  },
  "client_id_scheme": "redirect_uri"
}
```

Locations of certificate files:
- Private key: `vcknots/server/samples/certificate-openid-test/private_key_openid.pem`
- Certificate: `vcknots/server/samples/certificate-openid-test/certificate_openid.pem`


```typescript
// Initialize metadata with BASE_URL applied
const baseUrl = process.env.BASE_URL ?? 'http://localhost:8080'

// Use the sample verifier metadata (JSON) that has been read (e.g., verifierMetadataConfig)
verifierMetadataConfig.client_uri = baseUrl
await initializeVerifierMetadata(baseUrl, verifierMetadataConfig)
```

```typescript
// Read the certificate/private key and register the metadata
async function initializeVerifierMetadata(verifierId: string, metadata: VerifierMetadata) {
  try {
    const clientId = VerifierClientId(verifierId)

    const __dirname = dirname(fileURLToPath(import.meta.url))
    const privateKeyPath = join(
      __dirname,
      '..',
      'samples/certificate-openid-test/private_key_openid.pem'
    )
    const certificatePath = join(
      __dirname,
      '..',
      'samples/certificate-openid-test/certificate_openid.pem'
    )
    const option = {
      privateKey: readFileSync(privateKeyPath, 'utf-8'),
      certificate: readFileSync(certificatePath, 'utf-8'),
      format: 'pem',
      alg: 'ES256',
    } as const

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
- `DUPLICATE_VERIFIER`: Metadata with the same `verifierId` is already registered
- `INTERNAL_SERVER_ERROR`: `options.alg` is not specified (required when specifying a public key/certificate)
- `INVALID_CERTIFICATE`: The provided certificate is invalid

#### CreateVerifierMetadataOptions{#CreateVerifierMetadataOptions}
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
  query: DeepPartialUnknown<PresentationExchange> | DeepPartialUnknown<Dcql>,
  isRequestUri: boolean,
  options: CreateAuthzRequestOptions
): Promise<AuthorizationRequest>
```


**Parameters**:
- `verifierId`: Identifier of the Verifier ([VerifierClientId](#VerifierClientId))
- `response_type`: Response type ('vp_token')
- `client_id`: Client ID (see [OpenID for Verifiable Presentations 5.2 Existing Parameters, client_id](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.2))
- `response_mode`: Response mode ('direct_post' | 'query' | 'fragment' | 'dc_api.jwt' | 'dc_api')
- `query`: presentation_definition ([5.4. presentation_definition Parameter](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.4)) or DCQL query ([6. Digital Credentials Query Language (DCQL)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-digital-credentials-query-l))
- `isRequestUri`: Flag indicating whether to use a request URI  
  - `isRequestUri = true` → Request URI format (stores the Request Object externally)  
  - `isRequestUri = false` → Direct format (includes parameters directly in the authorization request)
- `options`: Options for creating the request ([CreateAuthzRequestOptions](#CreateAuthzRequestOptions))

**Return value**:
- Returns an `AuthorizationRequest` object ([AuthorizationRequest](#AuthorizationRequest)). This object takes one of the following forms:

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
    client_id_scheme: string,
    client_metadata: VerifierMetadata,
    nonce: string,
    // presentaion_defition or dcql_query
  }
  ```

**Error cases**:
- `UNSUPPORTED_CLIENT_ID_SCHEME`: An unsupported client_id_scheme was specified
- `CERTIFICATE_NOT_FOUND`: Certificate is not registered when using x509_san_dns or x509_san_uri
- `INVALID_REQUEST`: options.base_url is not specified even though isRequestUri = true



#### CreateAuthzRequestOptions {#CreateAuthzRequestOptions}
Defines the options used when creating an authorization request.

For detailed type definitions, see [verifier.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts).


**Notes**:
- When `isRequestUri` is `true`, `base_url` is required.
- If `response_uri` is not specified, `${verifierId}/post` is used by default.
- For security reasons, it is recommended to use a random, hard-to-predict value for `state`.

#### AuthorizationRequest (response type of createAuthzRequest) {#AuthorizationRequest}

This is the response type returned by `createAuthzRequest`. It is combined with the PE (Presentation Exchange) or DCQL schema, either as a “Request URI format” using `request_uri`, or as a “direct format” that includes the parameters directly.
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
- `VERIFIER_NOT_FOUND`: The specified Verifier does not exist
- `REQUEST_OBJECT_NOT_FOUND`: The specified Request Object does not exist
- `PROVIDER_NOT_FOUND`: Provider for the Authorization Request JAR cannot be found
- `AUTHZ_VERIFIER_KEY_NOT_FOUND`: Signing key provider for the specified algorithm cannot be found
- `INTERNAL_SERVER_ERROR`: Failed to generate the signature for the Request Object

**Notes**:
- A Request Object can be retrieved only once.
- Calling with the same Request Object ID multiple times results in an error.



#### RequestObjectId{#RequestObjectId}
A unique identifier for a Request Object (authorization request JAR).

For detailed type definitions, see [request-object-id.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/request-object-id.types.ts).


#### FindRequestObjectOptions{#FindRequestObjectOptions}
Defines the options used when retrieving a Request Object.

For detailed type definitions, see [verifier.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts).



### verifyPresentations
Verifies the VP token.

```typescript
verifyPresentations(
  id: ClientId,
  response: AuthorizationResponse
): Promise<void>
```

**Parameters**:
- `id`: Identifier of the Verifier ([VerifierClientId](#VerifierClientId))
- `response`: Information used for verification ([Verifierauthorizationresponse](#Verifierauthorizationresponse))

**Return value**:
- None


**Error cases**:
- `VERIFIER_NOT_FOUND`: The Verifier does not exist
- `UNSUPPORTED_VP_TOKEN`: The VP token format is not supported
- `INVALID_NONCE`: Occurs when the nonce issued at the time of the authorization request is not included in `vp_token`, or does not match. The Wallet must always return a `vp_token` that includes the nonce provided in the authorization request.
- `INVALID_CREDENTIAL`: Invalid credential
- `INVALID_PRESENTATION_SUBMISSION`: Invalid presentation_submission
- `HOLDER_BINDING_FAILED`: Holder binding verification failed




### findVerifierCertificate
Retrieves the Verifier’s certificate.

```typescript
findVerifierCertificate(id: ClientId): Promise<Certificate | null>
```

**Parameters**:
- `id`: Identifier of the Verifier ([VerifierClientId](#VerifierClientId))

**Return value**:
- Certificate object ([Certificate](#Certificate)), or `null` if it does not exist


#### Certificate{#Certificate}
Type that represents the certificate chain held by the Verifier (an array of PEM-formatted strings). Each element must have passed PEM format validation.

For detailed type definitions, see [signature-key.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/signature-key.types.ts).


Note:
- The recommended chain order is “leaf → intermediate → root”.
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

- **Q: Certificate-related error**: `INVALID_CERTIFICATE`
  - **A:** Check that the path to the certificate file is correct and that the file exists. Also verify that the certificate is valid.

- **Q: Metadata validation error**:
  - **A:** Check that the provided metadata conforms to the VerifierMetadata schema.

- **Q: Error when creating authorization request**: `invalid_request`
  - **A:** Verify that all required parameters have been provided.

- **Q: Error retrieving request object**: `REQUEST_OBJECT_NOT_FOUND`
  - **A:** A request object can be retrieved only once. Calling with the same Request Object ID multiple times results in an error.

- **Q: Nonce verification error for vp_token**: fails with `INVALID_NONCE` – nonce is not valid.
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


