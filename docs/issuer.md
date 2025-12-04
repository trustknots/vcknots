---
sidebar_position: 2
---

# How to Set Up and Use the Issuer Feature

This guide explains how to set up and use the Issuer feature of VCKnots.

## 1. Prerequisites

- Supports OpenID for Verifiable Credential Issuance - draft 13 ([OpenID for Verifiable Credential Issuance - draft 13](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html))
- Node.js v14 or later is installed
- TypeScript is configured
- This document is based on the sample implementation of the server
- The Hono web framework is used, but other frameworks can also be used
- The Pre-Authorized Code Flow is the flow currently supported.

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
import { initializeIssuerFlow, CredentialIssuer, CredentialIssuerMetadata } from '@trustknots/vcknots/issuer'
import { initializeAuthzFlow, AuthorizationServerIssuer, AuthorizationServerMetadata, AuthzTokenRequest } from '@trustknots/vcknots/authz'

const app = new Hono();

// Creates VcknotsContext
const context = initializeContext({
  debug: process.env.NODE_ENV !== "production",
});

// Creates IssuerFlow and AuthzFlow instances
const issuerFlow = initializeIssuerFlow(context);
const authzFlow = initializeAuthzFlow(context);
```

## 3. Sample Implementation of the Issuer Feature

### Parameters

#### `:issuer` Parameter

The `:issuer` parameter used in Issuer endpoints represents the identifier of the Issuer.

**Type**: URI string of type `CredentialIssuer`

**Example**:
```typescript
// HTTPS URI format
const issuerId = "https://issuer.example.com"
```

**Usage**:
- Managing issuer metadata
- Creating credential offers
- Issuing credentials
- Managing the authorization server

**Notes**:
- Must be in URL format (validated with z.string().url())
- It is recommended to use the HTTPS scheme
- If it contains special characters, make sure they are properly encoded

### 1. Initializing Default Metadata

Example of initializing the default Issuer and authorization server metadata when the server starts:

```typescript
import issuerMetadataConfigRaw from '../samples/issuer_metadata.json' with { type: 'json' }
import authorizationMetadataConfigRaw from '../samples/authorization_metadata.json' with {
  type: 'json',
}

const issuerMetadataConfig = CredentialIssuerMetadata(issuerMetadataConfigRaw)
const authorizationMetadataConfig = AuthorizationServerMetadata(authorizationMetadataConfigRaw)

serve({ fetch: app.fetch, port: Number.parseInt(process.env.PORT ?? '8080') }, async (info) => {
  console.log(`Server is running on http://localhost:${info.port}`)

  // Run initialization (using default settings)
  const issuerMetadata = CredentialIssuerMetadata({
    ...issuerMetadataConfig,
    credential_issuer: CredentialIssuer(baseUrl),
    authorization_servers: [baseUrl],
    credential_endpoint: `${baseUrl}/issue/credentials`,
    batch_credential_endpoint: `${baseUrl}/batch_credential`,
    deferred_credential_endpoint: `${baseUrl}/deferred_credential`,
  })

  await initializeIssuerMetadata(issuerMetadata);

  authorizationMetadataConfig.issuer = AuthorizationServerIssuer(baseUrl);
  authorizationMetadataConfig.authorization_endpoint = `${baseUrl}/issue/authorize`;
  authorizationMetadataConfig.token_endpoint = `${baseUrl}/issue/token`;
  await initializeAuthzMetadata(authorizationMetadataConfig)
})

async function initializeIssuerMetadata(issuerMetadata: CredentialIssuerMetadata) {
  try {
    await issuerFlow.createIssuerMetadata(issuerMetadata)
    return true
  } catch (error) {
    console.error('Error initializing issuer metadata:', error)
    return false
  }
}


async function initializeAuthzMetadata(authzMetadata: AuthorizationServerMetadata) {
  try {
    await authzFlow.createAuthzServerMetadata(authzMetadata)
    return true
  } catch (error) {
    console.error('Error initializing authz metadata:', error)
    return false
  }
}

```

### 2. Retrieving Issuer Metadata

Endpoint to retrieve Issuer metadata:

```typescript
app.get('.well-known/openid-credential-issuer', async (c) => {
    try {
      const issuer = CredentialIssuer(baseUrl)
      const metadata = await issuerFlow.findIssuerMetadata(issuer)

      if (!metadata) {
        return c.notFound()
      }

      return c.json(metadata)
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })
```

**Example**:

**Request**

```bash
curl http://localhost:8080/.well-known/openid-credential-issuer
```

**Response**

```json
{
	"credential_issuer": "http://localhost:8080",
	"authorization_servers": [
		"http://localhost:8080"
	],
	"credential_endpoint": "http://localhost:8080/issue/credentials",
	"batch_credential_endpoint": "http://localhost:8080/issue/batch_credential",
	"deferred_credential_endpoint": "http://localhost:8080/issue/deferred_credential",
	"credential_configurations_supported": {
		"UniversityDegreeCredential": {
			"format": "jwt_vc_json",
			"scope": "UniversityDegree",
			"cryptographic_binding_methods_supported": [
				"did:example"
			],
			"credential_definition": {
				"type": [
					"VerifiableCredential",
					"UniversityDegreeCredential"
				],
				"credentialSubject": {
					"given_name": {
						"mandatory": true,
						"value_type": "string",
						"display": [
							{
								"name": "Given Name",
								"locale": "en-US"
							}
						]
					},
					"family_name": {
						"display": [
							{
								"name": "Surname",
								"locale": "en-US"
							}
						]
					},
					"degree": {},
					"gpa": {
						"display": [
							{
								"name": "GPA"
							}
						]
					}
				}
			},
			"proof_types_supported": {
				"jwt": {
					"proof_signing_alg_values_supported": [
						"ES256"
					]
				}
			},
			"credential_signing_alg_values_supported": [
				"ES256"
			],
			"display": [
				{
					"name": "University Credential",
					"locale": "en-US",
					"logo": {
						"uri": "https://university.example.edu/public/logo.png",
						"alt_text": "a square logo of a university"
					},
					"background_color": "#12107c",
					"text_color": "#FFFFFF"
				}
			]
		}
	},
	"display": [
		{
			"name": "Example University",
			"locale": "en-US"
		},
		{
			"name": "Example Université",
			"locale": "fr-FR"
		}
	]
}
```

### 3. Creating a Credential Offer

Endpoint to create a credential offer:

```typescript
app.post('issue/configurations/:configuration/offer', async (c) => {
    try {
      const issuer = CredentialIssuer(baseUrl)
      const configurations = [CredentialConfigurationId(c.req.param('configuration'))]

      const offer = await issuerFlow.offerCredential(issuer, configurations, {
        usePreAuth: true,
      })
      console.log('offer:', offer)

      return c.text(
        `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`
      )
    } catch (err) {
      const errorResponse = handleError(err)
      return c.json(errorResponse, 400)
    }
  })

```

**Example**:

**Request**

```bash
curl -X POST http://localhost:8080/issue/configurations/UniversityDegreeCredential/offer
```

**Response**

```raw
openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22343ce17f1d274aa8bb3d19c140484889%22%7D%7D%7D
```



### 4. Retrieving Authorization Server Metadata

Endpoint to retrieve authorization server metadata:

```typescript
app.get("/.well-known/oauth-authorization-server", async (c) => {
    try {
      const authz = AuthorizationServerIssuer(baseUrl)
      const metadata = await authzFlow.findAuthzServerMetadata(authz)

      if (!metadata) {
        return c.notFound()
      }

      return c.json(metadata)
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })
```

**Example**:

**Request**

```bash
curl  http://localhost:8080/.well-known/oauth-authorization-server
```

**Response**

```json
{
  "pre-authorized_grant_anonymous_access_supported": true,
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/authz/authorize",
  "token_endpoint": "http://localhost:8080/authz/token",
  "scopes_supported": [
      "openid"
  ],
  "response_types_supported": [
      "code"
  ]
}
```

### 5. Issuing an Access Token

Endpoint to issue an access token:

```typescript
app.post("authz/token", async (c) => {
  const request = await c.req.formData();
  const tokenRequest = AuthzTokenRequest(Object.fromEntries(request.entries()));
  console.log("tokenRequest:", tokenRequest);
  const issuer = AuthorizationServerIssuer(issuerId);

  const accessToken = await authzFlow.createAccessToken(issuer, tokenRequest);
  return c.json(accessToken);
});


```

**Example**:

**Request**

```bash
curl -X POST http://localhost:8080/authz/token \
  -H "Content-Type: application/json" \
  -d ' {
    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": "343ce17f1d274aa8bb3d19c140484889"
  }'
```

**Response**

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJzdWIiOiIzNDNjZTE3ZjFkMjc0YWE4YmIzZDE5YzE0MDQ4NDg4OSIsImV4cCI6MTc2MTk3NjE1NiwiaWF0IjoxNzYxODg5NzU2fQ.vsV71EEtAo36jcb9N8un2cn36Oo_H1qtKuIp0uerdvI2jNcBhN7ltGeqmk1AVZhpk5kQZcfbkSiHje-j1Iv1zg",
  "token_type": "bearer",
  "expires_in": 86400,
  "c_nonce": "3ccc7973abef4102ad70a871e200304b",
  "c_nonce_expires_in": 300000
}
```

### 6. Issuing a Credential

Endpoint to issue a credential:

```typescript
app.post('issue/credentials', async (c) => {
  try {
    const issuer = AuthorizationServerIssuer(baseUrl)

    const request = await c.req.json()
    const parsedReq = CredentialRequest(request)

    // Access token validation
    const accessToken = c.req.header('Authorization')?.replace('Bearer ', '')
    if (!accessToken) {
      return c.json(
        {
          error: 'invalid_token',
          error_description: 'Access token is required.',
        },
        401
      )
    }
    const isValid = await authzFlow.verifyAccessToken(issuer, accessToken)
    console.log('isValid:', isValid)
    if (!isValid) {
      return c.json(
        {
          error: 'invalid_token',
          error_description: 'Access token is invalid.',
        },
        401
      )
    }
    // Credential Issuance
    const credential = await issuerFlow.issueCredential(CredentialIssuer(baseUrl), parse, {
      alg: 'ES256',
      cnonce: {
        c_nonce_expires_in: 60 * 5 * 1000,
      },
      claims: {
        given_name: 'Test',
        family_name: 'Smith',
        degree: '5',
        gpa: 'test',
      }
,
    })

    return c.json(credential)
  } catch (err) {
    const errorResponse = handleError(err)
    return c.json(errorResponse, 400)
  }
})
```

**Example**:

**Request**

```bash
curl -X POST http://localhost:8080/issue/credentials \
  -H "Authorization: eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJzdWIiOiJmZGMzMzIzYmM3MTg0ZmJkYWE0NTc2YTgwODU2OGE0MSIsImV4cCI6MTc2MTk3ODAwNSwiaWF0IjoxNzYxODkxNjA1fQ.PBKg31GJbIIKqtQL6gpZYoIM_PGlY681u4Rjjhxek38Kzl3prEBggXcqjUq3l-cBRYC1KS1fcJY6jUiUllwyJw" \
  -H "Content-Type: application/json" \
  --data '{
  "format": "jwt_vc_json",
  "credential_definition": {
    "type": ["VerifiableCredential", "UniversityDegreeCredential"]
  },
  "proof": {
    "proof_type": "jwt",
    "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20ifQ.zgj0A19Zo9EMMYtvGJtIehcq6eSmr_VEmiCMz-1ZM0yepvh8pqaSBdU83jXWr7Mgy2BRzVuGQL3WcY55GljjlQ"
  }
}'
```

**Response**

```json
{
  "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6IjM4YzEwMWQ2LTEwZDktNGU0Mi05MDlkLWY1N2Y0OWIyMTZjNiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJpc3N1YW5jZURhdGUiOiIyMDI1LTEwLTMxVDA3OjAzOjA4LjUzN1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSIsImdpdmVuX25hbWUiOiJ0ZXN0IiwiZmFtaWx5X25hbWUiOiJ0YXJvIiwiZGVncmVlIjoiNSIsImdwYSI6InRlc3QifX0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInN1YiI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.LwcUtOS0b2sEEKp-c1CpLZorqDF0heRUuJm_zPSuZVSa7XRWkghkvzq7olr2E4BOcoZryn-QCbGVugcZTPs4LA",
  "c_nonce_expires_in": 300000
}
```


## 4. Explanation of Type Definitions

### CredentialIssuer {#CredentialIssuer}

Represents the identifier of an Issuer. A URI-formatted string is used to uniquely identify an Issuer.

For the definition, see [issuer+verifier/src/credential-issuer.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-issuer.types.ts).

### CredentialIssuerMetadata {#CredentialIssuerMetadata}

Defines the metadata of the authorization server. It contains issuer information such as supported formats, endpoints, and so on.

For the definition, see [issuer+verifier/src/credential-issuer.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-issuer.types.ts).

### CredentialResponse {#CredentialResponse}

Represents the response for an issued credential. It contains information such as the credential in JWT format and related metadata.

For the definition, see [issuer+verifier/src/credential-response.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-response.types.ts).

### AuthorizationServerIssuer {#AuthorizationServerIssuer}

Represents the identifier of the authorization server. It is a URI-formatted string used to uniquely identify the authorization server.

For the definition, see [issuer+verifier/src/authorization-server.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/authorization-server.types.ts).

### AuthorizationServerMetadata {#AuthorizationServerMetadata}

Defines the metadata of the authorization server. It contains information such as issuer information, supported formats, endpoints, and so on.

For the definition, see [issuer+verifier/src/authorization-server.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/authorization-server.types.ts).

### AuthzTokenRequest

Represents an access token request. It contains information such as whether the type is an authorization code, a pre-authorized code, and so on.

For the definition, see [issuer+verifier/src/token-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/token-request.types.ts).

## 5. Methods of IssuerFlow

### findIssuerMetadata

Retrieves the metadata of an Issuer.

```typescript
findIssuerMetadata(id: CredentialIssuer): Promise<CredentialIssuerMetadata | null>
```

**Parameters**:
- `id`: Identifier of the Issuer ([CredentialIssuer](#CredentialIssuer))

**Return value**: Returns the metadata object ([CredentialIssuerMetadata](#CredentialIssuerMetadata)) or null.


### createIssuerMetadata
Creates and stores the Issuer metadata.

```typescript
createIssuerMetadata(issuer: CredentialIssuerMetadata): Promise<void>
```

**Parameters**:
- `issuer`: Issuer metadata ([CredentialIssuerMetadata](#CredentialIssuerMetadata))

**Return value**: None

**Error cases**:
- `PROVIDER_NOT_FOUND`: An unsupported `alg` is configured


### offerCredential
Creates a credential offer.

```typescript
offerCredential(
  issuer: CredentialIssuer,
  configurations: CredentialConfigurationId[],
  options?: OfferOptions
): Promise<CredentialOffer>
```

**Parameters**:
- `issuer`: Identifier of the Issuer ([CredentialIssuer](#CredentialIssuer))
- `configurations`: Array of credential configuration IDs ([CredentialConfigurationId](#CredentialConfigurationId))
- `options`: Options for creating the offer ([OfferOptions](#OfferOptions))

**Return value**: Returns a credential offer.

For the type definition of the credential offer, see [issuer+verifier/src/credential-offer.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-offer.types.ts).


**Error cases**:
- `FEATURE_NOT_IMPLEMENTED_YET`: An unsupported flow is configured (the authorization code flow is not supported)
- `ISSUER_NOT_FOUND`: An unregistered Issuer is configured

#### CredentialConfigurationId{#CredentialConfigurationId}
Defines the type for credential configuration IDs.

For the definition, see [issuer+verifier/src/credential-issuer.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-issuer.types.ts).

#### OfferOptions {#OfferOptions}
Defines the options used when creating a credential offer. You can configure whether to use the pre-authorized code flow.
The definition is as follows.

```typescript
type OfferOptions =
  | {
      usePreAuth: false
      state?: unknown
    }
  | {
      usePreAuth: true
      txCode?: {
        inputMode?: 'numeric' | 'text'
        length?: number
        description?: string
      }
    }
```

### issueCredential
Issues a credential.

```typescript
issueCredential(
  issuer: CredentialIssuer,
  credentialRequest: CredentialRequest,
  options?: IssueOptions
): Promise<CredentialResponse>
```

**Parameters**:
- `issuer`: Identifier of the Issuer ([CredentialIssuer](#CredentialIssuer))
- `credentialRequest`: Credential request ([CredentialRequest](#CredentialRequest))
- `options`: Issuance options ([IssueOptions](#IssueOptions))

**Return value**: Returns a credential response.

For the type definition of the credential response, see [issuer+verifier/src/credential-response.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-response.types.ts).

**Error cases**:
- `ISSUER_NOT_FOUND`: An unregistered Issuer is configured
- `PROVIDER_NOT_FOUND`: An unsupported `format` is configured
- `INVALID_REQUEST`: `format` is not set
- `UNSUPPORTED_CREDENTIAL_TYPE`: The specified `credential_definition` or `proof_type` is not supported
- `INVALID_CREDENTIAL_REQUES`: The `proof` is missing or not supported
- `INVALID_PROOF`: The `proof` cannot be verified, an unsupported header is set, or a `nonce` is missing
- `UNSUPPORTED_ISSUER_KEY_ALG`: The Issuer’s signing algorithm is not supported
- `AUTHZ_ISSUER_KEY_NOT_FOUND`: The Issuer’s key cannot be found
- `INTERNAL_SERVER_ERROR`: Signing failed

#### CredentialRequest{#CredentialRequest}
Defines the type for a credential issuance request. You can configure items such as the credential identifier.

For the definition, see [issuer+verifier/src/credential-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-request.types.ts).

#### IssueOptions{#IssueOptions}
Defines the type for credential issuance options. You can configure items such as algorithms and claims.
The definition is as follows.

```typescript
type IssueOptions = {
  alg: string
  cnonce?: {
    c_nonce_expires_in: number
  }
  claims?: Record<string, unknown>
}
```

## 6. Methods of AuthzFlow

### findAuthzServerMetadata
Retrieves the metadata of the authorization server.

```typescript
findAuthzServerMetadata(issuer: AuthorizationServerIssuer): Promise<AuthorizationServerMetadata | null>
```

**Parameters**:
- `issuer`: Identifier of the authorization server ([AuthorizationServerIssuer](#AuthorizationServerIssuer))

**Return value**: Returns the metadata object ([AuthorizationServerMetadata](#AuthorizationServerMetadata)) or null.


#### AuthorizationServerIssuer{#AuthorizationServerIssuer}
Defines the type for the issuer of the authorization server.

For the definition, see [issuer+verifier/src/authorization-server.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/authorization-server.types.ts).


### createAuthzServerMetadata
Creates and stores the metadata of the authorization server.

```typescript
createAuthzServerMetadata(
  metadata: AuthorizationServerMetadata,
  options?: { alg?: 'ES256' }
): Promise<void>
```

**Parameters**:
- `metadata`: Metadata of the authorization server ([AuthorizationServerMetadata](#AuthorizationServerMetadata))
- `options`: Signing algorithm

**Return value**: None


### createAccessToken
Issues an access token.

```typescript
createAccessToken<T extends GrantType>(
  authz: AuthorizationServerIssuer,
  tokenRequest: TokenRequest,
  options?: TokenRequestOptions[T]
): Promise<Object>
```

**Parameters**:
- `authz`: Identifier of the authorization server ([AuthorizationServerIssuer](#AuthorizationServerIssuer))
- `tokenRequest`: Token request ([TokenRequest](#TokenRequest))
- `options`: Options for the token request

  ```typescript
  type TokenRequestOptions = {
    [GrantType.AuthorizationCode]: {
      // The authorization code flow is not supported yet
    }
    [GrantType.PreAuthorizedCode]: {
      ttlSec?: number
      c_nonce_expire_in?: number
    }
  }
  ```

**Return value**: The access token is returned in the following format:
```typescript
// When the pre-authorized code is selected as grant_type
{
  access_token: `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`,
  token_type: 'bearer',
  expires_in: option?.ttlSec ?? 86400,
  c_nonce: cnonce,
  c_nonce_expires_in: option?.c_nonce_expire_in ?? 60 * 5 * 1000, // 5 minutes
}
```

**Error cases**:
- `PROVIDER_NOT_FOUND`: An unsupported algorithm is configured for the private key
- `PRE_AUTHORIZED_CODE_NOT_FOUND`: An invalid pre-authorized code is provided
- `INVALID_REQUEST`: The authorization server key is not registered, the algorithm is not set, or the grant type is not supported
- `INTERNAL_SERVER_ERROR`: Signing failed
- `FEATURE_NOT_IMPLEMENTED_YET`: The authorization code flow is configured (currently not supported)

#### TokenRequest{#TokenRequest}
Defines the type for a credential issuance request. You can configure items such as the credential identifier.

For the definition, see [issuer+verifier/src/token-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/token-request.types.ts).

#### TokenRequestOptions {#TokenRequestOptions}
Defines the type for options used when making a token request. You can configure items such as the flow to use (the authorization code flow is not supported).
The definition is as follows.

```typescript
type TokenRequestOptions = {
  [GrantType.AuthorizationCode]: {
    //TODO: Implement options for authorization code flow
  }
  [GrantType.PreAuthorizedCode]: {
    ttlSec?: number
    c_nonce_expire_in?: number
  }
}
```


### verifyAccessToken
Verifies the access token.

```typescript
verifyAccessToken(authz: AuthorizationServerIssuer, accessToken: string): Promise<boolean>
```

**Parameters**:
- `authz`: Identifier of the authorization server ([AuthorizationServerIssuer](#AuthorizationServerIssuer))

**Return value**: Returns a boolean indicating whether the access token is valid.

**Error cases**:
- `INVALID_ACCESS_TOKEN`: The access token is not a valid JWT, or the `authz` claim is not as expected
- `AUTHZ_ISSUER_KEY_NOT_FOUND`: The authorization server’s key cannot be found
- `PROVIDER_NOT_FOUND`: The signing algorithm is not supported


## 7. Notes

1. **Access token validation**: Always validate the access token when issuing credentials.

2. **Security**: In production environments, be sure to implement proper authentication and authorization.
   - Pay particular attention to managing private keys.
   - Use HTTPS to encrypt communications.

3. **URL encoding**: If the issuer ID contains characters that require URL encoding (for example, `:` or `/`), make sure they are properly encoded.


## 8. Troubleshooting

### Common issues

- **Q: Metadata validation error**  
  - **A:** Check that the provided metadata conforms to the CredentialIssuerMetadata schema and the AuthorizationServerMetadata schema.

- **Q: Error when creating credential offer**: `FEATURE_NOT_IMPLEMENTED_YET`  
  - **A:** Make sure you are not calling an unimplemented flow. Currently, only the pre-authorized code flow is supported.

- **Q: Error when issuing credential**: `INVALID_PROOF`  
  - **A:** Check that the header of prooj.jwt in the credential request includes a kid.



