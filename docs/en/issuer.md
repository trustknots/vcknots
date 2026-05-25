---
sidebar_position: 2
---

# How to Set Up and Use the Issuer Feature

This guide explains how to set up and use the Issuer feature of VCKnots.

## 1. Prerequisites

- Supports OpenID for Verifiable Credential Issuance 1.0 ([OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html))  
The following items are not implemented yet and are planned for future support:
  - Only the Pre-Authorized Code Flow is supported at this time.
  - `credential_response_encryption` in the Credential Request is not supported yet.
  - The Credential Request supports the `jwt` proof type (`di_vp` and `attestation` is not supported yet.).
- Node.js v14 or later is installed
- TypeScript is configured
- This document is based on the sample implementation of the server
- The Hono web framework is used, but other frameworks can also be used

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

## VcknotsOptions

Configuration options passed to `initializeContext()`.

```typescript
type VcknotsOptions = {
  debug?: boolean
  providers?: Providers
  extensions?: Extensions
  oauth?: OAuthOptions
}
```

### debug

Development option.

```typescript
const context = initializeContext({
  debug: true,
})
```

When `debug: true`:

- insecure `http://` endpoints are allowed
- localhost development workflows are enabled

When `debug: false` (default):

- using `http://` URLs in the following `CredentialIssuerMetadata` endpoints will throw an `insecure_http_not_allowed` error:
  - `credential_endpoint`
  - `deferred_credential_endpoint`

```json
{
  "error": "insecure_http_not_allowed",
  "error_description": "CredentialIssuerMetadata contains insecure http url in credential_endpoint: http://localhost:8080/credentials"
}
```

Use HTTPS endpoints in production environments.

---

### oauth.senderConstrainedAccessToken

Configuration for Sender-Constrained Access Tokens.

```typescript
const context = initializeContext({
  oauth: {
    senderConstrainedAccessToken: {
      method: 'dpop',
      dpop: {
        mode: 'required',
      },
    },
  },
})
```

#### method

Specifies the sender constraint method for access tokens.

```typescript
type SenderConstraintMethod = 'none' | 'dpop' | 'mtls'
```

| Value | Description |
|---|---|
| `none` | Sender-constrained access tokens are not used |
| `dpop` | Uses DPoP-bound access tokens |
| `mtls` | mTLS sender-constrained access tokens (planned) |

---

#### dpop.mode

Specifies the DPoP enforcement level.

```typescript
type DPoPMode = 'off' | 'optional' | 'required'
```

| mode | token endpoint / credential endpoint behavior |
|---|---|
| `off` | DPoP is disabled |
| `optional` | DPoP Proof is verified only when provided |
| `required` | DPoP Proof is required for all requests |

Internally, the mode is resolved using `resolveDpopMode()`.  
If omitted, the default value is `off`.

```typescript
export const resolveDpopMode = (
  options?: Pick<VcknotsOptions, 'oauth'>
): DPoPMode =>
  options?.oauth?.senderConstrainedAccessToken?.dpop?.mode ?? 'off'
```

---

### providers

Adds custom providers.

```typescript
const context = initializeContext({
  providers: [
    myProvider,
  ],
})
```

---

### extensions

Adds VCKnots extensions.

```typescript
const context = initializeContext({
  extensions: [
    myExtension,
  ],
})
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
    credential_endpoint: `${baseUrl}/credentials`,
    deferred_credential_endpoint: `${baseUrl}/deferred_credential`,
    nonce_endpoint: `${baseUrl}/nonce`,
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
    "credential_endpoint": "http://localhost:8080/credentials",
    "nonce_endpoint": "http://localhost:8080/nonce",
    "deferred_credential_endpoint": "http://localhost:8080/deferred_credential",
    "credential_response_encryption": {
        "alg_values_supported": [
            "ECDH-ES"
        ],
        "enc_values_supported": [
            "A128GCM"
        ],
        "encryption_required": false
    },
    "credential_configurations_supported": {
        "UniversityDegreeCredential": {
            "format": "jwt_vc_json",
            "scope": "UniversityDegree",
            "cryptographic_binding_methods_supported": [
                "did:key"
            ],
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
            "credential_metadata": {
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
                ],
                "claims": [
                    {
                        "path": [
                            "credentialSubject",
                            "given_name"
                        ],
                        "mandatory": true,
                        "display": [
                            {
                                "name": "Given Name",
                                "locale": "en-US"
                            },
                            {
                                "name": "Given Name",
                                "locale": "ja-JP"
                            }
                        ]
                    },
                    {
                        "path": [
                            "credentialSubject",
                            "family_name"
                        ],
                        "display": [
                            {
                                "name": "Surname",
                                "locale": "en-US"
                            },
                            {
                                "name": "Surname",
                                "locale": "ja-JP"
                            }
                        ]
                    },
                    {
                        "path": [
                            "credentialSubject",
                            "degree"
                        ],
                        "display": [
                            {
                                "name": "Degree",
                                "locale": "en-US"
                            },
                            {
                                "name": "Degree",
                                "locale": "ja-JP"
                            }
                        ]
                    },
                    {
                        "path": [
                            "credentialSubject",
                            "gpa"
                        ],
                        "display": [
                            {
                                "name": "GPA",
                                "locale": "en-US"
                            },
                            {
                                "name": "GPA",
                                "locale": "ja-JP"
                            }
                        ]
                    }
                ]
            },
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ]
            }
        },
        "UniversityDegreeCredentialSdJwt": {
            "format": "dc+sd-jwt",
            "scope": "UniversityDegreeSdJwt",
            "cryptographic_binding_methods_supported": [
                "jwk",
                "did:key"
            ],
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
            "credential_metadata": {
                "display": [
                    {
                        "name": "University Credential (SD-JWT)",
                        "locale": "en-US",
                        "logo": {
                            "uri": "https://university.example.edu/public/logo.png",
                            "alt_text": "a square logo of a university"
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                    }
                ],
                "claims": [
                    {
                        "path": [
                            "given_name"
                        ],
                        "display": [
                            {
                                "name": "Given Name",
                                "locale": "en-US"
                            },
                            {
                                "name": "Given Name",
                                "locale": "ja-JP"
                            }
                        ]
                    },
                    {
                        "path": [
                            "family_name"
                        ],
                        "display": [
                            {
                                "name": "Surname",
                                "locale": "en-US"
                            },
                            {
                                "name": "Surname",
                                "locale": "ja-JP"
                            }
                        ]
                    },
                    {
                        "path": [
                            "degree"
                        ],
                        "display": [
                            {
                                "name": "Degree",
                                "locale": "en-US"
                            },
                            {
                                "name": "Degree",
                                "locale": "ja-JP"
                            }
                        ]
                    },
                    {
                        "path": [
                            "gpa"
                        ],
                        "display": [
                            {
                                "name": "GPA",
                                "locale": "en-US"
                            },
                            {
                                "name": "GPA",
                                "locale": "ja-JP"
                            }
                        ]
                    },
                    {
                        "path": [
                            "address",
                            "country"
                        ],
                        "display": [
                            {
                                "name": "Country",
                                "locale": "en-US"
                            },
                            {
                                "name": "Country",
                                "locale": "ja-JP"
                            }
                        ]
                    },
                    {
                        "path": [
                            "address",
                            "region"
                        ],
                        "display": [
                            {
                                "name": "Region",
                                "locale": "en-US"
                            },
                            {
                                "name": "Region",
                                "locale": "ja-JP"
                            }
                        ]
                    }
                ]
            },
            "vct": "UniversityDegreeCredential"
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
app.post('/configurations/:configuration/offer', async (c) => {
    try {
      const issuer = CredentialIssuer(baseUrl)
      const parseResult = CredentialConfigurationId.schema.safeParse(c.req.param('configuration'))
      if (!parseResult.success) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'Invalid credential configuration ID.',
          },
          400
        )
      }
      const configurations = [parseResult.data]
      const rawBody = await c.req.text()

      let options: OfferOptions | undefined
      if (rawBody.trim().length > 0) {
        try {
          options = JSON.parse(rawBody) as OfferOptions
        } catch {
          return c.json(
            {
              error: 'invalid_request',
              error_description: 'Request body must be valid JSON.',
            },
            400
          )
        }
      }

      const { offer, tx_code } = await issuerFlow.offerCredential(issuer, configurations, {
        usePreAuth: true,
        txCode: options?.tx_code,
      })

      console.log('offer:', offer)
      console.log('tx_code:', tx_code)

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

Include a request body (JSON) only when specifying `tx_code`.

```bash
curl -X POST http://localhost:8080/configurations/UniversityDegreeCredential/offer \
  -H "Content-Type: application/json" \
  -d '{
    "tx_code": {
      "input_mode": "numeric",
      "length": 6,
      "description": "Please enter the one-time code."
    }
  }'
```

**Response**

```raw
openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredentialSdJwt%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%2268baf35e74ae430684662d85ea87160e%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22numeric%22%2C%22length%22%3A6%2C%22description%22%3A%22Please%20enter%20the%20one-time%20code.%22%7D%7D%7D%7D
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
  "authorization_endpoint": "http://localhost:8080/authorize",
  "token_endpoint": "http://localhost:8080/token",
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
app.post('/token', async (c) => {
  const dpopMode = resolveDpopMode(context.options)
  const dpopProof = parseDpopHeader(c.req.header('DPoP'))

  if (
    (dpopMode === 'required' && !dpopProof.ok) ||
    (dpopMode !== 'off' && !dpopProof.ok && dpopProof.reason !== 'missing')
  ) {
    return c.json(
      {
        error: 'invalid_request',
        error_description:
          dpopProof.reason === 'missing'
            ? 'DPoP proof JWT is required.'
            : dpopProof.reason === 'duplicate'
              ? 'DPoP header must appear exactly once.'
              : 'DPoP header must contain a compact JWT.',
      },
      400
    )
  }

  const request = await c.req.formData().catch(() => null)
  if (!request) {
    return c.json(
      {
        error: 'invalid_request',
        error_description: 'Request body must be a valid form data.',
      },
      400
    )
  }
  const requestData: Record<string, string | File | number> = Object.fromEntries(
    request.entries()
  )

  const parseResult = AuthzTokenRequest.schema.safeParse(requestData)
  if (!parseResult.success) {
    return c.json(
      {
        error: 'invalid_request',
        error_description: 'Invalid token request parameters.',
      },
      400
    )
  }
  const tokenRequest = parseResult.data
  const issuer = AuthorizationServerIssuer(baseUrl)

  const accessToken = await authzFlow.createAccessToken(issuer, tokenRequest, {
    ...(dpopMode !== 'off' && dpopProof.ok
      ? {
          dpopProof: {
            proofJwt: dpopProof.proofJwt,
            htm: c.req.method,
            htu: `${baseUrl}/token`,
            nonceRequired: true,
          },
        }
      : {}),
  })
  return c.json(accessToken)
})
```

The **request body is `application/x-www-form-urlencoded`** (`AuthzTokenRequest` is built from form fields). For the full handler—including branches such as **`invalid_dpop_proof`** (`invalid_dpop_proof`) and **`use_dpop_nonce`** (with a **`DPoP-Nonce`** header)—see [server/core/src/routes/authz.ts](https://github.com/trustknots/vcknots/blob/main/server/core/src/routes/authz.ts).

**Example**:

**Request**

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
  --data-urlencode "pre-authorized_code=343ce17f1d274aa8bb3d19c140484889"
```

**Response**

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJzdWIiOiIzNDNjZTE3ZjFkMjc0YWE4YmIzZDE5YzE0MDQ4NDg4OSIsImV4cCI6MTc2MTk3NjE1NiwiaWF0IjoxNzYxODg5NzU2fQ.vsV71EEtAo36jcb9N8un2cn36Oo_H1qtKuIp0uerdvI2jNcBhN7ltGeqmk1AVZhpk5kQZcfbkSiHje-j1Iv1zg",
  "token_type": "bearer",
  "expires_in": 86400
}
```

#### Token requests with DPoP Proof

`oauth.senderConstrainedAccessToken.dpop.mode` controls DPoP Proof verification at the token endpoint.

| mode | Token endpoint behavior |
|------|--------------------------|
| `off` | DPoP is not used. The server issues a Bearer access token. |
| `optional` | If the DPoP header is absent, the server issues a Bearer access token. If the DPoP header is present, the server verifies the proof and issues a DPoP-bound access token. |
| `required` | The DPoP header is required. A missing or malformed DPoP header results in `invalid_request`. |

If the DPoP Proof has no `nonce`, or the nonce is invalid, the Authorization Server returns `use_dpop_nonce` with a `DPoP-Nonce` response header. The Wallet retries the token request with this nonce in the DPoP Proof JWT `nonce` claim.

```http
HTTP/1.1 400 Bad Request
DPoP-Nonce: 9288f7b2dffb42c2b08f2f4d4d8635d8
Content-Type: application/json

{
  "error": "use_dpop_nonce",
  "error_description": "Authorization server requires nonce in DPoP proof."
}
```

When DPoP Proof verification succeeds, the response `token_type` is `DPoP`. The issued access token also contains `cnf.jkt`, the JWK Thumbprint of the public key from the DPoP Proof JOSE header.

```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 86400
}
```

Subsequent requests using a DPoP-bound access token must present a DPoP Proof signed with the private key corresponding to the same public key.

#### Differences in error responses between the token endpoint (AS) and credential endpoint (RS)

In [server/core](https://github.com/trustknots/vcknots/blob/main/server/core/src/routes/authz.ts), the HTTP status and challenge behavior differ by role:

- **`POST /token` (Authorization Server):** Most DPoP / request errors are returned as **HTTP 400** with a JSON body (`invalid_request` / `invalid_dpop_proof` / `use_dpop_nonce`). For `use_dpop_nonce`, the response includes a **`DPoP-Nonce`** header; **`WWW-Authenticate` is not sent** in the current implementation.
- **`POST /credentials` (Resource Server):** Failures in access token or DPoP verification are mostly **HTTP 401**. For **`invalid_token`**, the response includes **`WWW-Authenticate: Bearer`** (`realm`, `error`, `error_description`). For **`invalid_dpop_proof`** and **`use_dpop_nonce`** (credential-side message), the response includes **`WWW-Authenticate: DPoP`**, and in the latter case often a **`DPoP-Nonce`** header as well.

### 6. Nonce Endpoint

This endpoint corresponds to the OID4VCI [nonce endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint). It is used when a Wallet obtains a c_nonce before sending a credential request. 

When `nonce_endpoint` is set in the Issuer metadata, the Wallet references the nonce endpoint URL via the metadata obtained from `/.well-known/openid-credential-issuer`.

If you also want to return a DPoP nonce, configure `oauth.senderConstrainedAccessToken.dpop.mode` in the server settings.

```typescript
const context = initializeContext({
  oauth: {
    senderConstrainedAccessToken: {
      dpop: {
        mode: 'optional', // 'off' | 'optional' | 'required'
      },
    },
  },
})
```

When `mode !== 'off'`, `POST /nonce` returns a `DPoP-Nonce` response header in addition to the JSON body `c_nonce`. `c_nonce` and `DPoP-Nonce` are different values.

`c_nonce` is used for credential proofs. `DPoP-Nonce` is used for DPoP Proofs presented to the token endpoint. Since they have different purposes, their TTLs can be configured separately.

#### POST /nonce - Create nonce (c_nonce)

```typescript
app.post('/nonce', async (c) => {
  try {
    const C_NONCE_TTL_MS = 2 * 60 * 1000  // 2 minutes
    const DPOP_NONCE_TTL_MS = 5 * 60 * 1000  // 5 minutes
    const cnonce = await issuerFlow.createNonce(C_NONCE_TTL_MS)
    const dpopMode = resolveDpopMode(context.options)
    c.header('Cache-Control', 'no-store')
    if (dpopMode !== 'off') {
      const dpopNonce = await issuerFlow.createNonce(DPOP_NONCE_TTL_MS)
      c.header('DPoP-Nonce', dpopNonce)
    }
    return c.json({ c_nonce: cnonce }, 200)
  } catch (err) {
    const errorResponse = handleError(err)
    const status = errorResponse.error === 'internal_server_error' ? 500 : 400
    return c.json(errorResponse, status)
  }
})
```

**Example**:

**Request**

```bash
curl -i -X POST http://localhost:8080/nonce
```

**Response**

```http
HTTP/1.1 200 OK
Cache-Control: no-store
DPoP-Nonce: 9288f7b2dffb42c2b08f2f4d4d8635d8
Content-Type: application/json

{
  "c_nonce": "3ccc7973abef4102ad70a871e200304b"
}
```

If `oauth.senderConstrainedAccessToken.dpop.mode` is `off`, the `DPoP-Nonce` header is not returned.

**Implementation example**:

- [server/core/src/routes/issue.ts](https://github.com/trustknots/vcknots/blob/main/server/core/src/routes/issue.ts)

#### GET /nonce/:nonce - Validate nonce

```typescript
app.get('/nonce/:nonce', async (c) => {
  try {
    const nonce = c.req.param('nonce')
    const valid = await issuerFlow.validateNonce(nonce)
    return c.json({ valid })
  } catch (err) {
    const errorResponse = handleError(err)
    const status = errorResponse.error === 'internal_server_error' ? 500 : 400
    return c.json(errorResponse, status)
  }
})
```

**Example**:

**Request**

```bash
curl http://localhost:8080/nonce/3ccc7973abef4102ad70a871e200304b
```

**Response**

```json
{
  "valid": true
}
```

#### DELETE /nonce/:nonce - Revoke nonce

Revokes (deletes) the specified nonce. Returns 404 if the nonce does not exist.

```typescript
app.delete('/nonce/:nonce', async (c) => {
  try {
    const nonce = c.req.param('nonce')
    const deleted = await issuerFlow.revokeNonce(nonce)
    if (!deleted) {
      return c.json(
        { error: 'not_found', error_description: 'Nonce not found.' },
        404
      )
    }
    return c.json({ deleted: true }, 200)
  } catch (err) {
    const errorResponse = handleError(err)
    const status = errorResponse.error === 'internal_server_error' ? 500 : 400
    return c.json(errorResponse, status)
  }
})
```

**Example**:

**Request**

```bash
curl -X DELETE http://localhost:8080/nonce/3ccc7973abef4102ad70a871e200304b
```

**Response (200)**

```json
{
  "deleted": true
}
```

**Response (404 - nonce not found)**

```json
{
  "error": "not_found",
  "error_description": "Nonce not found."
}
```

### 7. Issuing a Credential

Endpoint to issue a credential:

#### DPoP-bound access token verification at the credential endpoint

`oauth.senderConstrainedAccessToken.dpop.mode` controls how the access token and DPoP Proof are handled at the credential endpoint.

| mode | Credential endpoint behavior |
|------|------------------------------|
| `off` | DPoP is not used. Requests that send `Authorization: DPoP <access_token>` or a `DPoP` header are rejected. |
| `optional` | DPoP is not required at the credential endpoint. Access tokens without sender binding may be presented with **`Authorization: Bearer` only**. If the token includes **`cnf.jkt`** (sender-constrained / DPoP-bound), **`Authorization: Bearer` alone is rejected**; you must use **`Authorization: DPoP <access_token>`** together with the **`DPoP`** header (DPoP Proof JWT). |
| `required` | Every request must include **`Authorization: DPoP <access_token>`** and the **`DPoP`** header (DPoP Proof JWT). **`Authorization: Bearer` only** is rejected. |

Because the credential endpoint acts as a resource server, when a DPoP-bound access token is used, the DPoP Proof is validated per RFC 9449.

- The **`DPoP`** header must be a single compact JWT (the implementation rejects values that contain a **comma**, treating them as merged duplicate headers).
- The DPoP Proof JOSE header **`typ`** must be **`dpop+jwt`**.
- **`alg`** must not be **`none`** or an HMAC family algorithm; an asymmetric signing algorithm must be used.
- The **`jwk`** header must contain a public key and must **not** include private-key material.
- The DPoP Proof JWT signature must verify with the **`jwk`** public key.
- The payload must include **`jti`**, **`iat`**, **`htm`**, and **`htu`**.
- **`htm`** must match the actual HTTP method.
- **`htu`** must match the credential endpoint URI excluding query string and fragment.
- At the credential endpoint, **`ath`** is required and must equal the SHA-256 hash of the presented access token, base64url-encoded.
- **`cnf.jkt`** on the access token must match the JWK thumbprint from the DPoP Proof **`jwk`**.
- **`jti`** values are tracked to reject replay of the same DPoP Proof.
- By default **`iat`** is considered valid within **`maxTokenAge` 300 seconds** and **`clockTolerance` 60 seconds** (issuer+verifier DPoP proof provider; factory options can change this).

If the DPoP Proof is invalid, the credential endpoint responds with **`401 Unauthorized`** and **`WWW-Authenticate: DPoP`**. For **`invalid_token`** issues (JWT shape/signature/`issuer` mismatch, etc.), the response is also **401**, with **`WWW-Authenticate: Bearer`** (`realm`, `error="invalid_token"`, etc.).

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP realm="http://localhost:8080", error="invalid_dpop_proof", error_description="DPoP proof JWT ath claim does not match the access token."
Content-Type: application/json

{
  "error": "invalid_dpop_proof",
  "error_description": "DPoP proof JWT ath claim does not match the access token."
}
```

If **`use_dpop_nonce`** is returned, the credential endpoint responds with **`401 Unauthorized`** and includes **`DPoP-Nonce`** in the response headers. The Wallet retries the credential request putting the **`DPoP-Nonce`** header value into the **`nonce`** claim of the DPoP Proof JWT.

```http
HTTP/1.1 401 Unauthorized
DPoP-Nonce: 9288f7b2dffb42c2b08f2f4d4d8635d8
WWW-Authenticate: DPoP realm="http://localhost:8080", error="use_dpop_nonce", error_description="Credential issuer requires nonce in DPoP proof."
Content-Type: application/json

{
  "error": "use_dpop_nonce",
  "error_description": "Credential issuer requires nonce in DPoP proof."
}
```

The following code excerpt matches [server/core/src/routes/issue.ts](https://github.com/trustknots/vcknots/blob/main/server/core/src/routes/issue.ts) in ordering (**verify access token and DPoP first, then read the JSON body**), **`nonceRequired: true`**, rejecting Bearer-presented tokens that contain **`cnf.jkt`**, and **401 with `WWW-Authenticate`**. Imports, **`Context` (Hono)**, **`VcknotsError`**, **`buildBearerAuthenticateHeader` / `buildDpopAuthenticateHeader`**, and production logging are omitted.

```typescript
const DPOP_NONCE_TTL_MS = 5 * 60 * 1000

app.post('/credentials', async (c) => {
  try {
    const issuer = CredentialIssuer(baseUrl)
    const authz = AuthorizationServerIssuer(baseUrl)
    const dpopMode = resolveDpopMode(context.options)
    const realm = baseUrl

    const hasCnfJkt = (payload: unknown): boolean => {
      if (payload === null || typeof payload !== 'object' || Array.isArray(payload))
        return false
      const cnf = (payload as { cnf?: unknown }).cnf
      if (cnf === null || typeof cnf !== 'object' || Array.isArray(cnf)) return false
      return typeof (cnf as { jkt?: unknown }).jkt === 'string'
    }

    const unauthorized = (
      c: Context,
      body: { error: string; error_description: string },
      challenge: { error?: 'invalid_request' | 'invalid_token' | 'insufficient_scope' } = {}
    ) => {
      c.header(
        'WWW-Authenticate',
        buildBearerAuthenticateHeader({
          realm,
          error: challenge.error,
          errorDescription: challenge.error ? body.error_description : undefined,
        })
      )
      return c.json(body, 401)
    }

    const invalidDpopProof = (c: Context, errorDescription: string) => {
      c.header(
        'WWW-Authenticate',
        buildDpopAuthenticateHeader({
          realm,
          error: 'invalid_dpop_proof',
          errorDescription,
        })
      )
      return c.json(
        { error: 'invalid_dpop_proof', error_description: errorDescription },
        401
      )
    }

    const dpopNonceResponse = async (c: Context) => {
      const dpopNonce = await authzFlow.createDpopNonceChallenge(DPOP_NONCE_TTL_MS)
      const errorDescription = 'Credential issuer requires nonce in DPoP proof.'
      c.header('DPoP-Nonce', dpopNonce)
      c.header(
        'WWW-Authenticate',
        buildDpopAuthenticateHeader({
          realm,
          error: 'use_dpop_nonce',
          errorDescription,
        })
      )
      return c.json(
        {
          error: 'use_dpop_nonce',
          error_description: errorDescription,
        },
        401
      )
    }

    const authorization = parseAuthorizationHeader(c.req.header('Authorization'))
    if (!authorization.ok) {
      return unauthorized(c, {
        error: 'invalid_token',
        error_description:
          authorization.reason === 'missing'
            ? 'Access token is required.'
            : 'Authorization header must use Bearer or DPoP scheme.',
      })
    }

    if (dpopMode === 'off' && (authorization.value.scheme === 'dpop' || c.req.header('DPoP'))) {
      return unauthorized(c, {
        error: 'invalid_token',
        error_description:
          'DPoP access tokens are not supported by this credential endpoint.',
      })
    }

    try {
      if (authorization.value.scheme === 'dpop') {
        const dpopProof = parseDpopHeader(c.req.header('DPoP'))
        if (!dpopProof.ok) {
          return invalidDpopProof(
            c,
            dpopProof.reason === 'missing'
              ? 'DPoP proof JWT is required.'
              : dpopProof.reason === 'duplicate'
                ? 'DPoP header must appear exactly once.'
                : 'DPoP header must contain a compact JWT.'
          )
        }
        await authzFlow.verifyDpopBoundAccessToken(authz, authorization.value.token, {
          dpopProof: {
            proofJwt: dpopProof.proofJwt,
            htm: c.req.method,
            htu: `${baseUrl}/credentials`,
            nonceRequired: true,
          },
        })
      } else {
        if (dpopMode === 'required') {
          return unauthorized(
            c,
            {
              error: 'invalid_token',
              error_description: 'DPoP access token is required.',
            },
            { error: 'invalid_token' }
          )
        }
        const accessTokenPayload = await authzFlow.verifyAccessTokenPayload(
          authz,
          authorization.value.token
        )
        if (hasCnfJkt(accessTokenPayload)) {
          return unauthorized(
            c,
            {
              error: 'invalid_token',
              error_description:
                'DPoP-bound access token must be presented with DPoP scheme.',
            },
            { error: 'invalid_token' }
          )
        }
      }
    } catch (err) {
      if (err instanceof VcknotsError && err.name === 'invalid_access_token') {
        return unauthorized(
          c,
          { error: 'invalid_token', error_description: err.message },
          { error: 'invalid_token' }
        )
      }
      if (err instanceof VcknotsError && err.name === 'invalid_dpop_proof') {
        return invalidDpopProof(c, err.message)
      }
      if (err instanceof VcknotsError && err.name === 'use_dpop_nonce') {
        return dpopNonceResponse(c)
      }
      throw err
    }

    const request = await c.req.json().catch(() => null)
    if (!request) {
      return c.json(
        {
          error: 'invalid_request',
          error_description: 'Request body must be a valid JSON.',
        },
        400
      )
    }
    const parseResult = CredentialRequest.schema.safeParse(request)
    if (!parseResult.success) {
      return c.json(
        {
          error: 'invalid_request',
          error_description: 'Request body does not conform to CredentialRequest schema.',
        },
        400
      )
    }
    const parse = parseResult.data
    const credential = await issuerFlow.issueCredential(issuer, parse, {
      alg: 'ES256',
      cnonce: {
        c_nonce_expires_in: 60 * 5 * 1000,
      },
      claims: {
        given_name: 'Test',
        family_name: 'Smith',
        degree: '5',
        gpa: 'test',
      },
      proofJwt: { usePreAuth: true },
    })
    return c.json(credential)
  } catch (err) {
    const errorResponse = handleError(err)
    const status = errorResponse.error === 'internal_server_error' ? 500 : 400
    return c.json(errorResponse, status)
  }
})
```

**Example**:

**Request**

```bash
curl -X POST http://localhost:8080/credentials \
  -H "Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  --data '{
  "credential_configuration_id": "UniversityDegreeCredential",
  "proofs": {
    "jwt": [
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiYXVkIjoiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20ifQ.zgj0A19Zo9EMMYtvGJtIehcq6eSmr_VEmiCMz-1ZM0yepvh8pqaSBdU83jXWr7Mgy2BRzVuGQL3WcY55GljjlQ"
    ]
  }'
```

**Response**

```json
{
  "credentials": [
    {
      "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6IjM4YzEwMWQ2LTEwZDktNGU0Mi05MDlkLWY1N2Y0OWIyMTZjNiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJpc3N1YW5jZURhdGUiOiIyMDI1LTEwLTMxVDA3OjAzOjA4LjUzN1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSIsImdpdmVuX25hbWUiOiJ0ZXN0IiwiZmFtaWx5X25hbWUiOiJ0YXJvIiwiZGVncmVlIjoiNSIsImdwYSI6InRlc3QifX0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInN1YiI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.LwcUtOS0b2sEEKp-c1CpLZorqDF0heRUuJm_zPSuZVSa7XRWkghkvzq7olr2E4BOcoZryn-QCbGVugcZTPs4LA"
    }
  ]
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
- `provider_not_found`: An unsupported `alg` is configured


### createNonce

Creates a nonce (c_nonce). Used for the OID4VCI nonce endpoint.

```typescript
createNonce(ttlMs?: number): Promise<string>
```

**Parameters**:
- `ttlMs`: Validity period of the nonce in milliseconds. Uses the provider's default when omitted.

**Return value**: The generated nonce string.

### validateNonce

Validates whether the specified nonce is valid.

```typescript
validateNonce(nonce: string): Promise<boolean>
```

**Parameters**:
- `nonce`: The nonce value to validate.

**Return value**: `true` if the nonce is valid; `false` if invalid or not found.

### revokeNonce

Revokes (deletes) the specified nonce.

```typescript
revokeNonce(nonce: string): Promise<boolean>
```

**Parameters**:
- `nonce`: The nonce value to revoke.

**Return value**: `true` if the nonce was successfully revoked; `false` if the nonce was not found.

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
- `unsupported_grant_type`: An unsupported flow is configured (the authorization code flow is not supported)
- `issuer_not_found`: An unregistered Issuer is configured

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
        input_mode?: 'numeric' | 'text'
        length?: number
        description?: string
      }
      ttlSec?: number
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

**JWT credential proofs (`proofs.jwt`)**

- **Pre-authorized code flow**: use `proofJwt: { usePreAuth: true }`. The proof JWT must **not** carry an **`iss`** claim.
- **Authorization code flow**: Not supported.

#### JWT proof JOSE protected header

For protected-header validation behavior, see [credential-proof-jwt.provider.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/providers/credential-proof-jwt.provider.ts). The normative description is in [OpenID for Verifiable Credential Issuance 1.0 — JWT proof type](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type) (chapter and section numbers may change in revised specifications).

- **`typ`**: Must be `openid4vci-proof+jwt` (explicit typing per RFC 8725).
- **`alg`**: `none` and symmetric signatures (MAC, IANA JWA identifiers starting with `HS*`) are rejected.
- **`kid` / `jwk` / `x5c`**: **Must not appear more than one at a time.** **At least one** of them is required (if none are present, the result is `invalid_proof`).
- **`trust_chain`**: Not currently supported.

Per-header behavior:

| Header | Behavior |
|--------|----------|
| **`kid`** | Resolved as a DID URL (`did:…` with an optional `#fragment`) via **`did-provider`**; the signature is verified with the public key of the matching `verificationMethod`. |
| **`jwk`** | Verification uses the JWK in the header. JWKs that include **private key material (e.g. `d`)** are rejected. |
| **`x5c`** | The certificate chain is validated with **`certificate-provider`**, then the signature is verified with the public key of the leaf certificate. When using `x5c`, register **`certificate-provider`** in the provider list when initializing Vcknots. |

**Error cases**:
- `issuer_not_found`: An unregistered Issuer is configured
- `unknown_credential_configuration`: `credential_configuration_id` is not supported
- `unsupported_credential_type`: The specified `credential_definition` or `proof_type` is not supported
- `invalid_credential_request`: The `proof` is missing or not supported, or the configuration id is invalid, etc.
- `invalid_proof`: The `proof` cannot be verified, the header does not conform to OID4VCI JWT proof rules (e.g. `typ` / `alg` / combinations of `kid`, `jwk`, and `x5c`), an unsupported header is set, or a `nonce` is missing
- `unsupported_issuer_key_alg`: The Issuer’s signing algorithm is not supported
- `authz_issuer_key_not_found`: The Issuer’s key cannot be found
- `internal_server_error`: Signing failed

#### CredentialRequest{#CredentialRequest}
Defines the type for a credential issuance request. You can configure items such as the credential identifier.

For the definition, see [issuer+verifier/src/credential-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-request.types.ts).

#### IssueOptions{#IssueOptions}
Defines the type for credential issuance options. You can configure algorithms, claims, hints for JWT proof verification, and more.
The definition is as follows (see [issuer.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/issuer.flows.ts) for the implementation).

```typescript
type IssueOptions = {
  alg: string
  cnonce?: {
    c_nonce_expires_in: number
  }
  claims?: Record<string, unknown>
  subject?: string
  /** Used for JWT proof `iss` validation etc., depending on how the access token was obtained */
  proofJwt?: {
    usePreAuth: boolean
    clientId?: string
  }
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
    }
  }
  ```

**Return value**: The access token is returned in the following format:
```typescript
// When the pre-authorized code is selected as grant_type
{
  access_token: `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`,
  token_type: 'bearer',
  expires_in: option?.ttlSec ?? 86400
}
```

**Error cases**:
- `provider_not_found`: An unsupported algorithm is configured for the private key
- `invalid_grant`: An invalid pre-authorized code is provided
- `invalid_request`: The authorization server key is not registered, the algorithm is not set, or the grant type is not supported
- `internal_server_error`: Signing failed
- `unsupported_grant_type`: The authorization code flow is configured (currently not supported)

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
- `invalid_access_token`: The access token is not a valid JWT, or the `authz` claim is not as expected
- `authz_issuer_key_not_found`: The authorization server’s key cannot be found
- `provider_not_found`: The signing algorithm is not supported


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

- **Q: Error when creating credential offer**: `unsupported_grant_type`  
  - **A:** Make sure you are not calling an unimplemented flow. Currently, only the pre-authorized code flow is supported.

- **Q: Error when issuing credential**: `invalid_proof`  
  - **A:** Check that the header of proof.jwt in the credential request includes a kid. Also verify that the `nonce` in the proof is valid.
