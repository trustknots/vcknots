---
sidebar_position: 2
---

# Issuer機能のセットアップと使用方法

このガイドでは、VCKnotsのIssuer機能のセットアップと使用方法について説明します。

## 1. 前提条件

- OpenID for Verifiable Credential Issuance 1.0 に対応([OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html))  
なお、以下は現時点では未実装ですが、今後対応予定です。
  - 現在対応しているフローは 事前認可コードフロー（Pre-Authorized Code Flow）のみです
  - Credential Requestの`credential_response_encryption`は未対応（今後対応予定）
  - Credential Requestのproof typeは`jwt`のみ対応 （`di_vp`,`attestation`今後対応予定）
- Node.js v14以降がインストールされていること
- TypeScriptが設定されていること
- 本ドキュメントはserverのサンプル実装に基づいて説明します
- HonoのWebフレームワークを使用していますが、他のフレームワークでも利用可能です

## 2. 初期設定

### 必要な依存関係のインストール

```bash
npm install @trustknots/vcknots
npm install hono @hono/node-server
```

### ライブラリを使うための準備

```typescript
import { Hono } from 'hono'
import { initializeContext } from '@trustknots/vcknots'
import { initializeIssuerFlow, CredentialIssuer, CredentialIssuerMetadata } from '@trustknots/vcknots/issuer'
import { initializeAuthzFlow, AuthorizationServerIssuer, AuthorizationServerMetadata, AuthzTokenRequest } from '@trustknots/vcknots/authz'

const app = new Hono();

// VcknotsContextを作成
const context = initializeContext({
  debug: process.env.NODE_ENV !== "production",
});

// IssuerFlowとAuthzFlowインスタンスを作成
const issuerFlow = initializeIssuerFlow(context);
const authzFlow = initializeAuthzFlow(context);
```

## VcknotsContext

`VcknotsContext` は、VCKnots の各機能で共有されるコアランタイムコンテキストです。

以下を管理します。各設定はVcknotsOptionsによって渡されます。

- providers
- extensions
- debug
- OAuth 関連

## VcknotsOptions

`initializeContext()` に渡す設定オプションです。

```typescript
type VcknotsOptions = {
  providers?: Providers
  extensions?: Extensions
  debug?: boolean
  oauth?: OAuthOptions
}
```

### providers

カスタム provider を追加します。

```typescript
const context = initializeContext({
  providers: [
    myProvider,
  ],
})
```

---

### extensions

VCKnots extension を追加します。

```typescript
const context = initializeContext({
  extensions: [
    myExtension,
  ],
})
```

### debug

開発用オプションです。

```typescript
const context = initializeContext({
  debug: true,
})
```

`debug: true` の場合:

- insecure な `http://` endpoint を許可
- localhost 開発環境向けの動作を有効化

`debug: false` または設定無し(undefined)の場合:

- `CredentialIssuerMetadata` の以下の endpoint に `http://` URL を設定すると `insecure_http_not_allowed` エラーになります。
  - `credential_endpoint`
  - `deferred_credential_endpoint`

```json
{
  "error": "insecure_http_not_allowed",
  "error_description": "CredentialIssuerMetadata contains insecure http url in credential_endpoint: http://localhost:8080/credentials"
}
```

本番環境では HTTPS endpoint を使用してください。

---

### oauth

Access Tokenに関する設定を指定します。

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

Access Token の sender constraint method を指定します。

```typescript
type SenderConstraintMethod = 'none' | 'dpop' | 'mtls'
```

| 値 | 説明 |
|---|---|
| `none` | sender-constrained access token を利用しません |
| `dpop` | DPoP-bound access token を利用します |
| `mtls` | mTLS sender-constrained access token（将来対応予定） |

---

#### dpop.mode

DPoP の要求レベルを指定します。詳細は[5.アクセストークンの発行](#5-アクセストークンの発行)を参照

## 3. Issuer機能のサンプル実装

### パラメータ

#### `:issuer` パラメータ

Issuerのエンドポイントで使用される`:issuer`パラメータは、Issuerの識別子を表します。

**形式**: `CredentialIssuer`型のURI文字列

**例**:
```typescript
// HTTPS URI形式
const issuerId = "https://issuer.example.com"
```

**用途**:
- Issuerのメタデータの管理
- クレデンシャルオファーの作成
- クレデンシャルの発行
- 認可サーバーの管理

**注意事項**:
- URL形式である必要がある（z.string().url()でバリデーション）
- HTTPSスキームを使用することを推奨
- 特殊文字を含む場合は適切にエンコードする

### 1. デフォルトメタデータの初期化

サーバー起動時にデフォルトのIssuer, 認可サーバーのメタデータを初期化する例：

```typescript
import issuerMetadataConfigRaw from '../samples/issuer_metadata.json' with { type: 'json' }
import authorizationMetadataConfigRaw from '../samples/authorization_metadata.json' with {
  type: 'json',
}

const issuerMetadataConfig = CredentialIssuerMetadata(issuerMetadataConfigRaw)
const authorizationMetadataConfig = AuthorizationServerMetadata(authorizationMetadataConfigRaw)

serve({ fetch: app.fetch, port: Number.parseInt(process.env.PORT ?? '8080') }, async (info) => {
  console.log(`Server is running on http://localhost:${info.port}`)

  // 初期化実行（デフォルト設定を使用）
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

### 2. Issuerメタデータの取得

Issuerのメタデータを取得するエンドポイント：

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

**例**:

**リクエスト**

```bash
curl http://localhost:8080/.well-known/openid-credential-issuer
```

**レスポンス**

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

### 3. クレデンシャルオファーの作成

クレデンシャルオファーを作成するエンドポイント：

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
        authorizationServer: options?.authorization_server,
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

**例**:

**リクエスト**

任意パラメータを指定する場合のみ、リクエストボディ（JSON）を含めてください。

- tx_code は、Credential Offer にトランザクションコードを含めるために使用できます。
- authorization_server は、Issuer Metadata の authorization_servers に複数のエントリーが含まれる場合にのみ指定できます。

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

**レスポンス**

```raw
openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredentialSdJwt%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%2268baf35e74ae430684662d85ea87160e%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22numeric%22%2C%22length%22%3A6%2C%22description%22%3A%22Please%20enter%20the%20one-time%20code.%22%7D%7D%7D%7D
```



### 4. 認可サーバーメタデータの取得

認可サーバーのメタデータを取得するエンドポイント：

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

**例**:

**リクエスト**

```bash
curl  http://localhost:8080/.well-known/oauth-authorization-server
```

**レスポンス**

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

### 5. アクセストークンの発行

アクセストークンを発行するエンドポイント：

```typescript
app.post('/token', async (c) => {
  const request = await c.req.formData()
  const requestData = Object.fromEntries(request.entries())
  const issuer = AuthorizationServerIssuer(baseUrl)

  const clientResolution = await authzFlow.resolveTokenRequestClientPolicy(
    issuer,
    requestData
  )
  if (!clientResolution.ok) {
    return c.json(
      {
        error: clientResolution.error,
        error_description: clientResolution.error_description,
      },
      400
    )
  }

  const dpopMode = clientResolution.dpopMode
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
  const accessToken = await authzFlow.createAccessToken(issuer, tokenRequest, {
    clientId: clientResolution.clientId,
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

**リクエストボディは `application/x-www-form-urlencoded` です**（`AuthzTokenRequest` はフォームフィールドから組み立てます）。`invalid_dpop_proof`（`invalid_dpop_proof`）や `use_dpop_nonce`（`DPoP-Nonce` ヘッダー付き）などの分岐を含む実装は [server/core/src/routes/authz.ts](https://github.com/trustknots/vcknots/blob/main/server/core/src/routes/authz.ts) を参照してください。

#### private_key_jwt による client authentication

Token endpoint では、`server/samples/oauth-clients.json` に登録された OAuth client を参照し、`token_endpoint_auth_method` が `private_key_jwt` の client に対して RFC 7523 の JWT bearer client authentication を検証します。

`oauth-server.json` / `oauth-clients.json` の項目説明は、[server/single/README.ja.md](https://github.com/trustknots/vcknots/blob/main/server/single/README.ja.md) の「OAuth policy / OAuth client 設定ファイル」を参照してください。

client の特定は次の順序で行います。

1. token request body に `client_id` がある場合は、その値を優先します。
2. `client_id` がない場合は、`client_assertion` JWT の `iss` / `sub` から client_id を導出します。
3. どちらからも client_id を得られない場合は anonymous token request として扱います。

Pre-Authorized Code の token request が anonymous token request になる場合、Authorization Server Metadata の `pre-authorized_grant_anonymous_access_supported` が `true` のときだけ `anonymous_client` policy を適用します。未設定または `false` の場合は、anonymous access を許可せず `invalid_client` を返します。

`client_id` が特定できたにもかかわらず登録済み client が存在しない場合は `invalid_client` です。登録済み client の `token_endpoint_auth_method` が `private_key_jwt` の場合は、`client_assertion_type` が `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` であること、`client_assertion` が compact JWT であること、`iss` / `sub` が登録済み `client_id` と一致すること、`aud` が登録済み `client_assertion_audience` または Authorization Server の token endpoint / issuer と一致することを確認します。

また、`exp` / `iat` / `jti` を必須として検証し、`nbf` がある場合は許容範囲内か確認します。`iat` / `nbf` は FAPI 2.0 Security Profile の clock skew 要件に合わせ、未来方向の許容範囲を短く制限します。`jti` は client ごとに保存し、同じ `client_assertion` の再利用を拒否します。

JOSE ヘッダーでは `alg` が `none` や `HS*` ではないことを確認します。Authorization Server メタデータの `token_endpoint_auth_signing_alg_values_supported` が設定されている場合は、その一覧に含まれる必要があります。さらに client 登録の `token_endpoint_auth_signing_alg` がある場合は、JWT ヘッダーの `alg` と一致する必要があります。署名検証には、登録済み client の `jwks.keys` に含まれる公開鍵を使用します。

認証済み client の `client_id` は、発行する access token の payload に `client_id` として含まれます。DPoP を併用する場合でも、private_key_jwt の client authentication と DPoP Proof の検証は独立して行います。

**例**:

**リクエスト**

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code" \
  --data-urlencode "pre-authorized_code=343ce17f1d274aa8bb3d19c140484889"
```

**レスポンス**

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJzdWIiOiIzNDNjZTE3ZjFkMjc0YWE4YmIzZDE5YzE0MDQ4NDg4OSIsImV4cCI6MTc2MTk3NjE1NiwiaWF0IjoxNzYxODg5NzU2fQ.vsV71EEtAo36jcb9N8un2cn36Oo_H1qtKuIp0uerdvI2jNcBhN7ltGeqmk1AVZhpk5kQZcfbkSiHje-j1Iv1zg",
  "token_type": "bearer",
  "expires_in": 86400
}
```

#### DPoP Proof を利用する token request

DPoP mode は Authorization Server の OAuth policy により、token endpoint の DPoP Proof 検証を制御できます。

| mode | token endpoint の挙動 |
|------|------------------------|
| `off` | DPoP を利用しません。Bearer access token を発行します。 |
| `optional` | DPoP ヘッダーがない場合は Bearer access token を発行します。DPoP ヘッダーがある場合は proof を検証し、DPoP-bound access token を発行します。 |
| `required` | DPoP ヘッダーを必須にします。未指定または不正な DPoP ヘッダーは `invalid_request` になります。 |

DPoP Proof に `nonce` がない、または nonce が無効な場合、Authorization Server は `DPoP-Nonce` レスポンスヘッダー付きで `use_dpop_nonce` を返します。Wallet はこの nonce を DPoP Proof JWT の `nonce` クレームに入れて token request を再送します。

```http
HTTP/1.1 400 Bad Request
DPoP-Nonce: 9288f7b2dffb42c2b08f2f4d4d8635d8
Content-Type: application/json

{
  "error": "use_dpop_nonce",
  "error_description": "Authorization server requires nonce in DPoP proof."
}
```

DPoP Proof の検証に成功した場合、レスポンスの `token_type` は `DPoP` になります。また、発行される access token には DPoP Proof の JOSE ヘッダーに含まれる公開鍵の JWK Thumbprint が `cnf.jkt` として含まれます。

```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 86400
}
```

DPoP-bound access token を使う後続リクエストでは、同じ公開鍵に対応する秘密鍵で署名した DPoP Proof を提示する必要があります。

#### Token endpoint（AS）と credential endpoint（RS）でのエラー応答の違い

[server/core](https://github.com/trustknots/vcknots/blob/main/server/core/src/routes/authz.ts) の実装では、役割によって HTTP ステータスとチャレンジの付け方が次のように異なります。

- **`POST /token`（Authorization Server）:** DPoP／リクエスト不正は多く **HTTP 400** と JSON ボディ（`invalid_request` / `invalid_dpop_proof` / `use_dpop_nonce`）で返します。`use_dpop_nonce` のときはレスポンスに **`DPoP-Nonce`** が付きますが、**現行実装では `WWW-Authenticate` は付けません**。
- **`POST /credentials`（Resource Server）:** アクセストークンや DPoP 検証の失敗は **HTTP 401** が中心です。**`invalid_token`** 相当では **`WWW-Authenticate: Bearer`**（`realm`・`error`・`error_description`）、**`invalid_dpop_proof`** および **`use_dpop_nonce`**（credential 側のメッセージ）では **`WWW-Authenticate: DPoP`** を付けます。後者は **`DPoP-Nonce` ヘッダー**も返る場合があります。Credential Request ボディが JSON でない、またはスキーマに合わない場合は **HTTP 400** と **`invalid_credential_request`** です。

### 6. Nonceエンドポイント

OID4VCI の [nonce endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint) に相当するエンドポイントです。Wallet が credential リクエストを送る前に c_nonce を取得する際に使用します。

Issuer メタデータに `nonce_endpoint` を設定すると、Wallet は `/.well-known/openid-credential-issuer` から取得したメタデータ経由で nonce エンドポイントの URL を参照します。

DPoP mode は `server/samples/oauth-server.json` の OAuth policy と、登録済み OAuth client の sender constraint 設定で決まります。Pre-Authorized Code の token request で `client_id` / `client_assertion` がない場合は anonymous token request として扱い、Authorization Server Metadata の `pre-authorized_grant_anonymous_access_supported` が `true` のときだけ `anonymous_client` policy を参照します。登録済み client に sender constraint 設定がない場合は `default_client` の policy を参照します。

OAuth policy の DPoP mode が `off` 以外の場合、`POST /nonce` は JSON ボディの `c_nonce` に加えて、レスポンスヘッダー `DPoP-Nonce` を返します。`c_nonce` と `DPoP-Nonce` は別の値です。

`c_nonce` は credential proof 用の nonce です。一方、`DPoP-Nonce` は token endpoint で提示する DPoP Proof 用の nonce です。用途が異なるため、TTL も別々に設定できます。

#### POST /nonce - nonce（c_nonce）の作成

```typescript
app.post('/nonce', async (c) => {
  try {
    const C_NONCE_TTL_MS = 2 * 60 * 1000  // 2分
    const DPOP_NONCE_TTL_MS = 5 * 60 * 1000  // 5分
    const cnonce = await issuerFlow.createNonce(C_NONCE_TTL_MS)
    const dpopMode = await resolveAuthzPolicyDpopMode(
      authzFlow,
      AuthorizationServerIssuer(baseUrl),
      'default_client'
    )
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

**例**:

**リクエスト**

```bash
curl -i -X POST http://localhost:8080/nonce
```

**レスポンス**

```http
HTTP/1.1 200 OK
Cache-Control: no-store
DPoP-Nonce: 9288f7b2dffb42c2b08f2f4d4d8635d8
Content-Type: application/json

{
  "c_nonce": "3ccc7973abef4102ad70a871e200304b"
}
```

OAuth policy の DPoP mode が `off` の場合、`DPoP-Nonce` ヘッダは付きません。

**実装例**:

- [server/core/src/routes/issue.ts](https://github.com/trustknots/vcknots/blob/main/server/core/src/routes/issue.ts)

#### GET /nonce/:nonce - nonceの有効性検証

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

**例**:

**リクエスト**

```bash
curl http://localhost:8080/nonce/3ccc7973abef4102ad70a871e200304b
```

**レスポンス**

```json
{
  "valid": true
}
```

#### DELETE /nonce/:nonce - nonceの取り消し

指定された nonce を取り消し（削除）します。nonce が存在しない場合は 404 を返します。

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

**例**:

**リクエスト**

```bash
curl -X DELETE http://localhost:8080/nonce/3ccc7973abef4102ad70a871e200304b
```

**レスポンス (200)**

```json
{
  "deleted": true
}
```

**レスポンス (404 - nonce が見つからない場合)**

```json
{
  "error": "not_found",
  "error_description": "Nonce not found."
}
```

### 7. クレデンシャルの発行

クレデンシャルを発行するエンドポイント：

#### Credential endpoint での DPoP-bound access token 検証

OAuth policy の DPoP mode により、credential endpoint で提示される access token と DPoP Proof の扱いを制御できます。

| mode | credential endpoint の挙動 |
|------|-----------------------------|
| `off` | DPoP を利用しません。`Authorization: DPoP <access_token>` または `DPoP` ヘッダーが送られた場合は拒否します。 |
| `optional` | DPoP を credential endpoint では必須にしません。送信者拘束のないアクセストークンは `Authorization: Bearer` のみで提示できます。一方、トークンに `cnf.jkt` が含まれる（送信者拘束／DPoP-bound）場合は `Authorization: Bearer` だけでは受け付けず、`Authorization: DPoP <access_token>` と `DPoP` ヘッダー（DPoP Proof JWT）を組み合わせて送る必要があります。 |
| `required` | すべてのリクエストで `Authorization: DPoP <access_token>` と `DPoP` ヘッダー（DPoP Proof JWT）が必要です。`Authorization: Bearer` のみの提示は拒否します。 |

credential endpoint はリソースサーバーとして動作するため、DPoP-bound access token を受け取った場合は RFC 9449 に沿って DPoP Proof を検証します。

- `DPoP` ヘッダーが単一の compact JWT であること（実装では値に **カンマ**が含まれると複数ヘッダの結合とみなし拒否します）。
- DPoP Proof JWT の JOSE ヘッダー `typ` が `dpop+jwt` であること。
- `alg` が `none` や HMAC 系ではなく、非対称署名アルゴリズムであること。
- JOSE ヘッダーの `jwk` に公開鍵が含まれ、秘密鍵が含まれていないこと。
- DPoP Proof JWT の署名を `jwk` の公開鍵で検証できること。
- payload に `jti`, `iat`, `htm`, `htu` が含まれること。
- `htm` が実際の HTTP method と一致すること。
- `htu` がクエリとフラグメントを除いた credential endpoint の URI と一致すること。
- credential endpoint では `ath` が必須であり、提示された access token の SHA-256 hash を base64url エンコードした値と一致すること。
- access token の `cnf.jkt` と DPoP Proof の `jwk` thumbprint が一致すること。
- `jti` を保存し、同じ DPoP Proof の再利用（リプレイ）を拒否すること。
- DPoP Proof の `iat` は、実装既定では `maxTokenAge` 300 秒と `clockTolerance` 60 秒の範囲で有効とみなされます（`issuer+verifier` の DPoP proof プロバイダ。工場オプションで変更可能）。

Credential proof JWT の `iss` は、Pre-Authorized Code Flow であっても常に省略するわけではありません。token endpoint で anonymous access により取得された access token には `client_id` が含まれないため、proof JWT の `iss` は省略する必要があります。一方、登録済み OAuth client として取得された access token には `client_id` が含まれます。`issueCredential` 呼び出し時に `authorizeCredentialEndpointAccess` の結果を `options.authorizationContext` として渡すと、ライブラリが access token から得た `client_id` を内部で proof 検証に使います。proof JWT に `iss` があるときは、その `client_id` と一致する必要があります。`proofJwt.clientId` を個別に指定する必要はありません。

DPoP Proof が不正な場合、credential endpoint は `401 Unauthorized` と `WWW-Authenticate: DPoP` を返します。アクセストークン JWT の形式・署名・issuer 不一致など **`invalid_token`** 相当の場合は、同じく **401** と **`WWW-Authenticate: Bearer`**（`realm` および `error="invalid_token"` 等）になります。

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP realm="http://localhost:8080", error="invalid_dpop_proof", error_description="DPoP proof JWT ath claim does not match the access token."
Content-Type: application/json

{
  "error": "invalid_dpop_proof",
  "error_description": "DPoP proof JWT ath claim does not match the access token."
}
```

`use_dpop_nonce` の場合、credential endpoint は `401 Unauthorized` を返し、レスポンスヘッダーに `DPoP-Nonce` を含めます。Wallet はこの `DPoP-Nonce` ヘッダーの値を DPoP Proof JWT の `nonce` クレームに入れて credential request を再送します。

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

次のコードは処理の順序（**先に `authorizeCredentialEndpointAccess` でアクセストークンと DPoP を検証し、その後 JSON ボディを読む**）、`nonceRequired: true`、Credential Request ボディ不正時の **`invalid_credential_request`**、および **401 と `WWW-Authenticate`** を [server/core/src/routes/issue.ts](https://github.com/trustknots/vcknots/blob/main/server/core/src/routes/issue.ts) に合わせた抜粋です。`Context`（Hono）、`VcknotsError`、`buildBearerAuthenticateHeader` / `buildDpopAuthenticateHeader` などのインポート・本番向けのログは省略しています。

```typescript
const DPOP_NONCE_TTL_MS = 5 * 60 * 1000

app.post('/credentials', async (c) => {
  try {
    const issuer = CredentialIssuer(baseUrl)
    const authz = AuthorizationServerIssuer(baseUrl)

    let authorizationContext: CredentialEndpointAuthorizationContext
    try {
      authorizationContext = await authzFlow.authorizeCredentialEndpointAccess(authz, {
        authorizationHeader: c.req.header('Authorization'),
        dpopHeader: c.req.header('DPoP'),
        htm: c.req.method,
        htu: `${baseUrl}/credentials`,
        nonceRequired: true,
      })
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
          error: 'invalid_credential_request',
          error_description: 'Request body must be a valid JSON.',
        },
        400
      )
    }
    let parse: CredentialRequest
    try {
      parse = CredentialRequest(request)
    } catch (err) {
      if (err instanceof Error && err.name === 'ZodError') {
        return c.json(
          {
            error: 'invalid_credential_request',
            error_description: 'Request body does not conform to CredentialRequest schema.',
          },
          400
        )
      }
      throw err
    }

    const credential = await issuerFlow.issueCredential(issuer, parse, {
      authorizationContext,
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
      proofJwt: {
        usePreAuth: true,
      },
    })
    return c.json(credential)
  } catch (err) {
    const errorResponse = handleError(err)
    const status = errorResponse.error === 'internal_server_error' ? 500 : 400
    return c.json(errorResponse, status)
  }
})
```

**例**:

**リクエスト**

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

**レスポンス**

```json
{
  "credentials": [
    {
      "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6IjM4YzEwMWQ2LTEwZDktNGU0Mi05MDlkLWY1N2Y0OWIyMTZjNiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJpc3N1YW5jZURhdGUiOiIyMDI1LTEwLTMxVDA3OjAzOjA4LjUzN1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSIsImdpdmVuX25hbWUiOiJ0ZXN0IiwiZmFtaWx5X25hbWUiOiJ0YXJvIiwiZGVncmVlIjoiNSIsImdwYSI6InRlc3QifX0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInN1YiI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.LwcUtOS0b2sEEKp-c1CpLZorqDF0heRUuJm_zPSuZVSa7XRWkghkvzq7olr2E4BOcoZryn-QCbGVugcZTPs4LA"
    }
  ]
}
```


## 4. 型定義の説明

### CredentialIssuer {#CredentialIssuer}

Issuerの識別子を表す型です。URI形式の文字列で、Issuerの一意な識別に使用されます。

定義は[issuer+verifier/src/credential-issuer.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-issuer.types.ts)を参照してください。

### CredentialIssuerMetadata {#CredentialIssuerMetadata}

Issuerのメタデータを定義する型です。クライアント名、サポートするクレデンシャル形式、エンドポイントなどの情報を含みます。

定義は[issuer+verifier/src/credential-issuer.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-issuer.types.ts)を参照してください。


### CredentialResponse {#CredentialResponse}

発行されたクレデンシャルのレスポンスを表す型です。JWT形式のクレデンシャルやメタデータなどの情報を含みます。

定義は[issuer+verifier/src/credential-response.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-response.types.ts)を参照してください。

### AuthorizationServerIssuer {#AuthorizationServerIssuer}

認可サーバーの識別子を表す型です。URI形式の文字列で、認可サーバーの一意な識別に使用されます。

定義は[issuer+verifier/src/authorization-server.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/authorization-server.types.ts)を参照してください。

### AuthorizationServerMetadata {#AuthorizationServerMetadata}

認可サーバーのメタデータを定義する型です。Issuer情報、サポートする形式、エンドポイントなどの情報を含みます。

定義は[issuer+verifier/src/authorization-server.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/authorization-server.types.ts)を参照してください。

### AuthzTokenRequest

アクセストークンリクエストを表す型です。タイプが認可コード、事前認可コードかなどの情報を含みます。

定義は[issuer+verifier/src/token-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/token-request.types.ts)を参照してください。

## 5. IssuerFlowの各メソッド

### findIssuerMetadata

Issuerのメタデータを取得します。

```typescript
findIssuerMetadata(id: CredentialIssuer): Promise<CredentialIssuerMetadata | null>
```

**パラメータ**:
- `id`: Issuerの識別子（[CredentialIssuer](#CredentialIssuer)）

**戻り値**: メタデータオブジェクト（[CredentialIssuerMetadata](#CredentialIssuerMetadata)）またはnullを返します。


### createIssuerMetadata
Issuerのメタデータを作成・保存します。

```typescript
createIssuerMetadata(issuer: CredentialIssuerMetadata): Promise<void>
```

**パラメータ**:
- `issuer`: Issuerのメタデータ（[CredentialIssuerMetadata](#CredentialIssuerMetadata)）

**戻り値**: なし

**エラーケース**:
- `provider_not_found`: 未対応の`alg`が設定された


### createNonce

nonce（c_nonce）を作成します。OID4VCI の nonce endpoint 用です。

```typescript
createNonce(ttlMs?: number): Promise<string>
```

**パラメータ**:
- `ttlMs`: nonce の有効期限（ミリ秒）。省略時はプロバイダーのデフォルト値を使用

**戻り値**: 生成された nonce 文字列

### validateNonce

指定された nonce の有効性を検証します。

```typescript
validateNonce(nonce: string): Promise<boolean>
```

**パラメータ**:
- `nonce`: 検証対象の nonce 値

**戻り値**: nonce が有効な場合 `true`、無効または存在しない場合 `false`

### revokeNonce

指定された nonce を取り消し（削除）します。

```typescript
revokeNonce(nonce: string): Promise<boolean>
```

**パラメータ**:
- `nonce`: 取り消し対象の nonce 値

**戻り値**: nonce の取り消しに成功した場合 `true`、nonce が見つからない場合 `false`

### offerCredential
クレデンシャルオファーを作成します。

```typescript
offerCredential(
  issuer: CredentialIssuer,
  configurations: CredentialConfigurationId[],
  options?: OfferOptions
): Promise<CredentialOffer>
```

**パラメータ**:
- `issuer`: Issuerの識別子（[CredentialIssuer](#CredentialIssuer)）
- `configurations`: クレデンシャル構成IDの配列（[CredentialConfigurationId](#CredentialConfigurationId)）
- `options`: オファー作成のオプション（[OfferOptions](#OfferOptions)）

**戻り値**: クレデンシャルオファーを返します。

クレデンシャルオファーの型定義は[issuer+verifier/src/credential-offer.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-offer.types.ts)を参照してください。


**エラーケース**:
- `unsupported_grant_type`: 未対応のフローが設定された（認可コードフローには未対応です）
- `issuer_not_found`: 未登録のIssuerが設定された

#### CredentialConfigurationId{#CredentialConfigurationId}
クレデンシャル構成IDを定義する型です。

定義は[issuer+verifier/src/credential-issuer.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-issuer.types.ts)を参照してください。

#### OfferOptions{#OfferOptions}
クレデンシャルオファー作成時のオプションを定義する型です。事前認可フローを使用するかを設定できます。
定義は下記のとおりです。

```typescript
type OfferOptions =
  | {
      usePreAuth: false
      state?: unknown
      authorizationServer?: string
    }
  | {
      usePreAuth: true
      txCode?: {
        input_mode?: 'numeric' | 'text'
        length?: number
        description?: string
      }
      ttlSec?: number
      authorizationServer?: string
    }
```

### issueCredential
クレデンシャルを発行します。

```typescript
issueCredential(
  issuer: CredentialIssuer,
  credentialRequest: CredentialRequest,
  options: IssueOptions
): Promise<CredentialResponse>
```

**パラメータ**:
- `issuer`: Issuerの識別子（[CredentialIssuer](#CredentialIssuer)）
- `credentialRequest`: クレデンシャルリクエスト（[CredentialRequest](#CredentialRequest)）
- `options`: 発行オプション（[IssueOptions](#IssueOptions)）。credential endpoint で検証済みの `authorizationContext` を含めます。

**戻り値**: クレデンシャルレスポンスを返します。

クレデンシャルレスポンスの型定義は[issuer+verifier/src/credential-response.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-response.types.ts)を参照してください。

**JWT クレデンシャルプルーフ（`proofs.jwt`）について**

- **事前認可コードフロー**で anonymous access token を得ている場合（access token に `client_id` なし）: `proofJwt: { usePreAuth: true }`。プルーフ JWT に **`iss` クレームを付けない**必要があります。
- **事前認可コードフロー**で登録済み OAuth client として access token を得ている場合（access token に `client_id` あり）: `proofJwt: { usePreAuth: true }`。プルーフ JWT に `iss` がある場合は、access token の `client_id` と一致する必要があります（`iss` の省略も可）。`client_id` は `options.authorizationContext` 経由で内部参照され、呼び出し側で `proofJwt` に渡す必要はありません。
- **認可コードフロー**：未対応


#### JWT proof の JOSE 保護ヘッダ

JOSE 保護ヘッダの検証内容は [credential-proof-jwt.provider.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/providers/credential-proof-jwt.provider.ts) を参照してください。根拠となる記述は [OpenID for Verifiable Credential Issuance 1.0 — JWT proof type](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type) を参照してください（仕様の章・節番号は改訂で変わる場合があります）。

- **`typ`**: `openid4vci-proof+jwt` であること（RFC 8725 に基づく明示的タイピング）。
- **`alg`**: `none` および IANA JWA の **対称署名（MAC、`HS*` で始まる識別子）** は拒否されます。
- **`kid` / `jwk` / `x5c`**: **同時に複数を含めてはいけません**。また **少なくともいずれか 1 つは必須**です（いずれも無い場合も `invalid_proof`）。
- **`trust_chain`**: 現在未対応です。

keyごとの動き:

| ヘッダ | 動き |
|--------|------|
| **`kid`** | DID URL（`did:…` とオプションの `#fragment`）として **`did-provider`** で解決し、該当する `verificationMethod` の公開鍵で署名を検証します。 |
| **`jwk`** | ヘッダ内の JWK で検証します。**秘密鍵材料（例: `d`）が含まれる JWK は拒否**されます。 |
| **`x5c`** | 証明書チェーンを **`certificate-provider`** で検証したうえで、先頭証明書の公開鍵で検証します。`x5c` を使う構成では、Vcknots 初期化時に **`certificate-provider` をプロバイダ一覧へ登録**してください。 |

**エラーケース**:
- `issuer_not_found`: 未登録のIssuerが設定された
- `unknown_credential_configuration`: `credential_configuration_id`がサポートされていない
- `unsupported_credential_type`: 指定された`credential_definition`もしくは`proof_type`がサポートされていない
- `invalid_credential_request`: Credential Request ボディ不正、許可されていない `credential_configuration_id`、`proof` が見つからないかサポートされていない、設定 ID 不備など
- `invalid_proof`: `proof`が検証できない、OID4VCI の JWT proof に合わないヘッダ（`typ` / `alg` / `kid`・`jwk`・`x5c` の組み合わせなど）、未サポートの header、`nonce`が見つからない
- `unsupported_issuer_key_alg`: Issuerの署名アルゴリズムがサポートされていない
- `authz_issuer_key_not_found`: Issuerの鍵が見つからない
- `internal_server_error`: 署名に失敗した

#### CredentialRequest {#CredentialRequest}
クレデンシャル発行リクエストを定義する型です。クレデンシャルの識別子などを設定できます。

定義は[issuer+verifier/src/credential-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-request.types.ts)を参照してください。

#### IssueOptions {#IssueOptions}
クレデンシャル発行オプションを定義する型です。アルゴリズムやクレーム、JWT プルーフ検証用のヒントなどを設定できます。
定義は下記のとおりです（実装は [issuer.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/issuer.flows.ts) を参照）。

```typescript
type IssueOptions = {
  /** credential endpoint で `authorizeCredentialEndpointAccess` が返した検証済みコンテキスト */
  authorizationContext: CredentialEndpointAuthorizationContext
  alg: string
  cnonce?: {
    c_nonce_expires_in: number
  }
  claims?: Record<string, unknown>
  subject?: string
  /** grant type が pre-authorized_code かどうか。access token に client_id があるかは authorizationContext 側で表し、proof 検証に内部利用されます。 */
  proofJwt?: {
    usePreAuth: boolean
  }
}
```

#### CredentialEndpointAuthorizationContext {#CredentialEndpointAuthorizationContext}

credential endpoint で access token（および必要なら DPoP Proof）を検証した結果です。`authorizeCredentialEndpointAccess` が返し、`issueCredential` の `options.authorizationContext` に渡します。

```typescript
type CredentialEndpointAuthorizationContext = {
  /** 提示された access token に紐づく allowed credential configuration の不透明キー */
  allowedCredentialConfigurationKey: string
  /** access token payload から得た OAuth client id。anonymous access token では省略 */
  clientId?: string
  /** credential endpoint が受理した access token の提示方法 */
  tokenType: 'bearer' | 'dpop'
}
```

`allowedCredentialConfigurationKey` は access token 文字列の SHA-256 hash（RFC 9449 `ath` と同じ計算法）です。呼び出し側で hash を計算したり access token payload を解析する必要はありません。

## 6. AuthzFlowの各メソッド

### findAuthzServerMetadata
認可サーバーのメタデータを取得します。

```typescript
findAuthzServerMetadata(issuer: AuthorizationServerIssuer): Promise<AuthorizationServerMetadata | null>
```

**パラメータ**:
- `issuer`: 認可サーバーの識別子（[AuthorizationServerIssuer](#AuthorizationServerIssuer)）

**戻り値**: メタデータオブジェクト（[AuthorizationServerMetadata](#AuthorizationServerMetadata)）またはnullを返します。


#### AuthorizationServerIssuer{#AuthorizationServerIssuer}
認可サーバーのIssuerを定義する型です。

定義は[issuer+verifier/src/authorization-server.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/authorization-server.types.ts)を参照してください。


### createAuthzServerMetadata
認可サーバーのメタデータを作成・保存します。

```typescript
createAuthzServerMetadata(
  metadata: AuthorizationServerMetadata,
  options?: { alg?: 'ES256' }
): Promise<void>
```

**パラメータ**:
- `metadata`: 認可サーバーのメタデータ（[AuthorizationServerMetadata](#AuthorizationServerMetadata)）
- `options`: 署名アルゴリズム

**戻り値**: なし


### createAccessToken
アクセストークンを発行します。

```typescript
createAccessToken<T extends GrantType>(
  authz: AuthorizationServerIssuer,
  tokenRequest: TokenRequest,
  options?: TokenRequestOptions[T]
): Promise<Object>
```

**パラメータ**:
- `authz`: 認可サーバーの識別子（[AuthorizationServerIssuer](#AuthorizationServerIssuer)）
- `tokenRequest`: トークンリクエスト（[TokenRequest](#TokenRequest)）
- `options`: トークンリクエストのオプション

  ```typescript
  type TokenRequestOptions = {
    [GrantType.AuthorizationCode]: {
      // 認可コードフローは未対応
      alg?: string
      clientId?: string
      dpopProof?: {
        proofJwt: string
        htm: string
        htu: string
        nonceRequired?: boolean
      }
    }
    [GrantType.PreAuthorizedCode]: {
      ttlSec?: number
      alg?: string
      clientId?: string
      dpopProof?: {
        proofJwt: string
        htm: string
        htu: string
        nonceRequired?: boolean
      }
    }
  }
  ```

  - `clientId`: client authentication 済みの OAuth client id。指定した場合、発行する access token payload に `client_id` として含まれます。
  - `dpopProof`: DPoP-bound access token を発行するための DPoP Proof 検証情報です。検証に成功した場合、access token payload に `cnf.jkt` が含まれ、レスポンスの `token_type` は `DPoP` になります。

**戻り値**: アクセストークンは下記のような形式で戻されます：
```typescript
// grant_typeで事前認可コードが選択された場合
{
  access_token: `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`,
  token_type: 'bearer',
  expires_in: option?.ttlSec ?? 86400
}
```

`clientId` を指定した場合、access token payload には `client_id` が含まれます。DPoP Proof を指定して検証に成功した場合は、payload に `cnf.jkt` が含まれ、`token_type` は `DPoP` になります。

Pre-Authorized Code フローでは、token 発行時に pre-authorized code に紐づく `credential_configuration_ids` を **`allowed-credential-configuration-store-provider`** に保存します。キーは compact access token の SHA-256 hash（base64url、`calculateAccessTokenHash` と同じ）で、TTL は `ttlSec`（access token の `expires_in` と同じ秒数）です。credential endpoint では `issueCredential` がこの store を参照し、リクエストされた `credential_configuration_id` が token 発行時に許可された ID かを確認します。

**エラーケース**:
- `provider_not_found`:  秘密鍵で未対応のアルゴリズムが設定された
- `invalid_grant`: 有効でない事前認可コードが設定された
- `invalid_request`: 認可サーバーの鍵が未登録、アルゴリズムが未設定、グラントタイプがサポートされていない
- `internal_server_error`: 署名に失敗した
- `unsupported_grant_type`: 認可コードフローを設定（現在未対応）

#### TokenRequest{#TokenRequest}
クレデンシャル発行リクエストを定義する型です。クレデンシャルの識別子などを設定できます。

定義は[issuer+verifier/src/token-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/token-request.types.ts)を参照してください。

#### TokenRequestOptions{#TokenRequestOptions}
トークンリクエスト時のオプションを定義する型です。使用するフローなどを設定できます。（認可コードフローは未対応です）
定義は下記のとおりです。

```typescript
type TokenRequestOptions = {
  [GrantType.AuthorizationCode]: {
    // 認可コードフローは未対応
    alg?: string
    clientId?: string
    dpopProof?: {
      proofJwt: string
      htm: string
      htu: string
      nonceRequired?: boolean
    }
  }
  [GrantType.PreAuthorizedCode]: {
    ttlSec?: number
    alg?: string
    clientId?: string
    dpopProof?: {
      proofJwt: string
      htm: string
      htu: string
      nonceRequired?: boolean
    }
  }
}
```

- `clientId`: client authentication 済みの OAuth client id。指定した場合、発行する access token payload に `client_id` として含まれます。
- `dpopProof`: DPoP-bound access token を発行するための DPoP Proof 検証情報です。検証に成功した場合、access token payload に `cnf.jkt` が含まれ、レスポンスの `token_type` は `DPoP` になります。
- `ttlSec`: Pre-Authorized Code フローにおける access token の有効期間（秒）。省略時はデフォルト値が使用されます。


### authorizeCredentialEndpointAccess
credential endpoint 向けの access token 検証を行い、クレデンシャル発行に必要なコンテキストを返します。`Authorization` / `DPoP` ヘッダーの解析、OAuth policy に基づく sender-constrained access token の扱い、DPoP Proof 検証（DPoP scheme の場合）を内部で行います。

```typescript
authorizeCredentialEndpointAccess(
  authz: AuthorizationServerIssuer,
  options: CredentialEndpointAuthorizationOptions
): Promise<CredentialEndpointAuthorizationContext>
```

**パラメータ**:
- `authz`: 認可サーバーの識別子（[AuthorizationServerIssuer](#AuthorizationServerIssuer)）
- `options`: リクエストヘッダーと HTTP コンテキスト

```typescript
type CredentialEndpointAuthorizationOptions = {
  authorizationHeader?: string | null
  dpopHeader?: string | null
  htm: string
  htu: string
  nonceRequired?: boolean
  alg?: string
}
```

**戻り値**: [CredentialEndpointAuthorizationContext](#CredentialEndpointAuthorizationContext)

**エラーケース**（主なもの）:
- `invalid_access_token`: Authorization ヘッダー不正、JWT 検証失敗、policy 不一致など
- `invalid_dpop_proof`: DPoP Proof 検証失敗
- `use_dpop_nonce`: DPoP Proof に nonce が必要

server 実装では、このメソッドを credential リクエストボディを読む**前**に呼び出してください。

### verifyAccessToken
アクセストークンを検証します。

```typescript
verifyAccessToken(authz: AuthorizationServerIssuer, accessToken: string): Promise<boolean>
```

**パラメータ**:
- `authz`: 認可サーバーの識別子（[AuthorizationServerIssuer](#AuthorizationServerIssuer)）

**戻り値**: アクセストークンが有効をbooleanで返します。

**エラーケース**:
- `invalid_access_token`:  アクセストークンが有効なjwtでないか、`authz`が期待されたものでない
- `authz_issuer_key_not_found`: 認可サーバーの鍵が見つからない
- `provider_not_found`: 署名アルゴリズムが未サポート


## 7. 注意事項

1. **アクセストークンの検証**: クレデンシャル発行時には `AuthzFlow.authorizeCredentialEndpointAccess` で access token（および必要なら DPoP Proof）を検証し、返却された `authorizationContext` を `issueCredential` の `options.authorizationContext` に渡してください。

2. **セキュリティ**: 本番環境では、適切な認証・認可の仕組みを実装してください。
   - 秘密鍵の管理には特に注意を払ってください
   - HTTPSを使用して通信を暗号化してください

3. **URLエンコード**: issuer IDにURLエンコードが必要な文字（例：`:`、`/`）が含まれる場合は、適切にエンコードしてください。

4. **Issuer Metadata の HTTPS 制約**:
   - 本番モード（`debug: false`）では、`CredentialIssuerMetadata` の以下の endpoint に `http://` URL を設定できません。
     - `credential_endpoint`
     - `deferred_credential_endpoint`
   - insecure な URL が設定された場合、`insecure_http_not_allowed` エラーになります。
   - ローカル開発用途では、`initializeContext({ debug: true })` を指定することで HTTP endpoint を許可できます。

```typescript
const context = initializeContext({
  debug: true,
})
```


## 8. トラブルシューティング

### よくある問題

- **Q:メタデータのバリデーションエラー**:
    - **A：** 提供されたメタデータがCredentialIssuerMetadataスキーマ、AuthorizationServerMetadataスキーマに適合しているかを確認してください。

- **Q:クレデンシャルオファーの作成エラー**:`unsupported_grant_type`
    - **A：**  未実装のフローを呼び出していないか確認してください。現在対応しているのは事前認可コードフローです。

- **Q:クレデンシャル発行エラー**:`invalid_proof`
    - **A：**  クレデンシャルリクエストのproof.jwtのheaderがkidを含んでいるかを確認してください。また、proof に含まれる `nonce` が有効かを確認してください。
