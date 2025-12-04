---
sidebar_position: 2
---

# Issuer機能のセットアップと使用方法

このガイドでは、VCKnotsのIssuer機能のセットアップと使用方法について説明します。

## 1. 前提条件

- OpenID for Verifiable Credential Issuance - draft 13 に対応([OpenID for Verifiable Credential Issuance - draft 13](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html))
- Node.js v14以降がインストールされていること
- TypeScriptが設定されていること
- 本ドキュメントはserverのサンプル実装に基づいて説明します
- HonoのWebフレームワークを使用していますが、他のフレームワークでも利用可能です
- 現在対応しているフローは事前認可コードフローです

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

### 3. クレデンシャルオファーの作成

クレデンシャルオファーを作成するエンドポイント：

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

**例**:

**リクエスト**

```bash
curl -X POST http://localhost:8080/issue/configurations/UniversityDegreeCredential/offer
```

**レスポンス**

```raw
openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22343ce17f1d274aa8bb3d19c140484889%22%7D%7D%7D
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

### 5. アクセストークンの発行

アクセストークンを発行するエンドポイント：

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

**例**:

**リクエスト**

```bash
curl -X POST http://localhost:8080/authz/token \
  -H "Content-Type: application/json" \
  -d ' {
    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "pre-authorized_code": "343ce17f1d274aa8bb3d19c140484889"
  }'
```

**レスポンス**

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJzdWIiOiIzNDNjZTE3ZjFkMjc0YWE4YmIzZDE5YzE0MDQ4NDg4OSIsImV4cCI6MTc2MTk3NjE1NiwiaWF0IjoxNzYxODg5NzU2fQ.vsV71EEtAo36jcb9N8un2cn36Oo_H1qtKuIp0uerdvI2jNcBhN7ltGeqmk1AVZhpk5kQZcfbkSiHje-j1Iv1zg",
  "token_type": "bearer",
  "expires_in": 86400,
  "c_nonce": "3ccc7973abef4102ad70a871e200304b",
  "c_nonce_expires_in": 300000
}
```

### 6. クレデンシャルの発行

クレデンシャルを発行するエンドポイント：

```typescript
app.post('issue/credentials', async (c) => {
  try {
    const issuer = AuthorizationServerIssuer(baseUrl)

    const request = await c.req.json()
    const parsedReq = CredentialRequest(request)
  
    // AccessToken 検証
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
    // Credential 発行
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

**例**:

**リクエスト**

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

**レスポンス**

```json
{
  "credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6IjM4YzEwMWQ2LTEwZDktNGU0Mi05MDlkLWY1N2Y0OWIyMTZjNiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJpc3N1YW5jZURhdGUiOiIyMDI1LTEwLTMxVDA3OjAzOjA4LjUzN1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSIsImdpdmVuX25hbWUiOiJ0ZXN0IiwiZmFtaWx5X25hbWUiOiJ0YXJvIiwiZGVncmVlIjoiNSIsImdwYSI6InRlc3QifX0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInN1YiI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.LwcUtOS0b2sEEKp-c1CpLZorqDF0heRUuJm_zPSuZVSa7XRWkghkvzq7olr2E4BOcoZryn-QCbGVugcZTPs4LA",
  "c_nonce_expires_in": 300000
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
- `PROVIDER_NOT_FOUND`: 未対応の`alg`が設定された


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
- `FEATURE_NOT_IMPLEMENTED_YET`: 未対応のフローが設定された（認可コードフローには未対応です）
- `ISSUER_NOT_FOUND`: 未登録のIssuerが設定された

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
クレデンシャルを発行します。

```typescript
issueCredential(
  issuer: CredentialIssuer,
  credentialRequest: CredentialRequest,
  options?: IssueOptions
): Promise<CredentialResponse>
```

**パラメータ**:
- `issuer`: Issuerの識別子（[CredentialIssuer](#CredentialIssuer)）
- `credentialRequest`: クレデンシャルリクエスト（[CredentialRequest](#CredentialRequest)）
- `options`: 発行オプション（[IssueOptions](#IssueOptions)）

**戻り値**: クレデンシャルレスポンスを返します。

クレデンシャルレスポンスの型定義は[issuer+verifier/src/credential-response.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-response.types.ts)を参照してください。

**エラーケース**:
- `ISSUER_NOT_FOUND`: 未登録のIssuerが設定された
- `PROVIDER_NOT_FOUND`:  未対応の`format`が設定された
- `INVALID_REQUEST`: `format`が未設定
- `UNSUPPORTED_CREDENTIAL_TYPE`: 指定された`credential_definition`もしくは`proof_type`がサポートされていない
- `INVALID_CREDENTIAL_REQUES`: `proof`が見つからないかサポートされていない
- `INVALID_PROOF`: `proof`が検証できない、未サポートのheaderが設定された、`nonce`が見つからない
- `UNSUPPORTED_ISSUER_KEY_ALG`: Issuerの署名アルゴリズムがサポートされていない
- `AUTHZ_ISSUER_KEY_NOT_FOUND`: Issuerの鍵が見つからない
- `INTERNAL_SERVER_ERROR`: 署名に失敗した

#### CredentialRequest{#CredentialRequest}
クレデンシャル発行リクエストを定義する型です。クレデンシャルの識別子などを設定できます。

定義は[issuer+verifier/src/credential-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/credential-request.types.ts)を参照してください。

#### IssueOptions{#IssueOptions}
クレデンシャル発行オプションを定義する型です。アルゴリズムやクレームなどを設定できます。
定義は下記のとおりです。

```typescript
type IssueOptions = {
  alg: string
  cnonce?: {
    c_nonce_expires_in: number
  }
  claims?: Record<string, unknown>
}
```

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
    }
    [GrantType.PreAuthorizedCode]: {
      ttlSec?: number
      c_nonce_expire_in?: number
    }
  }
  ```

**戻り値**: アクセストークンは下記のような形式で戻されます：
```typescript
// grant_typeで事前認可コードが選択された場合
{
  access_token: `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`,
  token_type: 'bearer',
  expires_in: option?.ttlSec ?? 86400,
  c_nonce: cnonce,
  c_nonce_expires_in: option?.c_nonce_expire_in ?? 60 * 5 * 1000, // 5 minutes
}
```

**エラーケース**:
- `PROVIDER_NOT_FOUND`:  秘密鍵で未対応のアルゴリズムが設定された
- `PRE_AUTHORIZED_CODE_NOT_FOUND`: 有効でない事前認可コードが設定された
- `INVALID_REQUEST`: 認可サーバーの鍵が未登録、アルゴリズムが未設定、グラントタイプがサポートされていない
- `INTERNAL_SERVER_ERROR`: 署名に失敗した
- `FEATURE_NOT_IMPLEMENTED_YET`: 認可コードフローを設定（現在未対応）

#### TokenRequest{#TokenRequest}
クレデンシャル発行リクエストを定義する型です。クレデンシャルの識別子などを設定できます。

定義は[issuer+verifier/src/token-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/token-request.types.ts)を参照してください。

#### TokenRequestOptions{#TokenRequestOptions}
トークンリクエスト時のオプションを定義する型です。使用するフローなどを設定できます。（認可コードフローは未対応です）
定義は下記のとおりです。

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
アクセストークンを検証します。

```typescript
verifyAccessToken(authz: AuthorizationServerIssuer, accessToken: string): Promise<boolean>
```

**パラメータ**:
- `authz`: 認可サーバーの識別子（[AuthorizationServerIssuer](#AuthorizationServerIssuer)）

**戻り値**: アクセストークンが有効をbooleanで返します。

**エラーケース**:
- `INVALID_ACCESS_TOKEN`:  アクセストークンが有効なjwtでないか、`authz`が期待されたものでない
- `AUTHZ_ISSUER_KEY_NOT_FOUND`: 認可サーバーの鍵が見つからない
- `PROVIDER_NOT_FOUND`: 署名アルゴリズムが未サポート


## 7. 注意事項

1. **アクセストークンの検証**: クレデンシャル発行時には必ずアクセストークンを検証してください。

2. **セキュリティ**: 本番環境では、適切な認証・認可の仕組みを実装してください。
   - 秘密鍵の管理には特に注意を払ってください
   - HTTPSを使用して通信を暗号化してください

3. **URLエンコード**: issuer IDにURLエンコードが必要な文字（例：`:`、`/`）が含まれる場合は、適切にエンコードしてください。


## 8. トラブルシューティング

### よくある問題

- **Q:メタデータのバリデーションエラー**:
    - **A：** 提供されたメタデータがCredentialIssuerMetadataスキーマ、AuthorizationServerMetadataスキーマに適合しているかを確認してください。

- **Q:クレデンシャルオファーの作成エラー**:`FEATURE_NOT_IMPLEMENTED_YET`
    - **A：**  未実装のフローを呼び出していないか確認してください。現在対応しているのは事前認可コードフローです。

- **Q:クレデンシャル発行エラー**:`INVALID_PROOF`
    - **A：**  クレデンシャルリクエストのprooj.jwtのheaderがkidを含んでいるかを確認してください。


