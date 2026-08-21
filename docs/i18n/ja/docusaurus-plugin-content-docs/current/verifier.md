---
sidebar_position: 3
---


# Verifier機能のセットアップと使用方法

このガイドでは、VCKnotsのVerifier機能のセットアップと使用方法について説明します。

## 1. 前提条件

- OpenID for Verifiable Presentations 1.0 に対応（[OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)）　　
以下は現時点では未実装ですが、今後対応予定です。
  - `response_mode`は`direct_post`は対応していますが、`direct_post.jwt`は未対応です（現時点では未実装／今後対応予定）。
- クロスデバイスフローを前提としています
- Node.js v14以降がインストールされていること
- TypeScriptが設定されていること
- 本ドキュメントはserverのサンプル実装に基づいて説明します
- HonoのWebフレームワークを使用していますが、他のフレームワークでも利用可能です
- 現在対応しているclient_id_schema:x509_san_dns、redirect_uriになります
- 現在対応しているVPフォーマットについては、VPはjwt_vp_json、VCはjwt_vc_jsonに対応しています。また、dc+sd-jwtにも対応しています。
- `state` パラメータを `createAuthzRequest` に渡した場合、`verifyPresentations` 呼び出し時にライブラリ側でレスポンスの `state` と照合します。`state` を使用しないフロー（dc_api 等）では省略可能です

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
import { initializeVerifierFlow, VerifierMetadata, VerifierClientId, VerifierAuthorizationResponse } from '@trustknots/vcknots/verifier'

const app = new Hono();

// VcknotsContextを作成
const context = initializeContext({
  debug: process.env.NODE_ENV !== "production",
});

// VerifierFlowインスタンスを作成
const verifierFlow = initializeVerifierFlow(context);

```

## 3. Verifier機能のサンプル実装

はじめに:
- サーバ起動時にVerifierのメタデータを事前登録しています。（[initializeVerifierMetadata](#initializeVerifierMetadata)）



### 1. Authorizationリクエストの作成

Verifier が Wallet に提示を依頼するための認可リクエスト（openid4vp://authorize?...）を生成します。

#### 1-1. 基本的な認可リクエスト

このエンドポイントは OAuth 2.0 に準拠した認可リクエスト形式を使用します。

- **エンドポイント**: `POST /verify/request`
- **リクエストボディ (JSON)**
  - `credentialId` (string, 必須): 要求する VC の type を指定。例: `UniversityDegreeCredential`。未指定の場合はエラー。
- **レスポンス**
  - `200 OK`: テキストで `openid4vp://authorize?...` 形式の認可リクエスト URL を返却。
  - `400 Bad Request`: `credentialId` 未指定時など。

- **実際のコード**
```typescript
app.post('/verify/request', async (c) => {
  try {
    const verifierId = VerifierClientId(baseUrl)
    const { credentialId } = (await c.req.json()) ?? {};

    if (!credentialId) throw err("INVALID_REQUEST");
    const client_id = 'redirect_uri:http://localhost:8080'

    const query = {
      dcql_query: {
        credentials: [
          {
            id: 'sample-id',
            format: 'jwt_vc_json',
            meta: {
              type_values: [['UniversityDegreeCredential']],
            },
            claims: [
              {
                path: ['vc', 'credentialSubject', 'given_name'],
              },
            ],
          },
        ],
      },
    }

    const { request, transactionId } = await verifierFlow.createAuthzRequest(
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
    // transactionId は verifyPresentations 呼び出し時に必要。セッション等と紐づけて保管してください。

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


**例**

**リクエスト**

```bash
curl --location 'http://localhost:8080/verify/request' \
--header 'Content-Type: application/json' \
--data ' {
 "credentialId": "UniversityDegreeCredential"
}'
```
**レスポンス**

```
openid4vp://authorize?response_type=vp_token&client_id=redirect_uri%3Ahttp%3A%2F%2Flocalhost%3A8080&client_metadata=...&nonce=a9a3e60cbb8e46e0946facb635839b57&response_mode=direct_post&response_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&dcql_query=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22sample-id%22%2C%22require_cryptographic_holder_binding%22%3Atrue%2C%22multiple%22%3Afalse%2C%22format%22%3A%22jwt_vc_json%22%2C%22claims%22%3A%5B%7B%22path%22%3A%5B%22vc%22%2C%22credentialSubject%22%2C%22given_name%22%5D%7D%5D%2C%22meta%22%3A%7B%22type_values%22%3A%5B%5B%22UniversityDegreeCredential%22%5D%5D%7D%7D%5D%7D
```


#### 1-2. JAR（JWT Authorization Request）形式のリクエスト

このエンドポイントは JWT Authorization Request (JAR) を用いて Request Object を生成・保存し、Wallet が取得するための認可リクエスト URI を返します。

- **エンドポイント**: `POST /verify/request-object`
- **リクエストボディ (JSON)**
  - 以下のフィールドを含めます。
      - `query.dcql_query`
      - `state`
      - `response_uri`
      - `client_id`：`redirect_uri:<URL>` または `x509_san_dns:<ホスト名>` を指定
- **レスポンス**
  - `200 OK`: テキストで `openid4vp://authorize?...` 形式の認可リクエスト URL を返却（`request_uri` 情報を含みます）。
  - `400 Bad Request`: JSON が不正な場合など、リクエスト内容に問題があるとき。

- 実際のコード
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
        query,
      } = body
      const { request, transactionId } = await verifierFlow.createAuthzRequest(
        verifierId,
        'vp_token',
        clientId,
        'direct_post',
        query,
        true,
        {
          state: state,
          base_url: baseUrl,
          response_uri: responseUri,
        }
      )
      // transactionId は verifyPresentations 呼び出し時に必要。セッション等と紐づけて保管してください。
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

**例**

**リクエスト**

```bash
curl --location 'http://localhost:8080/verify/request-object' \
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

**レスポンス**
```
openid4vp://authorize?client_id=x509_san_dns%3Alocalhost&request_uri=http%3A%2F%2Flocalhost%3A8080%2Fverifiers%2Fhttp%253A%252F%252Flocalhost%253A8080%2Frequest.jwt%2F0aab8b5062b0410ba96f1afaf3925f93
```



### 2. リクエストオブジェクトの取得

JAR 生成時に保存された Request Object（JWT）を Wallet などのクライアントが取得するためのエンドポイントです。

- **エンドポイント**: `GET /verify/request.jwt/:request-object-Id`
- **パスパラメーター**
  - `request-object-Id`: `createAuthzRequest` のレスポンスに含まれる `request_uri`（末尾の ID）で指定します。
- **レスポンス**
  - `200 OK`: `Content-Type: application/oauth-authz-req+jwt` の JWT 本文を返却。
  - `400 Bad Request`: ID が不正な場合や内部エラーが発生した場合。

- 実際のコード
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

**例**

**リクエスト**

```bash
curl --location 'http://localhost:8080/verify/request.jwt/fca442d1b80a43c7bb3faeb13e9a3b73'
```
**レスポンス**
```
eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QiLCJ4NWMiOlsiXG5NSUlDSGpDQ0FjT2dBd0lCQWdJVVpYOUJTNUNET0pSVzJ0MUZLMVVETXQvUXdNRXdDZ1lJS29aSXpqMEVBd0l3XG5JVEVMTUFrR0ExVUVCaE1DUjBJeEVqQVFCZ05WQkFNTUNVOUpSRVlnVkdWemREQWVGdzB5TkRFeE1qVXdPRE0yXG5NRFJhRncwek5ERXhNak13T0RNMk1EUmFNQ0V4Q3pBSkJnTlZCQVlUQWtkQ01SSXdFQVlEVlFRRERBbFBTVVJHXG5JRlJsYzNRd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFUVC9kTHNkNTFMTEJyR1Y2UjIzbzZ2XG55bVJ4SFhlRkJvSTh5cTMxeTVrRlYyVlYwZ2k5eDVaekVGaXE4RE1pQUh1Y0xBQ0ZuZHhMdFpvckNoYTl6em5RXG5vNEhZTUlIVk1CMEdBMVVkRGdRV0JCUzVjYmRnQWVNQmk1d3hwYnB3SVNHaFNoQVdFVEFmQmdOVkhTTUVHREFXXG5nQlM1Y2JkZ0FlTUJpNXd4cGJwd0lTR2hTaEFXRVRBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUlHQkJnTlZIUkVFXG5lakI0Z2hCM2QzY3VhR1ZsYm1GdUxtMWxMblZyZ2gxa1pXMXZMbU5sY25ScFptbGpZWFJwYjI0dWIzQmxibWxrXG5MbTVsZElJSmJHOWpZV3hvYjNOMGdoWnNiMk5oYkdodmMzUXVaVzF2WW1sNExtTnZMblZyZ2lKa1pXMXZMbkJwXG5aQzFwYzNOMVpYSXVZblZ1WkdWelpISjFZMnRsY21WcExtUmxNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNQXG5ibkx4Q0krV1IxdmhPVytBOEt6bkFXdjFNSm8rWUViMU1JNDVOS1cvVlFJaEFMenNxb3g4VnVCUndOMmRsNUxrXG5wbnhQNG9IOXA2SDBBT1ptS1ArWTduWFNcbiJdfQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X3Nhbl9kbnM6bG9jYWxob3N0Iiwic3RhdGUiOiIwMzg0NzViMDEyNmI0Njg0YTIyNmJjODBlYWM5MzRiNiIsImNsaWVudF9tZXRhZGF0YSI6eyJjbGllbnRfbmFtZSI6IlNhbXBsZSBWZXJpZmllciBBcHAiLCJjbGllbnRfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJFQyIsIngiOiIwXzNTN0hlZFN5d2F4bGVrZHQ2T3I4cGtjUjEzaFFhQ1BNcXQ5Y3VaQlZjIiwieSI6IlpWWFNDTDNIbG5NUVdLcndNeUlBZTV3c0FJV2QzRXUxbWlzS0ZyM1BPZEEiLCJjcnYiOiJQLTI1NiJ9XX0sInZwX2Zvcm1hdHMiOnsiand0X3ZwIjp7ImFsZyI6WyJFUzI1NiJdfX0sImNsaWVudF9pZF9zY2hlbWUiOiJyZWRpcmVjdF91cmkiLCJhdXRob3JpemF0aW9uX3NpZ25lZF9yZXNwb25zZV9hbGciOiJFUzI1NiJ9LCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdmVyaWZpZXJzL2h0dHAlM0ElMkYlMkZsb2NhbGhvc3QlM0E4MDgwL2NhbGxiYWNrIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiYXVkIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92MiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiODkyMGVjMGUtZDc3YS00MmJlLTk4OWQtZTU1MTBjZmFhNjlkIiwibmFtZSI6IlRlc3QgTmFtZSIsInB1cnBvc2UiOiJUZXN0IFB1cnBvc2UiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiI4ZjJmZWM3ZC1hMmI5LTRhZTEtYTdmMi1mMGJmMTgyMWYzY2UiLCJmb3JtYXQiOnsiand0X3ZjX2pzb24iOnsicHJvb2ZfdHlwZSI6WyJFUzI1NiJdfX0sImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjLnR5cGUiXSwiZmlsdGVyIjp7InR5cGUiOiJhcnJheSIsImNvbnRhaW5zIjp7ImNvbnN0IjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwifX19XX19XX0sImlhdCI6MTc2MTkwMTAzOCwibm9uY2UiOiI0YTVhYTQ1ZjllMWQ0N2FmOTkzNWY5OWEyM2M5ZDNlNiJ9.Kc4FFI1cNXJCO5nI8Yy0jnlYtLFDL-Wr-AoWtq8sasI0grzP1Zco8Zw9Ug2zybtMnn_o6XLDnnRj8jb2g0Y0TQ
```



### 3. vp_token の受信と検証

Wallet から返送される `vp_token` を受け取り、Verifier 側で検証 (VP 検証) を行うエンドポイントです。

- **エンドポイント**: `POST /verify/callback`
- **リクエストボディ**
  - `Content-Type: application/x-www-form-urlencoded`
  - フォームフィールドに `vp_token`（JSON オブジェクト）と `state` を載せます（Wallet の `direct_post` 応答と同形式）。
  - `vp_token` は DCQL のクレデンシャルクエリ ID をキー、VP の配列を値とする JSON オブジェクトです。
  - 値は検証のうえ `VerifierAuthorizationResponse` にパースされます。
- **レスポンス**
  - `200 OK`: JSON 本文 `{ "redirect_uri": "<baseUrl>/verified" }`（サンプルサーバの挙動。アプリに合わせて変更してください）。
  - `400 Bad Request` / `500 Internal Server Error`: バリデーションまたは VP 検証失敗時に `handleError` 由来の OAuth 形式 JSON（`error`, `error_description`）。

- **関連エンドポイント**: `POST /verify/callback-kbjwt` — 認可リクエストが `x509_san_dns` かつ SD-JWT + Key Binding JWT を使うサンプル向け。`verifyPresentations` を `isKbJwt: true` で呼び出します。`client_id`（KB-JWT の `aud` 検証に使用）はライブラリがトランザクションから自動的に取得します。

- コード例
```typescript
verifyApp.post('/verify/callback', async (c) => {
  try {
    const parsed = parseFormPayload(await c.req.formData())
    if (!parsed.ok) {
      return c.json(parsed.error, 400)
    }

    const authorizationResponse = VerifierAuthorizationResponse(parsed.payload)

    // `lookupTransactionId` はサンプルです。
    // `authorizationResponse.state`に対応する transaction ID を取得する処理は
    // アプリケーション側で実装するプレースホルダーとして置き換えてください。
    const transactionId = await lookupTransactionId(authorizationResponse.state)

    const vpPayload = await verifierFlow.verifyPresentations(authorizationResponse, transactionId)

    return c.json({ redirect_uri: `${baseUrl}/verified` }, 200)
  } catch (err) {
    const errorResponse = handleError(err)
    const status = errorResponse.error === 'internal_server_error' ? 500 : 400
    return c.json(errorResponse, status)
  }
})
```

**例**

**リクエスト**

```bash
curl --location 'http://localhost:8080/verify/callback' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'vp_token={"sample-id":["eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."]}' \
--data-urlencode 'state=example-state'
```

> **注意**: `vp_token` は DCQL 形式の JSON オブジェクトです（クレデンシャルクエリ ID をキー、VP 文字列の配列を値）。

**レスポンス**（`200 OK`）

```json
{
  "redirect_uri": "http://localhost:8080/verified"
}
```


## 4. Verifierメタデータの登録 {#initializeVerifierMetadata}

- 本ガイドのコードは、起動時に本セクションの手順に従ってVerifierメタデータを登録します。実運用や各自の開発環境に合わせて、`BASE_URL`およびメタデータ／証明書ファイルを適宜調整してください。

メタデータファイル（外部JSON）:
- 場所: `vcknots/server/samples/verifier_metadata.json`
- 例（内容）:
```json
{
	"vp_formats": {
		"jwt_vc_json": {
			"alg_values_supported": ["ES256"]
		},
		"jwt_vp_json": {
			"alg_values_supported": ["ES256"]
		},
		"dc+sd-jwt": {
			"sd-jwt_alg_values": ["ES256", "ES384"],
			"kb-jwt_alg_values": ["ES256", "ES384"]
		}
	}
}
```

証明書ファイルの場所:
- 秘密鍵: `vcknots/server/samples/certificate-openid-test/private_key_openid.pem`
- 証明書: `vcknots/server/samples/certificate-openid-test/certificate_openid.pem`


```typescript
// BASE_URL を反映してメタデータを初期化
const baseUrl = process.env.BASE_URL ?? 'http://localhost:8080'

// サンプルの verifier メタデータ(JSON) を読み込んだものを利用（例: verifierMetadataConfig）
verifierMetadataConfig.client_uri = baseUrl
await initializeVerifierMetadata(baseUrl, verifierMetadataConfig)
```

```typescript
// 証明書/秘密鍵を読み込み、メタデータを登録
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


## 6. 型定義の説明

### VerifierClientId {#VerifierClientId}
Verifierの識別子を表す型です。ClientIdSchemeと識別子を組み合わせた形式で、Verifierの一意な識別に使用されます。

定義は [issuer+verifier/src/client-id.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/client-id.types.ts) を参照してください。


### VerifierMetadata {#VerifierMetadata}
Verifierのメタデータを定義する型です。クライアント名、URI、サポートするVP形式、リダイレクトURIなどの情報を含みます。

定義は [issuer+verifier/src/verifier-metadata.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier-metadata.types.ts) を参照してください。


### VerifierAuthorizationResponse {#Verifierauthorizationresponse}
VP Tokenやプレゼンテーション提出情報を含み、プレゼンテーションの検証に使用されます。

定義は [issuer+verifier/src/authorization-response.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/authorization-response.types.ts) を参照してください。


### VpTokenPayload {#VpTokenPayload}
`verifyPresentations` が返す検証済みペイロードを表す型です。
VP フォーマット（例: `jwt_vp_json` / `dc+sd-jwt`）に応じたユニオン型です。

定義は [issuer+verifier/src/presentation.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/presentation.types.ts) を参照してください。

## 7. VerifierFlowの各メソッド

### createVerifierMetadata
Verifierのメタデータを作成・保存します。

```typescript
createVerifierMetadata(
  verifierId: VerifierClientId,
  metadata: VerifierMetadata,
  options?: CreateVerifierMetadataOptions
): Promise<void>
```

**パラメータ**:
- `verifierId`: Verifierの識別子（[VerifierClientId](#VerifierClientId)）
- `metadata`: Verifierのメタデータ（[VerifierMetadata](#VerifierMetadata)）
- `options`: 証明書や秘密鍵などのオプション（[CreateVerifierMetadataOptions](#CreateVerifierMetadataOptions)）

**戻り値**:
- なし

**エラーケース**:
- `DUPLICATE_VERIFIER`: 既に同じ`verifierId`のメタデータが登録済み
- `INTERNAL_SERVER_ERROR`: `options.alg`が未指定（公開鍵/証明書を指定する場合は必須）
- `INVALID_CERTIFICATE`: 提供された証明書が無効

#### CreateVerifierMetadataOptions {#CreateVerifierMetadataOptions}

Verifierメタデータ作成時のオプションを定義する型です。証明書または公開鍵の設定が可能です。


詳細な型定義については、[verifier.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts)を参照してください。


### createAuthzRequest
認可リクエストを作成します。

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


**パラメータ**:
- `verifierId`: Verifierの識別子（[VerifierClientId](#VerifierClientId)）
- `response_type`: レスポンスタイプ（'vp_token'）
- `client_id`: クライアントID（[OpenID for Verifiable Presentations 5.2 Existing Parameters の client_id 参照](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.2)）
- `response_mode`: レスポンスモード('direct_post' | 'query' | 'fragment' | 'dc_api.jwt' | 'dc_api')
- `query`: DCQLクエリ（[6. Digital Credentials Query Language (DCQL)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l)）
- `isRequestUri`: リクエストURIを使用するかどうかのフラグ
  - `isRequestUri = true` → request_uri形式（Request Objectを外部に保存）
  - `isRequestUri = false` → 直接形式（認可リクエストに直接パラメータを含める）
- `options`: リクエスト作成オプション　（[CreateAuthzRequestOptions](#CreateAuthzRequestOptions)）

**戻り値**:
- `{ request: AuthorizationRequest, transactionId: string }` オブジェクトを返します。
  - `request`（[AuthorizationRequest](#AuthorizationRequest)）: 以下の形式のいずれかになります：

    - **request_uri形式** (`isRequestUri = true`の場合):
    ```typescript
    {
      client_id: string,
      request_uri: string
    }
    ```

    - **直接形式** (`isRequestUri = false`の場合):
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

  - `transactionId` (string): `verifyPresentations` 呼び出し時に必要なトランザクション ID。セッションや状態管理の仕組みと紐づけて保管してください。

**エラーケース**:
- `UNSUPPORTED_CLIENT_ID_PREFIX`: 未対応のclient_id_prefixが指定された
- `CERTIFICATE_NOT_FOUND`: x509_san_dns利用時に証明書未登録
- `INVALID_REQUEST`: isRequestUri = trueなのにoptions.base_urlが未指定
- `VERIFIER_VP_FORMATS_NOT_SUPPORTED`: クエリで指定した VP フォーマットが Verifier のメタデータで未対応



#### CreateAuthzRequestOptions {#CreateAuthzRequestOptions}
認証リクエスト作成時のオプションを定義する型です。

詳細な型定義については、[verifier.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts)を参照してください。


**注意事項**:
- `isRequestUri`が`true`の場合、`base_url`は必須です
- `response_uri`が指定されない場合、デフォルトで`${verifierId}/post`が使用されます
- `state`はセキュリティのため、ランダムで予測困難な値を使用することを推奨します

#### AuthorizationRequest（createAuthzRequest のレスポンス型） {#AuthorizationRequest}

`createAuthzRequest` が返すレスポンス型です。`request_uri` を用いる「Request URI 形式」か、パラメータを直接含める「直接形式」のいずれかで、DCQL のスキーマと結合されます。

詳細な型定義については、[authorization-request.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/authorization-request.types.ts)を参照してください。


### findRequestObject
createAuthzRequestでJAR形式のレスポンスの場合に、JAR形式のリクエストオブジェクトを取得します。

```typescript
findRequestObject(
  verifierId: ClientId,
  objectId: RequestObjectId,
  options?: FindRequestObjectOptions
): Promise<string>
```

**パラメータ**:
- `verifierId`: Verifierの識別子（[VerifierClientId](#VerifierClientId)）
- `objectId`: リクエストオブジェクトID([RequestObjectId](#RequestObjectId))
- `options`: 取得オプション　（[FindRequestObjectOptions](#FindRequestObjectOptions)）

**戻り値**:
- JWT形式のRequest Object文字列を返します。この文字列は以下の形式になります：
```
{base64url(header)}.{base64url(payload)}.{signature}
```
**エラーケース**:
- `VERIFIER_NOT_FOUND`: 指定したVerifierが存在しない
- `REQUEST_OBJECT_NOT_FOUND`: 指定したRequest Objectが存在しない
- `PROVIDER_NOT_FOUND`: Authorization Request JARのプロバイダが見つからない
- `AUTHZ_VERIFIER_KEY_NOT_FOUND`: 指定アルゴリズムの署名鍵プロバイダが見つからない
- `INTERNAL_SERVER_ERROR`: Request Objectの署名生成に失敗

**注意事項**:
- リクエストオブジェクトは取得は一度のみとなります。
- 同じRequest Object IDで複数回呼び出すとエラーになります。



#### RequestObjectId {#RequestObjectId}

Request Object（認可リクエストJAR）の一意識別子です。

詳細な型定義については、[request-object-id.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/request-object-id.types.ts)を参照してください。


#### FindRequestObjectOptions {#FindRequestObjectOptions}

リクエストオブジェクト取得時のオプションを定義する型です。

詳細な型定義については、[verifier.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts)を参照してください。



### verifyPresentations
VP Tokenを検証します。

```typescript
verifyPresentations(
  response: AuthorizationResponse,
  transactionId: string,
  options?: VerifyPresentationOptions
): Promise<Record<string, VpTokenPayload[]>>
```

**パラメータ**:

- `response`: 検証に利用する情報（[Verifierauthorizationresponse](#Verifierauthorizationresponse)）
- `transactionId`: `createAuthzRequest` が返した `transactionId`。認可リクエスト時の DCQL クエリを照合するために使用します。
- `options`: [VerifyPresentationOptions](#VerifyPresentationOptions)

#### VerifyPresentationOptions {#VerifyPresentationOptions}
Verifier アプリから VP／クレデンシャル形式ごとの検査に渡すオプションです。型定義は [`verifier.flows.ts`](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts) を参照してください。

> **注意**: `expectedAud`（`client_id`）は `createAuthzRequest` 時に渡した値がトランザクション内に保存されており、`verifyPresentations` 内でライブラリが自動的に取得して検証します。呼び出し側から個別に渡す必要はありません。

| フィールド | 必須 | 説明 |
| ---------- | ---- | ---- |
| `isKbJwt` | いいえ | `dc+sd-jwt` 用。`true` のとき Key Binding JWT を検証（`nonce`、`aud`、`sd_hash` など）。省略時は KB-JWT 検証なし。 |
| `expectedTransactionDataHashes` | いいえ | `transaction_data` 利用時。KB-JWT に含まれるハッシュ列の期待値。 |

**戻り値**:
- `Record<string, VpTokenPayload[]>` を返します。キーは DCQL のクレデンシャルクエリ ID、値は検証済み VP トークンペイロードの配列です。
- 各ペイロードはサポートする VP フォーマット（例: `jwt_vp_json` / `dc+sd-jwt`）に対応したユニオン型です。

  - 例（`jwt_vp_json` の場合のペイロード）:
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

  - 例（`dc+sd-jwt` の場合のペイロード）:
  ```typescript
  {
    iss?: string,
    vct: string
    // _sd、cnf、status などの SD-JWT ペイロードクレームを含む場合があります
  }
  ```

- **実装者側の扱い**: 本ライブラリは検証済みペイロードを**自動では保存・管理しません**。セッションやデータベースへの紐づけ、保管期間、監査ログの有無などは、**利用者（実装者）のアプリケーション**が、業務要件に従って設計・実装してください。

**エラーケース**:
- `VERIFIER_NOT_FOUND`: Verifierが存在しない
- `TRANSACTION_ID_NOT_FOUND`: 指定した `transactionId` に対応するトランザクションが存在しない（既に使用済みまたは無効）
- `ILLEGAL_ARGUMENT`: 引数不備（例: 未知のクレデンシャルクエリ ID、プロバイダがオプションを拒否）
- `UNSUPPORTED_VP_TOKEN`: `vp_token` の形式が未対応（非文字列形式など）
- `INVALID_REQUEST`: レスポンスの `state` がトランザクションに保存された `state` と一致しない
- `INVALID_VP_TOKEN`: DCQL の必須クレデンシャルが不足、または VP 構造が不正
- `INVALID_NONCE`: 認可リクエストの `nonce` が VP に無い、または一致しない
- `INVALID_CREDENTIAL`: 内包 VC が無効（`jwt_vp_json` 経路）、発行者メタデータ／JWKS 取得失敗など
- `INVALID_SD_JWT` / `HOLDER_BINDING_FAILED`: SD-JWT または Key Binding の検証失敗

**注意事項**:
- `client_id`（`expectedAud`）はトランザクションから自動的に取得されます。Wallet が VP／KB-JWT に設定する `aud` は、`createAuthzRequest` に渡した `client_id` と一致している必要があります。
- `state` を `createAuthzRequest` の `options.state` に渡した場合、ライブラリはコールバックの `response.state` が一致することを自動的に検証します。不一致の場合は `INVALID_REQUEST` エラーになります。
- `transactionId` は検証成功後に自動で削除されます。同じ `transactionId` で複数回呼び出すとエラーになります。



### findVerifierCertificate
Verifierの証明書を取得します。

```typescript
findVerifierCertificate(id: ClientId): Promise<Certificate | null>
```

**パラメータ**:
- `id`: Verifierの識別子（[VerifierClientId](#VerifierClientId)）

**戻り値**:
- 証明書オブジェクト（[Certificate](#Certificate)）、または存在しない場合は`null`


#### Certificate {#Certificate}

Verifierが保持する証明書チェーンを表す型です（PEM形式の文字列配列）。各要素はPEMフォーマット検証を通過したものに限られます。

詳細な型定義については、[signature-key.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/signature-key.types.ts)を参照してください。


注意:
- チェーン順は「リーフ → 中間 → ルート」を推奨
- 無効なPEMはエラーとなります


## 8. 注意事項

1. **証明書の管理**: Verifierのメタデータを設定する際は、適切な証明書と秘密鍵を提供する必要があります。
   - 証明書チェーンの順序は重要です（リーフ証明書 → 中間証明書 → ルート証明書）
   - 本番環境では有効な証明書を使用してください

2. **セキュリティ**: 本番環境では、適切な認証・認可の仕組みを実装してください。
   - 秘密鍵の管理には特に注意を払ってください
   - HTTPSを使用して通信を暗号化してください

3. **URLエンコード**: verifier IDにURLエンコードが必要な文字（例：`:`、`/`）が含まれる場合は、適切にエンコードしてください。

## 9. トラブルシューティング


- **Q：証明書の関連のエラー**:`INVALID_CERTIFICATE`
    - **A：** 証明書ファイルのパスが正しいか、ファイルが存在するかを確認してください。また、有効な証明書であることを確認してください。

- **Q:メタデータのバリデーションエラー**:
    - **A：** 提供されたメタデータがVerifierMetadataスキーマに適合しているかを確認してください。

- **Q:認可リクエストの作成エラー**:`invalid_request`
    - **A：**  必要なパラメータがすべて提供されているかを確認してください。

- **Q:リクエストオブジェクト取得エラー**:`REQUEST_OBJECT_NOT_FOUND`
    - **A：**  リクエストオブジェクトの取得は一度のみとなります。同じRequest Object IDで複数回呼び出すとエラーになります。

- **Q:vp_tokenのnonce検証エラー**: `INVALID_NONCE` - nonce is not valid で失敗する。
   -  **A：** 以下の原因と解決方法を確認してください。
   - **原因**: 
     - `vp_token`内のnonceが認可リクエスト時に生成されたものと一致しない
     - nonceが既に使用済み
     - nonceの有効期限が切れている
   - **解決方法**:
     - 認可リクエスト時に生成されたnonceと`vp_token`内のnonceが一致することを確認
     - 同じnonceで複数回の認証を試行していないか確認
     - nonceの生成と保存処理が正しく動作しているか確認
     - 時計の同期が取れているか確認（有効期限チェックのため）

