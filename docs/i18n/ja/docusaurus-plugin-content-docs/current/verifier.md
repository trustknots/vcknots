---
sidebar_position: 3
---


# Verifier機能のセットアップと使用方法

このガイドでは、VCKnotsのVerifier機能のセットアップと使用方法について説明します。

## 1. 前提条件

- OpenID for Verifiable Presentations - draft 24 に対応（[OpenID for Verifiable Presentations - draft 24](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html)）
- クロスデバイスフローを前提としています
- Node.js v14以降がインストールされていること
- TypeScriptが設定されていること
- 本ドキュメントはserverのサンプル実装に基づいて説明します
- HonoのWebフレームワークを使用していますが、他のフレームワークでも利用可能です
- 現在対応しているclient_id_schema:x509_san_dns、redirect_uriになります
- 現在対応しているフォーマットについてVPはjwt_vp_json、VCはjwt_vc_jsonになります
- stateパラメータについては、実装者の責任での実装となります

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
openid4vp://authorize?response_type=vp_token&client_id=x509_san_dns%3Alocalhost&client_metadata=%7B%22client_name%22%3A%22Sample%20Verifier%20App%22%2C%22client_uri%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22jwks%22%3A%7B%22keys%22%3A%5B%7B%22kty%22%3A%22EC%22%2C%22x%22%3A%220_3S7HedSywaxlekdt6Or8pkcR13hQaCPMqt9cuZBVc%22%2C%22y%22%3A%22ZVXSCL3HlnMQWKrwMyIAe5wsAIWd3Eu1misKFr3POdA%22%2C%22crv%22%3A%22P-256%22%7D%5D%7D%2C%22vp_formats%22%3A%7B%22jwt_vp_json%22%3A%7B%22alg%22%3A%5B%22ES256%22%5D%7D%7D%2C%22client_id_scheme%22%3A%22redirect_uri%22%2C%22authorization_signed_response_alg%22%3A%22ES256%22%7D&nonce=5cf220cd62d3453192b1af4f6ba88b87&response_mode=direct_post&response_uri=http%3A%2F%2Flocalhost%3A8080%2Fverifiers%2Fhttp%253A%252F%252Flocalhost%253A8080%2Fcallback&client_id_scheme=x509_san_dns&presentation_definition=%7B%22id%22%3A%2243bff439-6929-4843-931f-5b7530ed8010%22%2C%22name%22%3A%22Test%20Name%22%2C%22purpose%22%3A%22Test%20Purpose%22%2C%22input_descriptors%22%3A%5B%7B%22id%22%3A%22UniversityDegreeCredential%22%2C%22format%22%3A%7B%22jwt_vc_json%22%3A%7B%22proof_type%22%3A%5B%22ES256%22%5D%7D%7D%2C%22constraints%22%3A%7B%22fields%22%3A%5B%7B%22path%22%3A%5B%22%24.vc.type%22%5D%2C%22filter%22%3A%7B%22type%22%3A%22array%22%2C%22contains%22%3A%7B%22const%22%3A%22VerifiableCredential%22%7D%7D%7D%5D%7D%7D%5D%7D
```


#### 1-2. JAR（JWT Authorization Request）形式のリクエスト

このエンドポイントは JWT Authorization Request (JAR) を用いて Request Object を生成・保存し、Wallet が取得するための認可リクエスト URI を返します。

- **エンドポイント**: `POST /verify/request-object`
- **リクエストボディ (JSON)**
  - 以下のフィールドを含めます。
      - `query.presentation_definition`
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

**例**

**リクエスト**

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
            "jwt_vc_json":{
                "alg":["RS256"]
            }
        },
        "constraints": {
          "fields": [
            {
              "path": ["$.type"],
              "filter": {
                "type": "array",
                "contains":{
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
- **リクエストボディ (JSON)**
  - `vp_token`, `presentation_submission` など OpenID4VP の Authorization Response フィールドを含む JSON。
  - `VerifierAuthorizationResponse` スキーマでバリデーションが行われます。
- **レスポンス**
  - `200 OK`: `message` と検証済み `authorization_response` を JSON で返却。
  - `400 Bad Request`: バリデーション失敗や検証エラーが発生した場合。

- 実際のコード
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

**例**

**リクエスト**

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
				"format": "jwt_vp_json",
				"path": "$",
				"path_nested": {
					"id": "BptkWumGAD21zS6uRm2a",
					"format": "jwt_vc_json",
					"path": "$.verifiableCredential[0]"
				}
			}
		]
	},
	"state": "tEoHpMJo1896FnkXJxVu"
}'
```

**レスポンス**

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
                    "format": "jwt_vp_json",
                    "path": "$",
                    "path_nested": {
                        "id": "BptkWumGAD21zS6uRm2a",
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
                }
            ]
        },
        "state": "tEoHpMJo1896FnkXJxVu"
    }
}
```


## 4. Verifierメタデータの登録{#initializeVerifierMetadata}

- 本ガイドのコードは、起動時に本セクションの手順に従ってVerifierメタデータを登録します。実運用や各自の開発環境に合わせて、`BASE_URL`およびメタデータ／証明書ファイルを適宜調整してください。

メタデータファイル（外部JSON）:
- 場所: `vcknots/server/samples/verifier_metadata.json`
- 例（内容）:
```json
{
  "client_name": "My Verifier App",
  "client_uri": "http://localhost:8080",
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
  },
  "client_id_scheme": "redirect_uri"
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

#### CreateVerifierMetadataOptions{#CreateVerifierMetadataOptions}
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
  query: DeepPartialUnknown<PresentationExchange> | DeepPartialUnknown<Dcql>,
  isRequestUri: boolean,
  options: CreateAuthzRequestOptions
): Promise<AuthorizationRequest>
```


**パラメータ**:
- `verifierId`: Verifierの識別子（[VerifierClientId](#VerifierClientId)）
- `response_type`: レスポンスタイプ（'vp_token'）
- `client_id`: クライアントID（[OpenID for Verifiable Presentations 5.2 Existing Parameters の client_id 参照](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.2)）
- `response_mode`: レスポンスモード('direct_post' | 'query' | 'fragment' | 'dc_api.jwt' | 'dc_api')
- `query`: presentaion_definition（[ 5.4. presentation_definition Parameter ](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.4)） または DCQLクエリ （[  6. Digital Credentials Query Language (DCQL)  ](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-digital-credentials-query-l)）
- `isRequestUri`: リクエストURIを使用するかどうかのフラグ
  - `isRequestUri = true` → request_uri形式（Request Objectを外部に保存）
  - `isRequestUri = false` → 直接形式（認可リクエストに直接パラメータを含める）
- `options`: リクエスト作成オプション　（[CreateAuthzRequestOptions](#CreateAuthzRequestOptions)）

**戻り値**:
- `AuthorizationRequest`オブジェクトを返します。（[AuthorizationRequest](#AuthorizationRequest)）このオブジェクトは以下の形式のいずれかになります：

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
    client_id_scheme: string,
    client_metadata: VerifierMetadata,
    nonce: string,
    // presentaion_defition または dcql_query
  }
  ```

**エラーケース**:
- `UNSUPPORTED_CLIENT_ID_SCHEME`: 未対応のclient_id_schemeが指定された
- `CERTIFICATE_NOT_FOUND`: x509_san_dnsまたはx509_san_uri利用時に証明書未登録
- `INVALID_REQUEST`: isRequestUri = trueなのにoptions.base_urlが未指定



#### CreateAuthzRequestOptions {#CreateAuthzRequestOptions}
認証リクエスト作成時のオプションを定義する型です。

詳細な型定義については、[verifier.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts)を参照してください。


**注意事項**:
- `isRequestUri`が`true`の場合、`base_url`は必須です
- `response_uri`が指定されない場合、デフォルトで`${verifierId}/post`が使用されます
- `state`はセキュリティのため、ランダムで予測困難な値を使用することを推奨します

#### AuthorizationRequest（createAuthzRequest のレスポンス型）{#AuthorizationRequest}

`createAuthzRequest` が返すレスポンス型です。`request_uri` を用いる「Request URI 形式」か、パラメータを直接含める「直接形式」のいずれかで、PE（Presentation Exchange）または DCQL のスキーマと結合されます。

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



#### RequestObjectId{#RequestObjectId}
Request Object（認可リクエストJAR）の一意識別子です。

詳細な型定義については、[request-object-id.types.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/request-object-id.types.ts)を参照してください。


#### FindRequestObjectOptions{#FindRequestObjectOptions}
リクエストオブジェクト取得時のオプションを定義する型です。

詳細な型定義については、[verifier.flows.ts](https://github.com/trustknots/vcknots/blob/main/issuer%2Bverifier/src/verifier.flows.ts)を参照してください。



### verifyPresentations
VP Tokenを検証します。

```typescript
verifyPresentations(
  id: ClientId,
  response: AuthorizationResponse
): Promise<void>
```

**パラメータ**:
- `id`: Verifierの識別子（[VerifierClientId](#VerifierClientId)）
- `response`: 検証に利用する情報（[Verifierauthorizationresponse](#Verifierauthorizationresponse)）

**戻り値**:
- なし  


**エラーケース**:
- `VERIFIER_NOT_FOUND`: Verifierが存在しない
- `UNSUPPORTED_VP_TOKEN`: サポートされていないVP Token形式
- `INVALID_NONCE`: 認可リクエスト時に発行されたnonceが`vp_token`に含まれていない、または一致しない場合に発生します。WalletはAuthorizationリクエストで提供されたnonceを`vp_token`に必ず含めて返す必要があります。
- `INVALID_CREDENTIAL`: 無効なクレデンシャル
- `INVALID_PRESENTATION_SUBMISSION`: 無効なpresentation_submission
- `HOLDER_BINDING_FAILED`: Holder binding検証失敗




### findVerifierCertificate
Verifierの証明書を取得します。

```typescript
findVerifierCertificate(id: ClientId): Promise<Certificate | null>
```

**パラメータ**:
- `id`: Verifierの識別子（[VerifierClientId](#VerifierClientId)）

**戻り値**:
- 証明書オブジェクト（[Certificate](#Certificate)）、または存在しない場合は`null`


#### Certificate{#Certificate}
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

