# Single Server

シングルテナント用のサーバー実装です。VCKnotsライブラリを使用して、Credential Issuer、Authorization Server、Verifier の機能を統合したサーバーを提供します。

## 概要

このサーバーは、OID4VCI（OpenID for Verifiable Credential Issuance）とOID4VP（OpenID for Verifiable Presentations）の仕様に基づいて実装されています。

## 実際のAPI仕様について

Credential Issuer・Authorization Server および Verifier の**実際のAPI仕様・パラメータ・型定義**は、以下の公式ドキュメントを参照してください。

- **Issuer（クレデンシャル発行・認可サーバー）**: [Issuer機能のセットアップと使用方法](https://trustknots.github.io/vcknots/ja/docs/issuer)
- **Verifier（証明提示検証）**: [Verifier機能のセットアップと使用方法](https://trustknots.github.io/vcknots/ja/docs/verifier)

本READMEのエンドポイント一覧は、このサンプルサーバーで利用しているパスの概要です。詳細なリクエスト/レスポンス形式やエラーコードは上記ドキュメントに従います。

## ディレクトリ構成

```
single/
├── src/
│   ├── app.ts          
│   ├── example.ts      
│   ├── routes/
│   │   ├── authz.ts    # Authorization Server のエンドポイント
│   │   ├── issue.ts    # Credential Issuer のエンドポイント
│   │   └── verify.ts   # Verifier のエンドポイント
│   └── utils/
│       └── error-handler.ts  # エラーハンドリングユーティリティ
├── .env.example        # 環境変数のサンプル設定
├── package.json        
└── tsconfig.json       
```

## エンドポイント

> 詳細なAPI仕様（パラメータ・型・エラー）は [Issuer](https://trustknots.github.io/vcknots/ja/docs/issuer) および [Verifier](https://trustknots.github.io/vcknots/ja/docs/verifier) の公式ドキュメントを参照してください。

### エンドポイント一覧

#### Credential Issuer
- [`POST /configurations/:configuration/offer`](#post-configurationsconfigurationoffer) - クレデンシャルオファーの作成
- [`POST /credentials`](#post-credentials) - クレデンシャルの発行
- [`GET /.well-known/openid-credential-issuer`](#get-well-knownopenid-credential-issuer) - Issuer メタデータの取得
- [`GET /.well-known/jwt-vc-issuer`](#get-well-knownjwt-vc-issuer) - JWT VC Issuer メタデータの取得

#### Authorization Server
- [`POST /token`](#post-token) - トークンエンドポイント
- [`GET /.well-known/oauth-authorization-server`](#get-well-knownoauth-authorization-server) - Authorization Server メタデータの取得

#### Verifier
- [`POST /request`](#post-request) - 認証リクエストの作成
- [`POST /request-object`](#post-request-object) - Request Object の作成
- [`POST /callback`](#post-callback) - 認証レスポンスのコールバック
- [`POST /callback-kbjwt`](#post-callback-kbjwt) - Key Binding JWT を使用したコールバック
- [`GET /verified`](#get-verified) - 検証結果の取得
- [`GET /request.jwt/:request-object-Id`](#get-requestjwtrequest-object-id) - Request Object JWT の取得
- [`GET /.well-known/openid-verifier-configuration`](#get-well-knownopenid-verifier-configuration) - Verifier メタデータの取得

---

### Credential Issuer

<a id="post-configurationsconfigurationoffer"></a>
#### `POST /configurations/:configuration/offer`

クレデンシャルオファーの作成

**パスパラメータ:**
- `configuration` (string) - クレデンシャル設定ID

**レスポンス:**
- `200 OK` - `openid-credential-offer://?credential_offer={encoded_offer}` 形式のテキスト

<a id="post-credentials"></a>
#### `POST /credentials`

クレデンシャルの発行

**リクエストヘッダー:**
- `Authorization: Bearer {access_token}` (必須) - アクセストークン

**リクエストボディ (JSON):**
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

**レスポンス:**
- `200 OK` - 発行されたクレデンシャル（JSON形式）
- `401 Unauthorized` - アクセストークンが無効または欠如

<a id="get-well-knownopenid-credential-issuer"></a>
#### `GET /.well-known/openid-credential-issuer`

Issuer メタデータの取得

**レスポンス:**
- `200 OK` - Credential Issuer メタデータ（JSON形式）
- `404 Not Found` - メタデータが見つからない場合

<a id="get-well-knownjwt-vc-issuer"></a>
#### `GET /.well-known/jwt-vc-issuer`

JWT VC Issuer メタデータの取得

**レスポンス:**
- `200 OK` - JWT VC Issuer メタデータ（JSON形式）
- `404 Not Found` - メタデータが見つからない場合

### Authorization Server

<a id="post-token"></a>
#### `POST /token`

トークンエンドポイント

**リクエスト (application/x-www-form-urlencoded):**

Pre-Authorized Code Grant:
```
grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
pre-authorized_code={pre_authorized_code}
tx_code={tx_code} (オプション)
```

Authorization Code Grant:
```
grant_type=authorization_code
code={authorization_code}
redirect_uri={redirect_uri} (オプション)
code_verifier={code_verifier} (オプション)
```

**レスポンス:**
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

Authorization Server メタデータの取得

**レスポンス:**
- `200 OK` - Authorization Server メタデータ（JSON形式）
- `404 Not Found` - メタデータが見つからない場合

### Verifier

<a id="post-request"></a>
#### `POST /request`

認証リクエストの作成。Presentation Definition を含む認証リクエストを生成し、`openid4vp://` スキームのURIを返します。

**リクエストボディ (JSON):**
```json
{
  "credentialId": string (必須),
  "client_id"?: string (オプション、デフォルト: "x509_san_dns:localhost")
}
```

**`client_id` の形式:**
- `redirect_uri:{uri}` - リダイレクトURIベースの識別子
- `x509_san_dns:{dns_name}` - X.509証明書のSAN DNS名ベースの識別子
- デフォルト: `"x509_san_dns:localhost"`

**レスポンス:**
- `200 OK` - `openid4vp://authorize?{encoded_params}` 形式のテキスト
- `400 Bad Request` - リクエストが無効な場合（例: `credentialId` 未指定）

<a id="post-request-object"></a>
#### `POST /request-object`

Request Object を JAR 形式で作成します。

**リクエストボディ (JSON、空でも可):**
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

**レスポンス:**
- `200 OK` - `openid4vp://authorize?{encoded_params}` 形式のテキスト
- `400 Bad Request` - リクエストが無効な場合

<a id="post-callback"></a>
#### `POST /callback`

認証レスポンスのコールバック。Wallet から送信された Verifiable Presentation を受け取り、検証します。

**リクエスト:** `application/json` または `application/x-www-form-urlencoded`

- `vp_token` (必須), `presentation_submission` (オプション), `state` (オプション)

**レスポンス:**
- `200 OK` - `{ "redirect_uri": "{baseUrl}/verified" }`
- `400 Bad Request` - リクエストが無効な場合または検証エラー

<a id="post-callback-kbjwt"></a>
#### `POST /callback-kbjwt`

Key Binding JWT を使用したコールバック。

**リクエスト (application/x-www-form-urlencoded):** `vp_token`, `presentation_submission`, `state`

**レスポンス:**
- `200 OK` - `{ "redirect_uri": "{baseUrl}/verified" }`
- `400 Bad Request` - リクエストが無効な場合または検証エラー

<a id="get-verified"></a>
#### `GET /verified`

検証完了後のリダイレクト先エンドポイント。

**レスポンス:** `200 OK` - `{ "message": "DONE!!" }`

<a id="get-requestjwtrequest-object-id"></a>
#### `GET /request.jwt/:request-object-Id`

Request Object JWT の取得。

**パスパラメータ:** `request-object-Id` (string)

**レスポンス:**
- `200 OK` - Request Object JWT（Content-Type: application/oauth-authz-req+jwt）
- `400 Bad Request` - Request Object が見つからない場合

<a id="get-well-knownopenid-verifier-configuration"></a>
#### `GET /.well-known/openid-verifier-configuration`

Verifier メタデータの取得。

**レスポンス:** `200 OK` - Verifier メタデータ（JSON形式）
