# Single Server

シングルテナント用のサーバー実装です。VCKnotsライブラリを使用して、Issuer、Authorization Server、Verifier の機能を統合したサーバーを提供します。

## 概要

このサーバーは、OID4VCI（OpenID for Verifiable Credential Issuance）とOID4VP（OpenID for Verifiable Presentations）の仕様に基づいて実装されています。

## 実際のAPI仕様について

Issuer・Authorization Server および Verifier の**実際のAPI仕様・パラメータ・型定義・実行例**は、以下の公式ドキュメントを参照してください。

- **Issuer**: [Issuer機能のセットアップと使用方法](https://trustknots.github.io/vcknots/ja/docs/issuer)
- **Verifier**: [Verifier機能のセットアップと使用方法](https://trustknots.github.io/vcknots/ja/docs/verifier)

本READMEのエンドポイント一覧は、このサンプルサーバーで利用しているパスの概要です。詳細なリクエスト/レスポンス形式やエラーコードは上記ドキュメントに従います。

## ディレクトリ構成

```
single/
├── src/
│   ├── app.ts          
│   ├── example.ts      
│   ├── routes/
│   │   ├── authz.ts    # Authorization Server のエンドポイント
│   │   ├── issue.ts    # Issuer のエンドポイント
│   │   └── verify.ts   # Verifier のエンドポイント
│   └── utils/
│       └── error-handler.ts  # エラーハンドリングユーティリティ
├── .env.example        # 環境変数のサンプル設定
├── package.json        
└── tsconfig.json       
```

## コンパイルとサーバーの起動

このサーバーを起動するには、以下の手順を実行してください。

### 前提条件

- Node.js がインストールされていること
- pnpm がインストールされていること
- VCKnots のルートディレクトリで依存関係がインストール済みであること

### 手順

1. **環境変数の設定**

   ```bash
   # server/single ディレクトリに移動
   cd server/single
   
   # .env.example をコピーして .env を作成
   cp .env.example .env
   
   # .env ファイルを編集して適切な値を設定
   # BASE_URL: サーバーのベースURL（例: http://localhost:8080）
   # PORT: サーバーのポート番号（デフォルト: 8080）
   # PRIVATE_KEY_PATH: 秘密鍵ファイルのパス（デフォルト: ../samples/certificate-openid-test/private_key_openid.pem）
   # CERTIFICATE_PATH: 証明書ファイルのパス（デフォルト: ../samples/certificate-openid-test/certificate_openid.pem）
   ```

2. **依存関係のインストール**（ルートディレクトリで実行）

   ```bash
   # vcknotsルートディレクトリへ移動
   cd /path/to/vcknots
   
   # 依存関係をインストール（未実施の場合）
   pnpm install
   ```

3. **モジュールのビルド**

   ```bash
   # issuer+verifierモジュールのビルド
   pnpm -F @trustknots/vcknots build
   
   # サーバーモジュールのビルド
   pnpm -F @trustknots/server build
   ```

4. **サーバーの起動**

   ```bash
   # サーバーを起動
   pnpm -F @trustknots/server start
   ```

### サーバー起動確認

サーバーが正常に起動すると、以下のようなメッセージが表示されます：

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

サーバーはデフォルトで `http://localhost:8080` で起動します。

## エンドポイント

> 詳細なAPI仕様（パラメータ・型・エラー）は [Issuer](https://trustknots.github.io/vcknots/ja/docs/issuer) および [Verifier](https://trustknots.github.io/vcknots/ja/docs/verifier) の公式ドキュメントを参照してください。

### エンドポイント一覧

#### Issuer
- [`POST /configurations/:configuration/offer`](#post-configurationsconfigurationoffer) - クレデンシャルオファーの作成
- [`POST /credentials`](#post-credentials) - クレデンシャルの発行
- [`GET /.well-known/openid-credential-issuer`](#get-well-knownopenid-credential-issuer) - Issuer メタデータの取得
- [`GET /.well-known/jwt-vc-issuer`](#get-well-knownjwt-vc-issuer) - JWT VC Issuer メタデータの取得

#### Authorization Server
- [`POST /token`](#post-token) - トークンエンドポイント
- [`GET /.well-known/oauth-authorization-server`](#get-well-knownoauth-authorization-server) - Authorization Server メタデータの取得

#### Verifier
- [`POST /request`](#post-request) - 認可リクエストの作成
- [`POST /request-object`](#post-request-object) - 認可リクエストの作成（参照渡し方式）
- [`GET /request.jwt/:request-object-Id`](#get-requestjwtrequest-object-id) - Request Object JWT の取得
- [`POST /callback`](#post-callback) - VP検証エンドポイント
- [`POST /callback-kbjwt`](#post-callback-kbjwt) - dc+sd-jwt 形式のKey Binding JWT を使用したVP検証エンドポイント
- [`GET /verified`](#get-verified) - VP検証完了後のリダイレクト先エンドポイント

---

### Issuer

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
- `200 OK` - Issuer メタデータ（JSON形式）
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
```json
{
  "issuer": "https://authz.example.com",
  "authorization_endpoint": "https://authz.example.com/authorize",
  "token_endpoint": "https://authz.example.com/token",
  "scopes_supported": ["openid"],
  "response_types_supported": ["code"],
  "pre-authorized_grant_anonymous_access_supported": true
}
```

### Verifier

<a id="post-request"></a>
#### `POST /request`

認証リクエストの作成。Presentation Definition を含む認可リクエストを生成し、`openid4vp://` スキームのURIを返します。

**リクエストボディ (JSON):**
```json
{
  "credentialId": string (必須, 例: "UniversityDegreeCredential"),
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

