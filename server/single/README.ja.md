# Single Server

シングルテナント用のサーバー実装です。VCKnotsライブラリを使用して、Issuer、Authorization Server、Verifier の機能を統合したサーバーを提供します。
共有の app/routes/server/util 実装は、`@trustknots/server-core`を利用します。

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
├─ src/    
│  └─ example.ts       # In-memory provider 起動エントリー
├─ .env.example        # 環境変数のサンプル設定
├─ package.json        
└─ tsconfig.json       
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

   DPoP の mode（`off` / `optional` / `required`）は、`server/samples/oauth-server.json` の `authorization_server.default_client` / `authorization_server.anonymous_client` で設定します。

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


   # server-coreモジュールのビルド
   pnpm -F @trustknots/server-core build

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
POST  /nonce
        [handler]
GET   /nonce/:nonce
        [handler]
DELETE  /nonce/:nonce
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

## 補足
- `server/single`はworkspaceパッケージ`@trustknots/server-core`に依存します。
- workspaceパッケージや依存を変更した後は、`pnpm install`を再実行してリンクを更新してください。

## エンドポイント

> 詳細なAPI仕様（パラメータ・型・エラー）は [Issuer](https://trustknots.github.io/vcknots/ja/docs/issuer) および [Verifier](https://trustknots.github.io/vcknots/ja/docs/verifier) の公式ドキュメントを参照してください。

### エンドポイント一覧

#### Issuer
- [`POST /configurations/:configuration/offer`](#post-configurationsconfigurationoffer) - クレデンシャルオファーの作成
- [`POST /credentials`](#post-credentials) - クレデンシャルの発行
- [`GET /.well-known/openid-credential-issuer`](#get-well-knownopenid-credential-issuer) - Issuer メタデータの取得
- [`GET /.well-known/jwt-vc-issuer`](#get-well-knownjwt-vc-issuer) - JWT VC Issuer メタデータの取得
- [`POST /nonce`](#post-nonce) - nonce（c_nonce）の作成
- [`GET /nonce/:nonce`](#get-noncenonce) - nonceの有効性検証
- [`DELETE /nonce/:nonce`](#delete-noncenonce) - nonceの取り消し

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

**リクエストボディ (JSON):**
- オプション（任意）です。`tx_code` を利用する場合のみボディに指定してください。
- 空または未送信の場合、`tx_code` は作成されません。
```json
{
  "tx_code"?: {
    "input_mode"?: 'numeric' | 'text',
    "length"?: number,
    "description"?: string
  }
}
```

**レスポンス:**
- `200 OK` - `openid-credential-offer://?credential_offer={encoded_offer}` 形式のテキスト

<a id="post-credentials"></a>
#### `POST /credentials`

クレデンシャルの発行

**リクエストヘッダー（OAuth policy の DPoP mode とトークンの種類に依存）:**
- **Bearer:** `Authorization: Bearer {access_token}` — sender binding のないアクセストークン、DPoP mode が `required` でないときに利用。
- **DPoP:** `Authorization: DPoP {access_token}` に加え、`DPoP: {compact_jwt}`（RFC 9449 の DPoP Proof）が必要 — DPoP mode が `required` のとき、またはトークンに `cnf.jkt` が含まれるとき（`optional` であっても Bearer のみでは不可）。
- エラー応答では `WWW-Authenticate: Bearer` または `WWW-Authenticate: DPoP` が返ることがあります（詳細は [Issuer ドキュメント](https://trustknots.github.io/vcknots/ja/docs/issuer) の credential endpoint / DPoP の節）。

**リクエストボディ (JSON):**
```json
{
  "credential_identifier"?: string,
  "credential_configuration_id"?: string,
  "proofs"?: {
    "jwt"?: string[],
    "di_vp"?: {
      "holder"?: string,
      "proof": {
        "domain": string,
        "challenge": string
      }
    }[],
    "attestation"?: string[]
  },
  "credential_response_encryption"?: {
    "jwk": string,
    "alg": string,
    "zip"?: string
  }
}
```

**レスポンス:**
- `200 OK` - 発行されたクレデンシャル（JSON形式）
- `401 Unauthorized` - アクセストークン／DPoP の検証失敗、`invalid_token` / `invalid_dpop_proof` / `use_dpop_nonce`（本文および `WWW-Authenticate` で区別される場合があります）

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

<a id="post-nonce"></a>
#### `POST /nonce`

nonce（c_nonce）の作成。OID4VCI の [nonce endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint) に相当します。Wallet が credential リクエストを送る前に c_nonce を取得する際に使用します。複数の credential を取得する場合、同一の nonce を有効期限内で再利用できます。

**レスポンスヘッダー:**
- `Cache-Control: no-store` - キャッシュを無効化
- `DPoP-Nonce: <nonce>` - OAuth policy の DPoP mode が `off` 以外の場合に付与される DPoP 用 nonce

**レスポンス:**
- `200 OK` - `{ "c_nonce": string }`（nonce の有効期限は 2 分）
- `400 Bad Request` / `500 Internal Server Error` - エラー時

`c_nonce`（JSON ボディ）と `DPoP-Nonce`（レスポンスヘッダー）は別の値です。`c_nonce` は credential proof 用、`DPoP-Nonce` は token endpoint で提示する DPoP Proof 用です。用途が異なるため、TTL も別々に管理されます。

<a id="get-noncenonce"></a>
#### `GET /nonce/:nonce`

指定された nonce の有効性を検証します。デバッグや Wallet による事前確認に利用できます。

**パスパラメータ:**
- `nonce` (string) - 検証対象の nonce 値

**レスポンス:**
- `200 OK` - `{ "valid": boolean }`
- `400 Bad Request` / `500 Internal Server Error` - エラー時

<a id="delete-noncenonce"></a>
#### `DELETE /nonce/:nonce`

指定された nonce を取り消し（削除）します。

**パスパラメータ:**
- `nonce` (string) - 取り消し対象の nonce 値

**レスポンス:**
- `200 OK` - `{ "deleted": true }`
- `404 Not Found` - nonce が見つからない場合（`{ "error": "not_found", "error_description": "Nonce not found." }`）
- `400 Bad Request` / `500 Internal Server Error` - エラー時

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
  "scope"?: string
}
```

DPoP mode は `server/samples/oauth-server.json` の OAuth policy と、`server/samples/oauth-clients.json` の client ごとの sender constraint 設定で決まります。Pre-Authorized Code の token request で `client_id` / `client_assertion` が無い場合は anonymous token request として扱い、Authorization Server Metadata の `pre-authorized_grant_anonymous_access_supported` が `true` のときだけ `anonymous_client` の policy を適用します。`default_client` は registered client に sender constraint 設定がない場合、および credential / nonce endpoint の既定値として使われます。

| DPoP mode | token endpoint | credential endpoint |
|-------------|----------------|---------------------|
| `off` | DPoP を利用せず、Bearer access token を発行します。 | DPoP を利用しません。`Authorization: DPoP` または `DPoP` ヘッダーは拒否します。 |
| `optional` | `DPoP` ヘッダーがない場合は Bearer access token を発行します。`DPoP` ヘッダーがある場合は proof を検証し、DPoP-bound access token を発行します。 | sender binding のない token は `Authorization: Bearer` で利用できます。`cnf.jkt` 付き token は `Authorization: DPoP` と `DPoP` ヘッダーが必要です。 |
| `required` | `DPoP` ヘッダーが必須です。 | `Authorization: DPoP` と `DPoP` ヘッダーが必須です。Bearer のみは拒否されます。 |

nonce に関する DPoP エラーは `invalid_request` / `invalid_dpop_proof` ではなく、`use_dpop_nonce` と `DPoP-Nonce` ヘッダーで処理されます。nonce 以外の malformed proof や署名検証失敗などは、endpoint に応じて `invalid_request` または `invalid_dpop_proof` として返されます。

token endpoint で DPoP Proof に `nonce` がない、または nonce が無効な場合は、**HTTP 400** と **`DPoP-Nonce` ヘッダー**、JSON `use_dpop_nonce` を返します（token endpoint は現行実装では `WWW-Authenticate` は付けません）。

```http
HTTP/1.1 400 Bad Request
DPoP-Nonce: <nonce>
Content-Type: application/json
```

```json
{
  "error": "use_dpop_nonce",
  "error_description": "Authorization server requires nonce in DPoP proof."
}
```

credential endpoint で DPoP Proof に `nonce` がない、または nonce が無効な場合は、**HTTP 401** と **`DPoP-Nonce` ヘッダー**、`WWW-Authenticate: DPoP`、JSON `use_dpop_nonce` を返します。

```http
HTTP/1.1 401 Unauthorized
DPoP-Nonce: <nonce>
WWW-Authenticate: DPoP realm="http://localhost:8080", error="use_dpop_nonce", error_description="Credential issuer requires nonce in DPoP proof."
Content-Type: application/json
```

```json
{
  "error": "use_dpop_nonce",
  "error_description": "Credential issuer requires nonce in DPoP proof."
}
```

DPoP Proof の検証に成功した場合、`token_type` は `DPoP` になります。発行される access token には、DPoP Proof の JOSE ヘッダーに含まれる公開鍵の JWK Thumbprint が `cnf.jkt` として含まれます。

```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 86400
}
```

#### OAuth client と private_key_jwt

OAuth client は `server/samples/oauth-clients.json` で管理します。token request body に `client_id` がある場合はその値を優先し、ない場合は `client_assertion` JWT の `iss` / `sub` から client_id を導出します。どちらからも client_id を得られない場合は anonymous token request として扱います。

Pre-Authorized Code の anonymous token request は、Authorization Server Metadata の `pre-authorized_grant_anonymous_access_supported` が `true` のときだけ許可されます。未設定または `false` の場合は `invalid_client` を返します。許可された anonymous token request には、`authorization_server.anonymous_client` の policy を適用します。

登録済み client の `token_endpoint_auth_method` が `private_key_jwt` の場合、token request には次のフォーム項目が必要です。

```text
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<compact JWT>
```

`private_key_jwt` の検証では、`iss` / `sub` が登録済み `client_id` と一致すること、`aud` が登録済み `client_assertion_audience` または Authorization Server の token endpoint / issuer と一致すること、`exp` / `iat` / `jti` が含まれること、`alg` が許可された非対称署名アルゴリズムであること、登録済み `jwks.keys` の公開鍵で署名検証できることを確認します。同じ `jti` の client assertion は再利用できません。

client ごとの DPoP mode は、client 定義の `senderConstrainedAccessToken` で上書きできます。client 側に指定がない場合は `authorization_server.default_client` の policy を使います。認証済み client の `client_id` は、発行される access token payload に `client_id` として含まれます。

#### OAuth policy / OAuth client 設定ファイル

OAuth policy は `server/samples/oauth-server.json`、登録済み OAuth client は `server/samples/oauth-clients.json` で管理します。シングルサーバー起動時にこれらの JSON を読み込み、in-memory provider に登録します。
`oauth-server.json` の内容は Authorization Server 全体の OAuth policy として provider に登録されます。
`oauth-clients.json` の内容は登録済み OAuth client として provider に登録されます。

##### `server/samples/oauth-server.json`

`oauth-server.json` は Authorization Server 全体の既定 policy を定義します。

| 項目 | 説明 |
|---|---|
| `authorization_server` | Authorization Server ごとの OAuth policy ルートです。 |
| `authorization_server.default_client` | 登録済み client に `senderConstrainedAccessToken` がない場合に使う既定 policy です。credential / nonce endpoint の既定 DPoP policy としても使います。 |
| `authorization_server.anonymous_client` | 許可された anonymous token request に使う anonymous client 用 policy です。Pre-Authorized Code の anonymous token request を許可するかどうかは、Authorization Server Metadata の `pre-authorized_grant_anonymous_access_supported` で判定します。 |
| `senderConstrainedAccessToken` | access token の sender constraint 方針です。 |
| `senderConstrainedAccessToken.method` | sender constraint 方式です。`none` / `dpop` / `mtls` を指定できます。現行の DPoP 処理では `dpop` の場合に `dpop.mode` を参照します。`mtls` は予約値で、現時点では DPoP mode 制御には使いません。 |
| `senderConstrainedAccessToken.dpop.mode` | DPoP mode です。`off` / `optional` / `required` を指定します。現行実装では token endpoint と credential endpoint に同じ値が適用されます。 |
| `comment` | サンプル説明用のコメントです。制御ロジックには使いません。 |

policy の適用順は次の通りです。

1. Pre-Authorized Code の token request に `client_id` も `client_assertion` もない場合は、Authorization Server Metadata の `pre-authorized_grant_anonymous_access_supported` が `true` のときだけ `authorization_server.anonymous_client` を使います。未設定または `false` の場合は `invalid_client` です。
2. 登録済み client に `senderConstrainedAccessToken` がある場合は、client 固有の policy を使います。
3. 登録済み client に `senderConstrainedAccessToken` がない場合は、`authorization_server.default_client` を使います。

##### `server/samples/oauth-clients.json`

`oauth-clients.json` は token endpoint で参照する登録済み OAuth client を定義します。

| 項目 | 説明 |
|---|---|
| `clients[]` | 登録済み OAuth client の一覧です。 |
| `client_id` | client identifier です。token request body の `client_id`、または `client_assertion` JWT の `iss` / `sub` と照合します。 |
| `client_name` | 表示・説明用の名称です。 |
| `token_endpoint_auth_method` | token endpoint の client authentication 方式です。未指定時は `none` として扱います。現行実装では `private_key_jwt` と `none` を扱い、それ以外の方式は `invalid_client` として未実装エラーになります。 |
| `token_endpoint_auth_signing_alg` | `private_key_jwt` の JOSE header `alg` と照合する client 固有の署名アルゴリズムです。 |
| `client_assertion_audience` | `client_assertion` JWT の `aud` と照合する値です。未指定時は Authorization Server metadata の `token_endpoint` と issuer を期待値として使います。 |
| `jwks.keys` | `private_key_jwt` の署名検証に使う登録済み公開鍵です。秘密鍵はここに置きません。 |
| `jwks_uri` | client の JWKS URI です。現行の `private_key_jwt` 検証ではリモート取得せず、`jwks.keys` を使います。鍵ローテーション向けの登録情報として扱います。 |
| `allowed_grant_types` | client が利用できる grant type の登録情報です。現行実装では token endpoint の grant type 制御としては enforcement していません。 |
| `senderConstrainedAccessToken` | client 固有の sender constraint policy です。指定した場合は `authorization_server.default_client` より優先します。 |
| `senderConstrainedAccessToken.method` | client 固有の sender constraint 方式です。`none` / `dpop` / `mtls` を指定できます。 |
| `senderConstrainedAccessToken.dpop.mode` | client 固有の DPoP mode です。`off` / `optional` / `required` を指定します。現行実装では token endpoint と credential endpoint に同じ値が適用されます。 |
| `enabled` | `false` の場合、provider から取得されず無効 client として扱われます。未指定または `true` の場合は有効です。 |
| `comment` | サンプル説明用のコメントです。制御ロジックには使いません。 |

`private_key_jwt` client の最小構成例です。

```json
{
  "client_id": "https://wallet.example.com",
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "ES256",
  "client_assertion_audience": "https://authz.example.com",
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "kid": "wallet-es256-2026-01",
        "alg": "ES256",
        "x": "...",
        "y": "..."
      }
    ]
  },
  "senderConstrainedAccessToken": {
    "method": "dpop",
    "dpop": {
      "mode": "required"
    }
  },
  "enabled": true
}
```

<a id="get-well-knownoauth-authorization-server"></a>
#### `GET /.well-known/oauth-authorization-server`

Authorization Server メタデータの取得

**レスポンス:**
- `200 OK` - Authorization Server メタデータ（JSON形式）
- `404 Not Found` - メタデータが見つからない場合

以下は項目の一例です。シングルサーバーでは初期化時に **`BASE_URL`（例: `http://localhost:8080`）** に合わせて `issuer` / `authorization_endpoint` / `token_endpoint` が設定されます（必ずしも下記ホストとは一致しません）。
```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/authorize",
  "token_endpoint": "http://localhost:8080/token",
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
