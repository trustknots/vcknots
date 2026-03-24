# Google Cloud Server

Google Cloud / Firebase 連携付きのシングルテナントサーバー実装です。VCKnots ライブラリを利用して Issuer、Authorization Server、Verifier の機能を統合したサーバーを提供します。

共有の `app/routes/server/utils` 実装は `@trustknots/server-core` を利用します。

## 概要

このサーバーは OID4VCI（OpenID for Verifiable Credential Issuance）および OID4VP（OpenID for Verifiable Presentations）をベースに実装されています。

バックエンドの保存先として、Firebase Admin SDK と `@trustknots/google-cloud` による Firestore Provider 連携を利用します。

## 実際の API 仕様について

Issuer / Authorization Server / Verifier の実際の API 仕様（パラメータ、型定義、利用例）は、以下の公式ドキュメントを参照してください。

- **Issuer**: [Issuer 設定・利用ガイド](https://trustknots.github.io/vcknots/ja/docs/issuer)
- **Verifier**: [Verifier 設定・利用ガイド](https://trustknots.github.io/vcknots/ja/docs/verifier)

この README のエンドポイント一覧は、サンプルサーバーで使用しているパスの概要です。詳細なリクエスト/レスポンス形式やエラーコードは上記ドキュメントに従います。

## ディレクトリ構成

```text
google-cloud/
├─ src/        
│  └─ example.ts          # Google Cloud / Firebase 起動エントリ
├─ .env.example           # 環境変数設定のサンプル
├─ package.json
└─ tsconfig.json
```

共有実装は `server/core` にあります。

## コンパイルとサーバー起動

このサーバーを起動するには、以下の手順に従ってください。

### 前提条件

- Node.js がインストールされていること
- pnpm がインストールされていること
- VCKnots リポジトリルートで依存関係がインストール済みであること
- Google Cloud / Firebase の認証情報が利用可能であること

### 手順

1. **環境変数を設定**

   ```bash
   # server/google-cloud ディレクトリへ移動
   cd server/google-cloud

   # .env.example をコピーして .env を作成
   cp .env.example .env
   ```

   `src/example.ts` で必須の環境変数:

   - `GOOGLE_PROJECT_ID`
   - `GOOGLE_PROJECT_LOCATION`
   - `FIREBASE_PRIVATE_KEY`
   - `FIREBASE_CLIENT_EMAIL`

   任意の環境変数:

   - `FIRESTORE_DATABASE_ID`
   - `BASE_URL`（例: `http://localhost:8080`）
   - `PORT`（既定値: `8080`）
   - `PRIVATE_KEY_PATH`
   - `CERTIFICATE_PATH`

2. **依存関係をインストール（ルートで実行）**

   ```bash
   # vcknots ルートディレクトリへ移動
   cd /path/to/vcknots

   # 依存関係をインストール（未実行の場合）
   pnpm install
   ```

3. **モジュールをビルド**

   ```bash
   # issuer+verifier モジュールをビルド
   pnpm -F @trustknots/vcknots build

   # 共有 server-core モジュールをビルド
   pnpm -F @trustknots/server-core build

   # Google Cloud モジュールをビルド
   pnpm -F @trustknots/google-cloud build

   # Google Cloud サーバーモジュールをビルド
   pnpm -F @trustknots/server-google-cloud build
   ```

4. **サーバーを起動（Google Cloud 版）**

   ```bash
   # Google Cloud / Firebase バックエンド版を起動
   pnpm -F @trustknots/server-google-cloud start
   ```

### サーバー起動確認

サーバーが正常に起動すると、以下のような出力が表示されます。

```text
> @trustknots/server-google-cloud@0.1.0 start /path/to/vcknots/server/google-cloud
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

既定では `http://localhost:8080` で起動します。

## 補足

- `server/google-cloud` は workspace パッケージ `@trustknots/server-core` に依存します。
- workspace パッケージや依存関係を変更した後は、リポジトリルートで `pnpm install` を再実行してリンクを更新してください。

## エンドポイント

> API の詳細仕様（パラメータ、型、エラー）は [Issuer](https://trustknots.github.io/vcknots/ja/docs/issuer) および [Verifier](https://trustknots.github.io/vcknots/ja/docs/verifier) の公式ドキュメントを参照してください。

### エンドポイント一覧

#### Issuer

- [`POST /configurations/:configuration/offer`](../single/README.md#post-configurationsconfigurationoffer) - クレデンシャルオファーを作成
- [`POST /credentials`](../single/README.md#post-credentials) - クレデンシャルを発行
- [`GET /.well-known/openid-credential-issuer`](../single/README.md#get-well-knownopenid-credential-issuer) - Issuer メタデータを取得
- [`GET /.well-known/jwt-vc-issuer`](../single/README.md#get-well-knownjwt-vc-issuer) - JWT VC Issuer メタデータを取得

#### Authorization Server

- [`POST /token`](../single/README.md#post-token) - トークンエンドポイント
- [`GET /.well-known/oauth-authorization-server`](../single/README.md#get-well-knownoauth-authorization-server) - Authorization Server メタデータを取得

#### Verifier

- [`POST /request`](../single/README.md#post-request) - 認可リクエストを作成
- [`POST /request-object`](../single/README.md#post-request-object) - 認可リクエストを作成（参照形式）
- [`GET /request.jwt/:request-object-Id`](../single/README.md#get-requestjwtrequest-object-id) - Request Object JWT を取得
- [`POST /callback`](../single/README.md#post-callback) - VP 検証エンドポイント
- [`POST /callback-kbjwt`](../single/README.md#post-callback-kbjwt) - Key Binding JWT を使う VP 検証エンドポイント（dc+sd-jwt）
- [`GET /verified`](../single/README.md#get-verified) - VP 検証完了後のリダイレクト先
