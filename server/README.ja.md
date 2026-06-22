# Server

このディレクトリには、VCKnotsライブラリを使用したサーバー実装のサンプルが含まれています。

## ディレクトリ構成

### `core/`

`single/` と `google-cloud/` で共有するサーバーの共通実装です。

- 共通 Hono アプリ作成 (`createApp`)
- 共通サーバーブートストラップ (`createServer`)
- 共通ルート (`authz`, `issue`, `verify`)
- 共通ユーティリティ (e.g. error handling)

### `single/`

シングルテナント用のサーバー実装です。すべてのエンドポイントがルートパス（`/`）にマウントされます。
app/routes/utilの実装は `@trustknots/server-core` を利用します。

詳細については、[single/README.ja.md](./single/README.ja.md) を参照してください。

### `google-cloud/`

Google Cloud連携のシングルテナント用のサーバー実装です。すべてのエンドポイントがルートパス（`/`）にマウントされます。
app/routes/utilの実装は `@trustknots/server-core` を利用します。

### `aws/`

AWS Lambda 向けのサーバー実装です。ハンドラは `server/aws/lambda/handlers/`、vcknots context は `server/aws/lambda/context/`（`@trustknots/server-aws`）にあります。
CDK インフラは `server/aws/resources/`、AWS provider は `aws/provider/`（`@trustknots/aws`）です。

デプロイ手順とアーキテクチャの詳細は [aws/resources/README.ja.md](./aws/resources/README.ja.md) を参照してください。

### `multi/`

マルチテナント用のサーバー実装です（開発中）。エンドポイントは `/issuers`、`/authorizations`、`/verifiers` などのプレフィックス付きでマウントされます。

### `samples/`

サーバー実装で使用するサンプル設定ファイルが含まれています。

- `issuer_metadata.json`: Credential Issuer のメタデータ設定
- `authorization_metadata.json`: Authorization Server のメタデータ設定
- `verifier_metadata.json`: Verifier のメタデータ設定
- `certificate-chain/`: 証明書チェーンのサンプルファイル
- `certificate-openid-test/`: OpenID Foundation が提供しているテスト用の証明書と秘密鍵
