# Server

このディレクトリには、VCKnotsライブラリを使用したサーバー実装のサンプルが含まれています。

## ディレクトリ構成

### `single/`

シングルテナント用のサーバー実装です。すべてのエンドポイントがルートパス（`/`）にマウントされます。

詳細については、[single/README.ja.md](./single/README.ja.md) を参照してください。

### `multi/`

マルチテナント用のサーバー実装です（開発中）。エンドポイントは `/issuers`、`/authorizations`、`/verifiers` などのプレフィックス付きでマウントされます。

### `samples/`

サーバー実装で使用するサンプル設定ファイルが含まれています。

- `issuer_metadata.json`: Credential Issuer のメタデータ設定
- `authorization_metadata.json`: Authorization Server のメタデータ設定
- `verifier_metadata.json`: Verifier のメタデータ設定
- `certificate-chain/`: 証明書チェーンのサンプルファイル
- `certificate-openid-test/`: OpenID Foundation が提供しているテスト用の証明書と秘密鍵
