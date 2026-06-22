# server/aws

vcknots の AWS Lambda デプロイメントです。

## パッケージ

| ディレクトリ | パッケージ | 説明 |
|---|---|---|
| [`lambda/`](./lambda) | `@trustknots/server-aws` | Lambda ハンドラ、vcknots コンテキスト、ユーティリティ |
| [`resources/`](./resources) | `resources` | CDK スタック: API Gateway・Lambda・DynamoDB |

## 概要

Issuer・Authz・Verifier の3つのロールをそれぞれ独立した Lambda 関数として、各自の API Gateway REST API の背後にデプロイします。

インフラは `resources/` で AWS CDK を使って定義しています。ハンドラのソースコードは `lambda/src/` にあります。

アーキテクチャの詳細とデプロイ手順は [resources/README.ja.md](./resources/README.ja.md) を参照してください。
