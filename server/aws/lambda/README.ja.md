# @trustknots/server-aws

AWS 上の vcknots 向け Lambda ハンドラと vcknots コンテキストです。

## ディレクトリ構成

```text
lambda/
├── src/
│   ├── handlers/
│   │   ├── issuer.ts       Lambda ハンドラ（Issuer）
│   │   ├── authz.ts        Lambda ハンドラ（Authz）
│   │   └── verifier.ts     Lambda ハンドラ（Verifier）
│   ├── context/
│   │   └── vcknots-context.ts  vcknots コンテキスト初期化・ベース URL 解決
│   └── utils/
│       └── error-logger.ts     CloudWatch 向けサニタイズ済みエラーロギング
├── package.json
└── tsconfig.json
```

## 概要

各ハンドラは `@trustknots/server-core` の単一ルートを Hono アプリにマウントし、API Gateway プロキシ統合向けに `handle(app)` をエクスポートします。

| ハンドラ | ルート |
|---|---|
| `issuer.ts` | `@trustknots/server-core/routes/issue` |
| `authz.ts` | `@trustknots/server-core/routes/authz` |
| `verifier.ts` | `@trustknots/server-core/routes/verify` |

ハンドラはデフォルトでインメモリの vcknots プロバイダを使用します。`@trustknots/aws` プロバイダ（DynamoDB / KMS / Secrets Manager）が実装されたら差し替えてください。

未処理エラーは `utils/error-logger.ts`（`sanitizeError`）経由でログ出力され、安全なフィールド（message・name・開発時のみ stack）のみが CloudWatch に記録されます。

### ベース URL 解決（`context/vcknots-context.ts`）

| 環境変数 | 結果 |
|---|---|
| `API_GATEWAY_ID` + `AWS_REGION` + `API_STAGE` が設定済み | `https://{id}.execute-api.{region}.amazonaws.com/{stage}` |
| `BASE_URL` が設定済み | `BASE_URL` の値 |
| どちらも未設定 | `http://localhost:8080`（ローカルフォールバック） |

CDK スタック（`resources/`）が `API_GATEWAY_ID` と `API_STAGE` を自動で注入します。

## ビルド

```bash
# プロジェクトルートから
pnpm --filter @trustknots/server-aws build

# または server/aws/lambda から
pnpm build
```

## ローカル開発

このディレクトリの `.env` に `BASE_URL` を設定し、Lambda エミュレーションツールを使ってハンドラをローカルで実行してください。
