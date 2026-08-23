# AWS Resources

vcknots を AWS 上で動かすための CDK スタックです。

関連パッケージ:

- [`@trustknots/server-aws`](../src) — Lambda ハンドラ、vcknots context、ユーティリティ（`src/handlers/`、`src/context/`、`src/utils/`）
- [`@trustknots/aws`](../../../aws) — DynamoDB / KMS（Issuer / Authz / Verifier 署名鍵）/ Secrets Manager（Verifier 証明書）向け AWS provider

## アーキテクチャ

```text
aws/                       @trustknots/aws

server/aws/
├── src/                   @trustknots/server-aws
│   ├── package.json
│   ├── handlers/
│   │   ├── issuer.ts      Lambda ハンドラ（Issuer）
│   │   ├── authz.ts       Lambda ハンドラ（Authz）
│   │   └── verifier.ts    Lambda ハンドラ（Verifier）
│   ├── apps/
│   │   ├── create-issuer-app.ts   Issuer アプリ（DynamoDB issuer メタデータストア、KMS 署名鍵ストア）
│   │   ├── create-authz-app.ts    Authorization Server アプリ（DynamoDB authz メタデータストア、KMS 署名鍵ストア）
│   │   └── create-verifier-app.ts Verifier アプリ（DynamoDB verifier メタデータストア、KMS 署名鍵ストア、Secrets Manager 証明書ストア）
│   ├── context/
│   │   └── vcknots-context.ts context / baseUrl ヘルパー
│   └── utils/
│       └── error-logger.ts  サニタイズ済み CloudWatch エラーログ
└── resources/             このパッケージ（CDK アプリ）
    ├── bin/resources.ts
    ├── scripts/
    │   ├── deploy-resources.sh
    │   └── .env.example
    └── lib/
        ├── construct/
        │   ├── data/
        │   │   └── data-stores.ts
        │   ├── api/
        │   │   ├── lambda-api.ts
        │   │   ├── issuer-api.ts
        │   │   ├── authz-api.ts
        │   │   └── verifier-api.ts
        │   └── security/
        │       └── secret-management.ts   （プレースホルダー、スタック未組み込み）
        ├── util/
        │   └── paths.ts
        └── resources-stack.ts

ResourcesStack
├── DataStores (construct/data)
├── IssuerApi  (construct/api) → Lambda + REST API (vcknots-issuer-{stage})
├── AuthzApi   (construct/api) → Lambda + REST API (vcknots-authz-{stage})
└── VerifierApi (construct/api) → Lambda + REST API (vcknots-verifier-{stage})
```

### Lambda ハンドラ

ハンドラのソースは `@trustknots/server-aws`（`server/aws/src/handlers/` と `server/aws/src/context/`）にあります。

各ハンドラは `@trustknots/server-core` の単一ルートを Hono アプリにマウントし、API Gateway 向けに `handle(app)` をエクスポートします。

| ハンドラ（`server/aws/src/handlers/`） | ルート |
|---|---|
| `issuer.ts` | `@trustknots/server-core/routes/issue` |
| `authz.ts` | `@trustknots/server-core/routes/authz` |
| `verifier.ts` | `@trustknots/server-core/routes/verify` |

Issuer は `@trustknots/aws` の `dynamodbIssuerMetadataStore` と `kmsIssuerSignatureKeyStore` を、Authorization Server は `dynamodbAuthzServerMetadataStore` と `kmsAuthzSignatureKeyStore` を、Verifier は `dynamodbVerifierMetadataStore`、`kmsVerifierSignatureKeyStore`、`secretsManagerVerifierCertificateStore` を使用します。

未処理エラーは `utils/error-logger.ts`（`sanitizeError`）経由でログ出力され、CloudWatch には安全なフィールドのみが記録されます。

### API Gateway + Lambda

各ロールは共通の `LambdaApi` construct（`lib/construct/api/lambda-api.ts`）を使用します。

物理名（ロググループ、REST API 名）には `API_STAGE` から取得したデプロイステージが含まれ、同一アカウント/リージョン内で複数ステージを共存させられます。

| リソース | 設定 |
|---|---|
| API 種別 | `{proxy+}` 付き `LambdaRestApi` |
| ステージ | `API_STAGE` 環境変数（既定: `test`；デプロイ時の `--stage` または `scripts/.env` で設定） |
| CORS | `defaultCorsPreflightOptions`: `prod` 以外のステージは全オリジン許可；`prod` は `CORS_ALLOWED_ORIGINS`（カンマ区切りの HTTPS オリジン）が必須。メソッド: GET, POST, DELETE, OPTIONS |
| Lambda ランタイム | Node.js 24（`NODEJS_24_X`、ARM64） |
| タイムアウト | 29 秒 |
| メモリ | 512 MB |
| ログ保持 | 1 週間 |
| `API_GATEWAY_ID`、`API_STAGE` | ランタイムで API Gateway のデフォルト URL を組み立てるために使用 |

| Lambda | ロググループ（`{stage}` = `API_STAGE`） | REST API 名 | 環境変数 |
|---|---|---|---|
| Issuer | `/vcknots/{stage}/issuer` | `vcknots-issuer-{stage}` | `ISSUERS_TABLE_NAME`、`NONCES_TABLE_NAME`、`PRE_CODES_TABLE_NAME`、`TX_CODE_PEPPER` |
| Authz | `/vcknots/{stage}/authz` | `vcknots-authz-{stage}` | `AUTH_SERVERS_TABLE_NAME`、`PRE_CODES_TABLE_NAME`、`TX_CODE_PEPPER` |
| Verifier | `/vcknots/{stage}/verifier` | `vcknots-verifier-{stage}` | `VERIFIERS_TABLE_NAME`、`REQUEST_OBJECTS_TABLE_NAME`、`NONCES_TABLE_NAME`、`VERIFIER_CERTIFICATE_SECRET_PREFIX` |

`TX_CODE_PEPPER` はデプロイ時の環境変数から読み込まれ（[デプロイ](#デプロイ)参照）、Issuer/Authz Lambda の環境変数に注入されます。未設定の場合、CDK synth はすぐに失敗します。

`lib/construct/api/` のロール別 construct が DynamoDB テーブル、IAM、環境変数を接続します。

カスタムドメイン（ACM / Route 53）は未設定です。

### DynamoDB テーブル設計

データ種別ごとに 1 テーブルです。  
各テーブルはパーティションキー `id` のみで 1 アイテムを識別します（ソートキーなし）。  
課金はオンデマンド（`PAY_PER_REQUEST`）です。スタック削除時は `RETAIN` とし、**ポイントインタイムリカバリ（PITR）** を有効にしています。

| テーブル | `id` の例 | TTL | 保存データ |
|---|---|---|---|
| IssuersTable | Issuer URL のハッシュ | なし | Credential Issuer メタデータ |
| AuthServersTable | Authorization Server URL のハッシュ | なし | Authorization Server メタデータ |
| PreCodesTable | Pre-Authorized Code 文字列 | あり（`ttl`） | 発行時に使用する Pre-authorized code |
| NoncesTable | Nonce 文字列 | あり（`ttl`） | リプレイ防止用 Nonce |
| VerifiersTable | Verifier client ID のハッシュ | なし | Verifier メタデータ |
| RequestObjectsTable | Request Object ID | あり（`ttl`） | VP リクエスト用 Request Object |

`id` 以外の属性（メタデータ本体、`expires_at`、`ttl` など）はアプリケーションが書き込みます。TTL を使うテーブル（PreCodesTable / NoncesTable / RequestObjectsTable）では、`expires_at` はアプリケーションレベルの有効期限で **epoch ミリ秒**（Firestore / in-memory プロバイダと揃えた期限判定に使用）、`ttl` は DynamoDB TTL 専用の **epoch 秒**属性です。

### IAM

| Lambda | DynamoDB アクセス |
|---|---|
| Issuer | IssuersTable、NoncesTable（読み書き）；PreCodesTable（書き込みのみ） |
| Authz | AuthServersTable、PreCodesTable（読み書き） |
| Verifier | VerifiersTable、RequestObjectsTable、NoncesTable（読み書き） |

Issuer ロール・Authz ロール・Verifier ロールには署名鍵ストア用にスコープを絞った KMS ポリシーも付与されています（`grantSignatureKeyStoreAccess()`、`lib/construct/security/signature-key-policy.ts` 参照）。鍵は実行時に作成されるため ARN で指定できず、各ステートメントは条件でスコープを絞っています:

| アクション | スコープの絞り方 |
|---|---|
| `CreateKey`・`TagResource` | `kms:KeyUsage=SIGN_VERIFY` と、provider が作成する `kms:KeySpec`/`kms:KeyOrigin` の値 |
| `CreateAlias`・`UpdateAlias` | 各ロールのエイリアス名前空間（エイリアス側）と `aws:ResourceTag`（キー側 — 新規キーにはまだエイリアスが無いため） |
| `DescribeKey`・`GetPublicKey`・`Sign` | `kms:ResourceAliases` 条件で各ロールのエイリアス名前空間 |
| `GetParametersForImport`・`ImportKeyMaterial`・`ScheduleKeyDeletion` | `aws:ResourceTag` |

最後の行を分けているのは意図的です。`kms:ResourceAliases` はキーに既に設定されているエイリアスと照合するため、**エイリアスが無いキーに対する操作は決して許可できません**。provider は最初の `CreateAlias` より前に（あるいは `CreateAlias` の代わりに）鍵材料のインポートと孤児キーの破棄を行うため、これらの呼び出しは `CreateKey` 時に付与するタグでスコープを絞っています。

3つのロールの違いはエイリアス名前空間とタグだけです:

| ロール | エイリアス名前空間 | キーのタグ |
|---|---|---|
| Issuer | `alias/vcknots/issuers/*` | `vcknots:issuer-signature-key=true` |
| Authz | `alias/vcknots/authz/*` | `vcknots:authz-signature-key=true` |
| Verifier | `alias/vcknots/verifiers/*` | `vcknots:verifier-signature-key=true` |

Verifier ロールには `secretsManagerVerifierCertificateStore` 用にスコープを絞った Secrets Manager ポリシーも付与されています（`lib/construct/api/verifier-api.ts` 参照）。`CreateSecret` は Secrets Manager 側にリソースレベル権限がなく、リクエスト時点ではシークレットの ARN がまだ存在しないため、`Resource: '*'` に `secretsmanager:Name` 条件（`vcknots/verifier-certificates/*` に限定）を組み合わせて付与しています。`PutSecretValue`/`GetSecretValue` は別ステートメントとして `secret:vcknots/verifier-certificates/*` に限定して付与しています。末尾のワイルドカードは、Secrets Manager がすべてのシークレット ARN にランダムな6文字のサフィックスを付与するため必須です。プレフィックス定数は construct と `aws/src/providers/secrets-manager.ts` の2箇所に存在しますが、Lambda には `VERIFIER_CERTIFICATE_SECRET_PREFIX` として渡されるため両者がずれることはありません。シークレットは `aws/secretsmanager` マネージドキーで暗号化されるため、KMS 権限の付与は不要です。

### スタック出力

- `IssuerApiUrl`、`AuthzApiUrl`、`VerifierApiUrl`
- `IssuersTableName`、`AuthServersTableName`、`PreCodesTableName`、`NoncesTableName`、`VerifiersTableName`、`RequestObjectsTableName`

## 前提条件

### ローカル環境

| ツール | バージョン | 備考 |
|---|---|---|
| [Node.js](https://nodejs.org/) | 20+ | CDK 実行および Lambda ハンドラのバンドルに必要（Lambda ランタイム: Node.js 24） |
| [pnpm](https://pnpm.io/) | 10.11.0 | モノレポのパッケージマネージャ（ルート `package.json` の `packageManager`） |
| [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) | v2 推奨 | `deploy-resources.sh` がアイデンティティ/リージョン取得に使用 |
| POSIX `sh` | — | デプロイスクリプト（`scripts/deploy-resources.sh`；macOS/Linux では `/bin/sh`） |

`aws-cdk`、`ts-node`、`esbuild` は `server/aws/resources` の devDependencies としてインストールされます。  
グローバルな `cdk` インストールは不要です。`server/aws/resources` から `pnpm cdk` または `pnpm run deploy` を使用してください。

### AWS アカウントアクセス

- 対象アカウント/リージョン向けの認証情報（`~/.aws/credentials`、`~/.aws/config`、または環境変数）。
- CDK bootstrap およびデプロイを実行する IAM 権限（CloudFormation、Lambda、API Gateway、DynamoDB、IAM、S3、ECR、SSM など関連リソース）。
- アカウント/リージョンへの初回デプロイ時、デプロイスクリプトが自動的に `cdk bootstrap` を実行します。

デプロイ前にアクセスを確認してください:

```bash
aws sts get-caller-identity
aws configure get region
```

### プロジェクトのセットアップ

モノレポのルートから:

```bash
pnpm install
```

任意のローカルデプロイ既定値:

```bash
cp server/aws/resources/scripts/.env.example server/aws/resources/scripts/.env
# API_STAGE、AWS_PROFILE、CORS_ALLOWED_ORIGINS（API_STAGE=prod 時は必須）などを編集
```

## ビルド

TypeScript は `dist/` にコンパイルされます（ソースと同じ場所には出力しません）。

```bash
# プロジェクトルートから
pnpm -F @trustknots/aws-resources build

# または server/aws/resources から
pnpm build
```

## デプロイ

デプロイスクリプトを使用します（`cdk bootstrap` の後に `cdk deploy` を実行）。CDK は `ts-node` 経由で実行されます（`cdk.json`）。`pnpm build` は不要です。

```bash
# プロジェクトルートから
pnpm -F @trustknots/aws-resources run deploy

# または server/aws/resources から
cd server/aws/resources

# 既定の AWS プロファイル、ステージ: test
pnpm run deploy

# プロファイルやステージを指定
pnpm run deploy -- --profile vc-knots
pnpm run deploy -- --stage prod --profile vc-knots
# prod では CORS_ALLOWED_ORIGINS が必須（環境変数または scripts/.env）
CORS_ALLOWED_ORIGINS=https://app.example.com pnpm run deploy -- --stage prod
# TX_CODE_PEPPER は常に必須（環境変数または scripts/.env）。未設定だと CDK synth がエラーになる
TX_CODE_PEPPER=<your-tx-code-pepper-here> pnpm run deploy -- --profile vc-knots
```

オプション:

| フラグ / 環境変数 | 説明 |
|---|---|
| `--profile` | AWS プロファイル（任意；省略時は CLI の既定値を使用） |
| `--stage` | API Gateway ステージ名（既定: `test`）。CDK synth 時の `API_STAGE` にも設定される |
| `CORS_ALLOWED_ORIGINS` | API Gateway CORS 用のカンマ区切り HTTPS オリジン（**`API_STAGE=prod` 時は必須**） |
| `TX_CODE_PEPPER` | `tx_code` HMAC ハッシュ化用の秘密 pepper。Issuer/Authz Lambda の環境変数に注入される（**常に必須**） |
| `STACK_NAME` | CloudFormation スタック名（既定: `ResourcesStack`） |

`scripts/.env` は存在する場合に読み込まれます。CLI フラグは `.env` より優先されます。

## Synth のみ

```bash
cd server/aws/resources
pnpm cdk synth
```
