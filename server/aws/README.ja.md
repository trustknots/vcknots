# AWS Lambda サーバー（ローカル開発）

`@trustknots/server-aws` — AWS API Gateway 上で動作する Issuer・Authorization Server・Verifier の Lambda ハンドラーです。

共通ルートは `@trustknots/server-core` が提供します。Issuer・Authorization Server・Verifier はいずれも DynamoDB バックエンドのメタデータストア（`@trustknots/aws`）を使用します。

Issuer および Verifier の **実際の API 仕様・パラメーター・型定義・使用例**については、以下の公式ドキュメントを参照してください：

- **Issuer**: [Issuer セットアップと使用ガイド](https://trustknots.github.io/vcknots/docs/issuer)
- **Verifier**: [Verifier セットアップと使用ガイド](https://trustknots.github.io/vcknots/docs/verifier)

このREADMEのエンドポイント一覧はパス概要です。リクエスト・レスポンスの詳細は上記ドキュメントを参照してください。

## ディレクトリ構成

```text
src/
├── apps/
│   ├── create-base-app.ts      # 共通 Hono アプリファクトリ
│   ├── create-issuer-app.ts    # Issuer アプリ（DynamoDB issuer メタデータストア）
│   ├── create-authz-app.ts     # Authorization Server アプリ（DynamoDB authz server メタデータストア）
│   └── create-verifier-app.ts  # Verifier アプリ（DynamoDB verifier メタデータストア）
├── handlers/
│   ├── issuer.ts               # Lambda ハンドラー / ローカル起動エントリーポイント — Issuer（ポート 8081）
│   ├── authz.ts                # Lambda ハンドラー / ローカル起動エントリーポイント — Authorization Server（ポート 8082）
│   └── verifier.ts             # Lambda ハンドラー / ローカル起動エントリーポイント — Verifier（ポート 8083）
├── context/
│   └── vcknots-context.ts      # VcknotsContext と baseUrl ヘルパー
├── utils/
│   └── error-logger.ts         # エラーログのサニタイズ処理
├── .env.example                # 環境変数サンプル
└── package.json
```

## 前提条件

| ツール | バージョン | 備考 |
|---|---|---|
| [Node.js](https://nodejs.org/) | 20 以上 | |
| [pnpm](https://pnpm.io/) | 10.11.0 | モノレポパッケージマネージャー |
| AWS 認証情報 | — | Issuer・Authorization Server・Verifier（DynamoDB）で必要 |

AWS 認証情報は `~/.aws/credentials`・`~/.aws/config`・環境変数（`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`）・`AWS_PROFILE` のいずれかで設定できます。

Issuer・Authorization Server・Verifier をローカルで起動するには、CDK スタック（`server/aws/resources`）を事前に AWS へデプロイしておく必要があります（実際の DynamoDB テーブルを参照するため）。

## セットアップ

### 1. 依存関係のインストール

モノレポルートから実行します：

```bash
pnpm install
```

### 2. ワークスペースパッケージのビルド

```bash
pnpm -F @trustknots/vcknots build
pnpm -F @trustknots/server-core build
pnpm -F @trustknots/aws build
```

### 3. 環境変数の設定

```bash
cd server/aws/src
cp .env.example .env
```

`.env` を編集します。テーブル名は `server/aws/resources` をデプロイした後、CloudFormation スタックの出力から確認できます。

| 変数 | 使用するサーバー | 説明 |
|---|---|---|
| `AWS_REGION` | Issuer | DynamoDB テーブルがデプロイされている AWS リージョン（例: `ap-northeast-1`） |
| `AWS_PROFILE` | Issuer（任意） | 使用する AWS プロファイル（省略時はデフォルトを使用） |
| `ISSUERS_TABLE_NAME` | Issuer **必須** | DynamoDB テーブル名（スタック出力: `IssuersTableName`） |
| `NONCES_TABLE_NAME` | Issuer（任意） | DynamoDB テーブル名（スタック出力: `NoncesTableName`） |
| `PRE_CODES_TABLE_NAME` | Issuer（任意） | DynamoDB テーブル名（スタック出力: `PreCodesTableName`） |
| `AUTH_SERVERS_TABLE_NAME` | Authz **必須** | DynamoDB テーブル名（スタック出力: `AuthServersTableName`） |
| `PRE_CODES_TABLE_NAME` | Authz（任意） | DynamoDB テーブル名（スタック出力: `PreCodesTableName`） |
| `VERIFIERS_TABLE_NAME` | Verifier **必須** | DynamoDB テーブル名（スタック出力: `VerifiersTableName`） |
| `REQUEST_OBJECTS_TABLE_NAME` | Verifier **必須** | DynamoDB テーブル名（スタック出力: `RequestObjectsTableName`） |
| `NONCES_TABLE_NAME` | Verifier（任意） | DynamoDB テーブル名（スタック出力: `NoncesTableName`） |
| `ISSUER_PORT` | Issuer（任意） | Issuer のリッスンポートを上書き（デフォルト: `8081`） |
| `ISSUER_BASE_URL` | Issuer（任意） | Issuer メタデータで使用するベース URL を上書き（デフォルト: `http://localhost:{ISSUER_PORT}`） |
| `AUTHZ_PORT` | Authz（任意） | Authorization Server のリッスンポートを上書き（デフォルト: `8082`） |
| `AUTHZ_BASE_URL` | Authz（任意） | Authz メタデータで使用するベース URL を上書き（デフォルト: `http://localhost:{AUTHZ_PORT}`） |
| `VERIFIER_PORT` | Verifier（任意） | Verifier のリッスンポートを上書き（デフォルト: `8083`） |
| `VERIFIER_BASE_URL` | Verifier（任意） | Verifier メタデータで使用するベース URL を上書き（デフォルト: `http://localhost:{VERIFIER_PORT}`） |

**`ISSUERS_TABLE_NAME`・`AUTH_SERVERS_TABLE_NAME`・`VERIFIERS_TABLE_NAME`・`REQUEST_OBJECTS_TABLE_NAME` は必須**です。未設定の場合、該当サーバーは起動時に終了します。

## サーバーの起動

`server/aws/src` ディレクトリで、各サーバーを別々のターミナルで起動します：

```bash
# Issuer — http://localhost:8081
pnpm start:issuer

# Authorization Server — http://localhost:8082
pnpm start:authz

# Verifier — http://localhost:8083
pnpm start:verifier
```

モノレポルートからパッケージフィルターを使って実行することもできます：

```bash
pnpm -F @trustknots/server-aws start:issuer
```

### 起動確認

初回起動時、Issuer・Authorization Server・Verifier は `server/samples/` のサンプルデータを DynamoDB へ自動投入します：

```text
Issuer metadata initialized
Issuer is running on http://localhost:8081
```

```text
Authz server metadata initialized
Authz is running on http://localhost:8082
```

```text
Verifier metadata initialized
Verifier is running on http://localhost:8083
```

2回目以降はデータが既に存在する場合スキップされます：

```text
Issuer metadata already exists, skipping initialization
Issuer is running on http://localhost:8081
```

```text
Authz server metadata already exists, skipping initialization
Authz is running on http://localhost:8082
```

```text
Verifier metadata already exists, skipping initialization
Verifier is running on http://localhost:8083
```

### ポートまたはベース URL の変更

```bash
ISSUER_PORT=9081 ISSUER_BASE_URL=http://localhost:9081 pnpm start:issuer
```

## エンドポイント

### Issuer（`http://localhost:8081`）

| メソッド | パス | 説明 |
|---|---|---|
| `POST` | `/configurations/:configuration/offer` | クレデンシャルオファーの作成 |
| `POST` | `/credentials` | クレデンシャルの発行 |
| `GET` | `/.well-known/openid-credential-issuer` | Issuer メタデータ |
| `GET` | `/.well-known/jwt-vc-issuer` | JWT VC Issuer メタデータ |
| `POST` | `/nonce` | ノンスの作成（c_nonce） |
| `GET` | `/nonce/:nonce` | ノンスの検証 |
| `DELETE` | `/nonce/:nonce` | ノンスの失効 |

### Authorization Server（`http://localhost:8082`）

| メソッド | パス | 説明 |
|---|---|---|
| `POST` | `/token` | トークンエンドポイント（Pre-Authorized Code グラント） |
| `GET` | `/.well-known/oauth-authorization-server` | Authorization Server メタデータ |

### Verifier（`http://localhost:8083`）

| メソッド | パス | 説明 |
|---|---|---|
| `POST` | `/request` | 認可リクエストの作成 |
| `POST` | `/request-object` | 認可リクエストの作成（参照方式） |
| `GET` | `/request.jwt/:request-object-Id` | Request Object JWT の取得 |
| `POST` | `/callback` | VP 検証コールバック |
| `POST` | `/callback-kbjwt` | VP 検証コールバック（Key Binding JWT） |
| `GET` | `/verified` | 検証完了後のリダイレクトエンドポイント |

## 注意事項

- `.env` は起動時に `dotenv/config` によって読み込まれます。変更を反映するにはサーバーを再起動してください。
- ワークスペースパッケージを変更した場合は、モノレポルートで `pnpm install` を実行してリンクを更新し、変更したパッケージを再ビルドしてください。
- AWS へのデプロイ方法は [`server/aws/resources/README.md`](./resources/README.md) を参照してください。
