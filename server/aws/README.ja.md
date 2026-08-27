# AWS Lambda サーバー（ローカル開発）

`@trustknots/server-aws` — AWS API Gateway 上で動作する Issuer・Authorization Server・Verifier の Lambda ハンドラーです。

共通ルートは `@trustknots/server-core` が提供します。Issuer・Authorization Server・Verifier はいずれも DynamoDB バックエンドのメタデータストア（`@trustknots/aws`）を使用します。Issuer と Verifier はさらに署名鍵を AWS KMS に保存します（[Issuer の署名鍵（AWS KMS）](#issuer-の署名鍵aws-kms)、[Verifier の署名鍵（AWS KMS）](#verifier-の署名鍵aws-kms)を参照）。

Issuer および Verifier の **実際の API 仕様・パラメーター・型定義・使用例**については、以下の公式ドキュメントを参照してください：

- **Issuer**: [Issuer セットアップと使用ガイド](https://trustknots.github.io/vcknots/docs/issuer)
- **Verifier**: [Verifier セットアップと使用ガイド](https://trustknots.github.io/vcknots/docs/verifier)

このREADMEのエンドポイント一覧はパス概要です。リクエスト・レスポンスの詳細は上記ドキュメントを参照してください。

## ディレクトリ構成

```text
src/
├── apps/
│   ├── create-base-app.ts      # 共通 Hono アプリファクトリ
│   ├── create-issuer-app.ts    # Issuer アプリ（DynamoDB issuer メタデータストア + KMS 署名鍵ストア）
│   ├── create-authz-app.ts     # Authorization Server アプリ（DynamoDB authz server メタデータストア）
│   └── create-verifier-app.ts  # Verifier アプリ（DynamoDB verifier メタデータストア + KMS 署名鍵ストア）
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
| AWS 認証情報 | — | Issuer・Authorization Server・Verifier（DynamoDB。Issuer と Verifier は KMS も使用）で必要 |

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
| `AWS_REGION` | 全サーバー **必須** | DynamoDB テーブルと KMS 鍵が存在する AWS リージョン（例: `ap-northeast-1`） |
| `AWS_PROFILE` | 全サーバー（任意） | 使用する AWS プロファイル（省略時はデフォルトを使用） |
| `TX_CODE_PEPPER` | 全サーバー **必須** | `tx_code` を DynamoDB に保存する前に HMAC ハッシュ化するための秘密 pepper |
| `ISSUERS_TABLE_NAME` | Issuer **必須** | DynamoDB テーブル名（スタック出力: `IssuersTableName`） |
| `NONCES_TABLE_NAME` | Issuer **必須** | DynamoDB テーブル名（スタック出力: `NoncesTableName`） |
| `PRE_CODES_TABLE_NAME` | Issuer・Authz **必須** | DynamoDB テーブル名（Issuer/Authz 共通、スタック出力: `PreCodesTableName`） |
| `AUTH_SERVERS_TABLE_NAME` | Authz **必須** | DynamoDB テーブル名（スタック出力: `AuthServersTableName`） |
| `VERIFIERS_TABLE_NAME` | Verifier **必須** | DynamoDB テーブル名（スタック出力: `VerifiersTableName`） |
| `REQUEST_OBJECTS_TABLE_NAME` | Verifier **必須** | DynamoDB テーブル名（スタック出力: `RequestObjectsTableName`） |
| `NONCES_TABLE_NAME` | Verifier **必須** | DynamoDB テーブル名（スタック出力: `NoncesTableName`） |
| `ISSUER_PORT` | Issuer（任意） | Issuer のリッスンポートを上書き（デフォルト: `8081`） |
| `ISSUER_BASE_URL` | Issuer（任意） | Issuer メタデータで使用するベース URL を上書き（デフォルト: `http://localhost:{ISSUER_PORT}`） |
| `AUTHZ_PORT` | Authz（任意） | Authorization Server のリッスンポートを上書き（デフォルト: `8082`） |
| `AUTHZ_BASE_URL` | Authz（任意） | Authz メタデータで使用するベース URL を上書き（デフォルト: `http://localhost:{AUTHZ_PORT}`） |
| `VERIFIER_PORT` | Verifier（任意） | Verifier のリッスンポートを上書き（デフォルト: `8083`） |
| `VERIFIER_BASE_URL` | Verifier（任意） | Verifier メタデータで使用するベース URL を上書き（デフォルト: `http://localhost:{VERIFIER_PORT}`） |

**`ISSUERS_TABLE_NAME`・`PRE_CODES_TABLE_NAME`（Issuer・Authz）・`NONCES_TABLE_NAME`（Issuer と Verifier）・`AUTH_SERVERS_TABLE_NAME`・`VERIFIERS_TABLE_NAME`・`REQUEST_OBJECTS_TABLE_NAME` は必須**です。必要なテーブル名が未設定の場合、該当サーバーは起動時に終了します。

**`TX_CODE_PEPPER` は全サーバーで必須**です。`tx_code` を DynamoDB に保存する前に HMAC-SHA256 でハッシュ化するための秘密値（pepper）です。`@trustknots/aws` は import 時にこの値を評価するため、未設定の場合は Issuer・Authorization Server・Verifier のいずれも起動時に `TX_CODE_PEPPER environment variable is required` でエラーになります。十分に長いランダム文字列を設定し、環境ごとに固定して運用してください（変更すると既存データの `tx_code` 検証に失敗します）。

誤った `tx_code` の試行は、pre-authorized code ごとに `dynamodbPreAuthorizedCodeStore` が制限します（既定 **5** 回）。上限を変える場合は、`server/aws/src/apps` で provider を生成するときに `maxTxCodeAttempts` を渡してください（環境変数は未対応です）。上限到達後はコードが削除され、正しい `tx_code` でも以降のリクエストは `invalid_grant` になります。

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

## Issuer の署名鍵（AWS KMS）

Issuer はクレデンシャル署名鍵を `kmsIssuerSignatureKeyStore()`（`@trustknots/aws`）経由で AWS KMS に保存します。署名は常に KMS の `Sign` API で実行されます。KMS 内で生成した鍵の場合、秘密鍵は KMS の外に出ません。一方、外部で生成した鍵ペアをインポートする場合は、アプリケーションが秘密鍵を受け取ってラップし、`ImportKeyMaterial` で KMS に送信します — その時点までは秘密鍵は KMS の外に存在します。

- **エイリアス命名規則**: 各鍵はエイリアス `alias/vcknots/issuers/<md5(issuer)>-<alg>`（issuer 識別子の MD5 を base64url 化したもの + JOSE アルゴリズム名。例: `ES256`）で参照されます。鍵ペアを指定しない場合、鍵は一度だけ作成され、以降の `save` では同じエイリアスが再利用されます。外部生成の鍵ペアをインポートする場合は、`save` を呼ぶたびに新しい KMS 鍵が作成され、エイリアスがその鍵に付け替えられます（古い鍵は削除されず残ります）。いずれの場合も追加の環境変数は不要です。
- **対応アルゴリズム**: `ES256`・`ES384`・`RS256`・`RS512`・`PS256`・`PS512`。KMS 内での鍵生成はすべてのアルゴリズムに対応しています。外部で生成した鍵ペアのインポートは EC 系（`ES256`/`ES384`）のみ対応です — RSA 秘密鍵は RSAES_OAEP_SHA_256 のラップ上限を超えるため `RSA_AES_KEY_WRAP` が必要になりますが、これは未実装です（Google Cloud プロバイダと同じ制限）。
- **必要な IAM 権限**（CDK スタックが Issuer Lambda ロールに付与）: `kms:CreateKey`・`kms:TagResource`・`kms:CreateAlias`・`kms:UpdateAlias`・`kms:DescribeKey`・`kms:GetPublicKey`・`kms:Sign`・`kms:GetParametersForImport`・`kms:ImportKeyMaterial`・`kms:ScheduleKeyDeletion`。ローカル実行時は AWS プロファイルに同等の権限が必要です。プロバイダが作成する鍵にはすべてタグ（`vcknots:issuer-signature-key=true`）が付与されます。新規作成直後の鍵にはまだエイリアスが無く、エイリアスによる権限の絞り込みができないため、CDK スタックはこのタグを使って鍵本体への`CreateAlias`/`UpdateAlias`を認可しています。

## Verifier の署名鍵（AWS KMS）

Verifier は認可リクエストオブジェクト（JAR）の署名鍵を `kmsVerifierSignatureKeyStore()`（`@trustknots/aws`）経由で AWS KMS に保存します。Issuer 用ストアと同じ provider ファクトリから構築されているため、KMS 内での鍵生成・ラップしたインポート・`Sign` API による署名といった挙動は同一で、エイリアス名前空間と鍵に付与するタグだけが異なります。

- **エイリアス命名規則**: 各鍵はエイリアス `alias/vcknots/verifiers/<md5(client_id)>-<alg>`（verifier のクライアント ID の MD5 を base64url 化したもの + JOSE アルゴリズム名）で参照されます。鍵は verifier の登録時（`createVerifierMetadata`）に作成され、その公開鍵が verifier メタデータの `jwks` として公開されます。追加の環境変数は不要です。
- **対応アルゴリズム**: Issuer と同じです — KMS 内での生成は `ES256`・`ES384`・`RS256`・`RS512`・`PS256`・`PS512`、外部生成の鍵ペアのインポートは EC 系（`ES256`/`ES384`）のみ対応です。
- **必要な IAM 権限**（CDK スタックが Verifier Lambda ロールに付与）: Issuer と同じアクション一式を、`alias/vcknots/verifiers/*` 名前空間と `vcknots:verifier-signature-key=true` タグの付いた鍵にスコープを絞って付与しています。
- **ストア間のズレ**: verifier メタデータは DynamoDB、鍵は KMS と別ストアにあるため、両者がズレることがあります（インメモリ鍵ストアで動かしていた環境を KMS に向けた場合に起こりやすいです）。`createVerifierMetadata` は登録済みの verifier を弾くため自動修復できず、Verifier は起動時に警告を出して処理を続行します（`Verifier metadata exists but no <alg> key is registered in KMS`）。復旧は手動で、verifier を最初に登録する手順と同じです。**登録処理はローカル起動時にしか実行されない**点に注意してください: `handlers/verifier.ts` は `AWS_LAMBDA_FUNCTION_NAME` が設定されていると `initialize()` をスキップし、verifier を登録する HTTP エンドポイントも存在しないため、デプロイ済みの Lambda が自力で登録することはありません。

  `initialize()` は常に同梱の `server/samples/verifier_metadata.json` を登録するため、以下の手順は**その verifier が持っていたメタデータを置き換えます**。サンプルメタデータで動かしている verifier にのみ適用してください。

  1. Verifiers テーブルから該当 verifier のアイテムを削除します。パーティションキーはクライアント ID そのものではなく、その MD5 を base64url 化した値です: `node -e "console.log(require('crypto').createHash('md5').update('<client-id>').digest('base64url'))"`
  2. ローカルの `.env` を同じテーブルに向け、`VERIFIER_BASE_URL` に復旧対象の verifier を設定します（デプロイ済み環境を直す場合は `localhost` ではなくデプロイ先の API URL）。
  3. `pnpm start:verifier` を一度実行します。その verifier ID へのサンプルメタデータ登録と KMS 鍵の作成が行われるので、完了後は停止して構いません。

  カスタムメタデータを持つ verifier の場合は、先にアイテムをバックアップし、同じメタデータを `createVerifierMetadata` に渡すスクリプトから再登録してください（鍵の作成と `jwks` の書き換えはフローが行います）。**バックアップしたアイテムをそのまま復元してはいけません** — その `jwks` は失われた鍵を指したままで、まさに直そうとしているドリフトが再現します。

## Authorization Server の署名鍵（AWS KMS）

Authorization Server はアクセストークン / レスポンスの署名鍵を `kmsAuthzSignatureKeyStore()`（`@trustknots/aws`）経由で AWS KMS に保存します。Issuer・Verifier 用ストアと同じ provider ファクトリから構築されているため、KMS 内での鍵生成・ラップしたインポート・`Sign` API による署名といった挙動は同一で、エイリアス名前空間と鍵に付与するタグだけが異なります。

- **エイリアス命名規則**: 各鍵はエイリアス `alias/vcknots/authz/<md5(issuer)>-<alg>`（authorization server の issuer URL の MD5 を base64url 化したもの + JOSE アルゴリズム名）で参照されます。鍵は authorization server の登録時（`createAuthzServerMetadata`）に、常に `ES256` で作成されます（`create-authz-app.ts` はカスタムの `alg` を渡していません）。追加の環境変数は不要です。
- **対応アルゴリズム**: Issuer・Verifier と同じです — KMS 内での生成は `ES256`・`ES384`・`RS256`・`RS512`・`PS256`・`PS512`、外部生成の鍵ペアのインポートは EC 系（`ES256`/`ES384`）のみ対応です。
- **必要な IAM 権限**（CDK スタックが Authz Lambda ロールに付与）: Issuer・Verifier と同じアクション一式を、`alias/vcknots/authz/*` 名前空間と `vcknots:authz-signature-key=true` タグの付いた鍵にスコープを絞って付与しています。
- **ストア間のズレ**: authz サーバーメタデータは DynamoDB、鍵は KMS と別ストアにあるため、両者がズレることがあります（インメモリ鍵ストアで動かしていた環境を KMS に向けた場合に起こりやすいです）。`createAuthzServerMetadata` は登録済みの authorization server を弾くため自動修復できず、Authorization Server は起動時に警告を出して処理を続行します（`Authz server metadata exists but no <alg> key is registered in KMS`）。復旧は手動で、authorization server を最初に登録する手順と同じです。**登録処理はローカル起動時にしか実行されない**点に注意してください: `handlers/authz.ts` は `AWS_LAMBDA_FUNCTION_NAME` が設定されていると `initialize()` をスキップし、authorization server を登録する HTTP エンドポイントも存在しないため、デプロイ済みの Lambda が自力で登録することはありません。

  `initialize()` は常に同梱の `server/samples/authorization_metadata.json` を登録するため、以下の手順は**その authorization server が持っていたメタデータを置き換えます**。サンプルメタデータで動かしている authorization server にのみ適用してください。

  1. AuthServers テーブルから該当 authorization server のアイテムを削除します。パーティションキーは issuer URL そのものではなく、その MD5 を base64url 化した値です: `node -e "console.log(require('crypto').createHash('md5').update('<issuer-url>').digest('base64url'))"`
  2. ローカルの `.env` を同じテーブルに向け、`AUTHZ_BASE_URL` に復旧対象の authorization server を設定します（デプロイ済み環境を直す場合は `localhost` ではなくデプロイ先の API URL）。
  3. `pnpm start:authz` を一度実行します。その authorization server へのサンプルメタデータ登録と KMS 鍵の作成が行われるので、完了後は停止して構いません。

## 注意事項

- `.env` は起動時に `dotenv/config` によって読み込まれます。変更を反映するにはサーバーを再起動してください。
- ワークスペースパッケージを変更した場合は、モノレポルートで `pnpm install` を実行してリンクを更新し、変更したパッケージを再ビルドしてください。
- AWS へのデプロイ方法は [`server/aws/resources/README.md`](./resources/README.md) を参照してください。
