# Server Core

サンプルサーバーパッケージ向けの共通サーバー実装です。

このパッケージには、`server/single` と `server/google-cloud` で共有する サーバーブートストラップ、Hono アプリ生成処理、ルート実装、ユーティリティが含まれます。

- `server/single`
- `server/google-cloud`

パッケージ名: `@trustknots/server-core`

## 提供するもの

- 共通サーバーブートストラップ: `createServer(options?)`
- 共通 Hono アプリ生成: `createApp(context, baseUrl)`
- 共通ルート生成:
  - `createIssueRouter`
  - `createAuthzRouter`
  - `createVerifierRouter`
- 共通ユーティリティ:
  - `handleError`

## ディレクトリ構成

```text
core/
├─ src/
│  ├─ app.ts
│  ├─ index.ts
│  ├─ server.ts
│  ├─ routes/
│  │  ├─ authz.ts
│  │  ├─ issue.ts
│  │  └─ verify.ts
│  └─ utils/
│     └─ error-handler.ts
├─ package.json
└─ tsconfig.json
```

## 利用方法

推奨はパッケージルートから import する方法です。

```ts
import { createApp, createServer } from '@trustknots/server-core'
```

`createServer(options?)` では Provider / Extension などの実装依存の設定を渡せます。DPoP mode などの OAuth policy は `server/samples/oauth-server.json` から読み込み、起動時に authorization server ごとの policy store へ登録します。

共有の `POST /nonce` ルートは、OAuth policy の DPoP mode が `off` 以外の場合に `DPoP-Nonce` レスポンスヘッダーを追加できます。`c_nonce` と `DPoP-Nonce` は別の値として発行され、`DPoP-Nonce` は token endpoint の DPoP Proof 用 nonce として使います。

共有の `POST /token` ルートも同じ OAuth policy を参照します。また、OAuth client store に登録された client を使って `private_key_jwt` client authentication を検証できます。サンプルでは `server/samples/oauth-clients.json` を起動時に読み込み、client ごとの sender constraint 設定、`jwks.keys`、`client_assertion_audience` などを登録します。

`client_id` が token request body にある場合はその値を優先し、ない場合は `client_assertion` JWT の `iss` / `sub` から導出します。Pre-Authorized Code の token request でどちらからも client_id を得られない場合は anonymous token request として扱い、Authorization Server Metadata の `pre-authorized_grant_anonymous_access_supported` が `true` のときだけ anonymous client policy を使います。未設定または `false` の場合は `invalid_client` です。詳細は [シングルサーバー README](../single/README.ja.md#post-token) を参照してください。

| mode | `POST /token` の挙動 |
| --- | --- |
| `off` | DPoP を利用せず、Bearer access token を発行します。 |
| `optional` | DPoP ヘッダーがない場合は Bearer access token を発行します。DPoP ヘッダーがある場合は proof を検証し、DPoP-bound access token を発行します。 |
| `required` | DPoP ヘッダーを必須にします。未指定または不正な DPoP ヘッダーは `invalid_request` になります。 |

DPoP Proof に nonce がない、または nonce が無効な場合は、`DPoP-Nonce` レスポンスヘッダー付きで `use_dpop_nonce` を返します。DPoP Proof の検証に成功した場合は `token_type: "DPoP"` のレスポンスになり、access token には `cnf.jkt` が含まれます。

サブパス export で個別モジュールを import することもできます。

```ts
import { createIssueRouter } from '@trustknots/server-core/routes/issue'
import { handleError } from '@trustknots/server-core/utils/error-handler'
```

## サーバーオプション

`createServer(options?)` は、利用ライブラリ vcknots の `VcknotsOptions`（providers / extensions など）を拡張した `ServerOptions` を受け取ります。

コンポーネントごとに独立した名前空間でオプションを渡せる設計としています。

現在は `verifier` 名前空間のみ実装されています。将来的に `issuer` や `authz` にも同じパターンでオプションを追加できます。

### `verifier` オプション

#### `vpAudTransactionStore`

`direct_post` フローで OAuth `state` と verifier トランザクション ID を紐づけるストアを注入します。省略時はプロセス内のインメモリ実装（`createDirectPostVpAudTransactionStore()`）が使われます。

**インメモリ実装の制約**: シングルプロセス環境専用です。Cloud Run など複数インスタンスが起動する環境では、`/request` と `/callback` が別インスタンスに割り当てられると state の照合に失敗します。このような場合は外部ストアを実装して注入してください。

`DirectPostVpAudTransactionStore` インターフェース：

| メソッド | 説明 |
| --- | --- |
| `reserve(state)` | state を予約し、`reservationToken` を返す。同一 state が使用中なら `invalid_request` を返す。 |
| `register(state, transactionId, reservationToken)` | `reservationToken` を検証し、state に verifier トランザクション ID を紐づける。 |
| `resolve(state)` | state に対応する `transactionId` を返す。未登録・期限切れは `invalid_request`。 |
| `consume(state, transactionId)` | 保存済みの transactionId が引数と一致する場合に限り state エントリを削除する。VP 検証成功後に呼び出す。 |
| `release(state, reservationToken)` | エラー時のロールバック。`reservationToken` を検証して state エントリを削除する。 |

`reserve` → `register`（成功時）または `release`（エラー時）という 2 フェーズコミットパターンで、並行リクエストによる state の二重登録を防ぎます。

Firestore を使った実装例は [Google Cloud サーバー README](../google-cloud/README.ja.md#vpaudtransactionstore-firestore-実装) を参照してください。

## ビルド

リポジトリルートで実行:

```bash
pnpm install
pnpm -F @trustknots/server-core build
```

## 補足

- このパッケージは workspace 内の private パッケージです。
- `@trustknots/vcknots`、`hono`、`@hono/node-server` に依存します。
