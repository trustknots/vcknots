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

`createServer(options?)` では、OAuth 関連の設定も渡せます。例えば DPoP 用 nonce を有効にする場合は次のように指定します。

```ts
createServer({
  oauth: {
    senderConstrainedAccessToken: {
      dpop: {
        mode: 'optional',
      },
    },
  },
})
```

この設定を使うと、共有の `POST /nonce` ルートは `mode !== 'off'` の場合に `DPoP-Nonce` レスポンスヘッダーを追加できます。

サブパス export で個別モジュールを import することもできます。

```ts
import { createIssueRouter } from '@trustknots/server-core/routes/issue'
import { handleError } from '@trustknots/server-core/utils/error-handler'
```

## ビルド

リポジトリルートで実行:

```bash
pnpm install
pnpm -F @trustknots/server-core build
```

## 補足

- このパッケージは workspace 内の private パッケージです。
- `@trustknots/vcknots`、`hono`、`@hono/node-server` に依存します。
