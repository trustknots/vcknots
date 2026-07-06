---
sidebar_position: 6
---

# 02. Provider インターフェースの基本

VCKnots では、各種の機能モジュール（ストレージ, 鍵管理, DID 解決, 検証など）を疎結合に保ちつつ、柔軟に差し替え・拡張できるようにするために `Provider` インターフェースを採用しています。

この章では、すべてのプロバイダーに共通するコアプロパティと、プロバイダーが登録・解決される際の優先順位の仕組みについて解説します。

---

## 1. Provider のコアプロパティ

VCKnots のすべてのプロバイダーは、以下の 3 つの共通プロパティを持っています。

```ts
export type Provider = {
  kind: string
  name: string
  single: boolean
  // ... 各種プロバイダー固有のメソッドやプロパティ
}
```

### `kind` (string)
プロバイダーの **種類（カテゴリ）** を表す一意の識別子です。
- 例: `'nonce-provider'`, `'did-provider'`, `'jwt-signature-provider'`
- VCKnots の内部処理は、この `kind` を指定して必要なプロバイダーを取得します。
- 各 `kind` ごとの用途については、[04. Provider の選択](./04-provider-type.md) を参照してください。

### `name` (string)
そのプロバイダー**実装の固有名**です。
- 例: `'in-memory-nonce-provider'`, `'aws-kms-signature-provider'`
- ログ出力やデバッグ、あるいは同一 `kind` の中から特定のプロバイダーを識別する目的などで利用されます。

### `single` (boolean)
同一の `kind` に対して、 **「1つだけしか有効にできない（Single）」** か、 **「複数共存できる（Multi）」** かを表します。

| `single` の値 | 区分 | 説明 | 代表的な例 |
| --- | --- | --- | --- |
| `true` | **Single Provider** | 同じ `kind` に対して 1 つだけ登録できます。ユーザーが新規プロバイダーを登録すると、デフォルトのプロバイダーは**完全に上書き（置き換え）**されます。 | `nonce-provider`, `issuer-metadata-store-provider` |
| `false` | **Multi Provider** | 同じ `kind` のプロバイダーを複数登録して共存させることができます。どれを利用するかは、`canHandle(...)` メソッドなどを用いて動的に判断されます。 | `did-provider`, `issue-credential-provider` |

---

## 2. プロバイダーの解決と優先評価順位

`single: false`（Multi Provider）の場合、デフォルトのプロバイダーとユーザーが登録したプロバイダーが共存します。このとき、VCKnots がどのプロバイダーを優先して選択するかのルールは、以下のようになっています。

### 優先評価のルール
VCKnots のプロバイダーレジストリ（`ProviderRegistry`）にプロバイダーが登録される際、内部では以下のルールでマッピングが構築されます。

1. `single: true` の場合、既存のプロバイダーをフィルタリングして除外し、新しいプロバイダーで置き換えます。
2. `single: false` の場合、既存のリストに新しいプロバイダーを追加します。このとき、**「後から登録されたプロバイダーほど、評価用配列の先頭（インデックス 0）に配置される」**（`[provider, ...current]`）ようになっています。

マルチプロバイダーから適切なプロバイダーを選択する際、レジストリの `select(kind, value)` メソッドが呼び出されます。

```ts
// 例: "did:key:123" を解決できる did-provider を選択する
const didProvider = context.providers.select('did-provider', 'did:key:123')
```

`select` メソッドは、登録されているプロバイダー配列を**先頭から順に走査**し、最初に `canHandle(value)` が `true` を返したプロバイダーを返します。

この仕組みにより、**ユーザーが後から登録した独自のプロバイダーが、デフォルトのプロバイダーよりも優先的に評価**されます。また、同一 `kind` のマルチプロバイダーを複数登録した場合も、後に登録したものほど優先して評価されます。
