---
sidebar_position: 42
---

# 02. Provider インターフェースの基本

VC Knots では、各種の機能モジュール（ストレージ, 鍵管理, DID 解決, 検証など）を疎結合に保ちつつ、柔軟に差し替え・拡張できるようにするために `provider` インターフェースを採用しています。

この章では、すべての `provider` に共通するコアプロパティと、 `provider` が登録・解決される際の優先順位の仕組みについて解説します。

---

## 1. Provider のコアプロパティ

VC Knots のすべての `provider` は、以下の 3 つの共通プロパティを持っています。

```ts
export type Provider = {
  kind: string
  name: string
  single: boolean
  // ... 各種 `provider` 固有のメソッドやプロパティ
}
```

### `kind` (string)
 `provider` の **種類（カテゴリ）** を表す一意の識別子です。
- 例: `'nonce-provider'`, `'did-provider'`, `'jwt-signature-provider'`
- VC Knots の内部処理は、この `kind` を指定して必要な `provider` を取得します。
- 各 `kind` ごとの用途については、[04. Provider の選択](./04-provider-type.md) を参照してください。

### `name` (string)
その `provider`  **実装の固有名** です。
- 例: `'in-memory-nonce-provider'`, `'aws-kms-signature-provider'`
- ログ出力やデバッグ、あるいは同一 `kind` の中から特定の `provider` を識別する目的などで利用されます。

### `single` (boolean)
同一の `kind` に対して、 **「1つだけしか有効にできない（Single）」** か、 **「複数共存できる（Multi）」** かを表します。

| `single` の値 | 区分 | 説明 | 代表的な例 |
| --- | --- | --- | --- |
| `true` | **Single Provider** | 同じ `kind` に対して 1 つだけ登録できます。ユーザーが新規 `provider` を登録すると、デフォルトの `provider` は **完全に上書き（置き換え）** されます。 | `nonce-provider`, `issuer-metadata-store-provider` |
| `false` | **Multi Provider** | 同じ `kind` の `provider` を複数登録して共存させることができます。どれを利用するかは、`canHandle(...)` メソッドなどを用いて動的に判断されます。 | `did-provider`, `issue-credential-provider` |

---

## 2.  provider の解決と優先評価順位

`single: false`（Multi Provider）の場合、デフォルトの `provider` とユーザーが登録した `provider` が共存します。このとき、VC Knots がどの `provider` を優先して選択するかのルールは、以下のようになっています。

### 優先評価のルール
VC Knots の `ProviderRegistry` に `provider` が登録される際、内部では以下のルールでマッピングが構築されます。

1. `single: true` の場合、既存の `provider` をフィルタリングして除外し、新しい `provider` で置き換えます。
2. `single: false` の場合、既存のリストに新しい `provider` を追加します。このとき、 **「後から登録された `provider` ほど、評価用配列の先頭（インデックス 0）に配置される」** （`[provider, ...current]`）ようになっています。

Multi Provider から適切な `provider` を選択する際、レジストリの `select(kind, value)` メソッドが呼び出されます。

```ts
// 例: "did:key:123" を解決できる did-provider を選択する
const didProvider = context.providers.select('did-provider', 'did:key:123')
```

`select` メソッドは、登録されている `provider` 配列を **先頭から順に走査** し、最初に `canHandle(value)` が `true` を返した `provider` を返します。

この仕組みにより、 **ユーザーが後から登録した独自の `provider` が、デフォルトの `provider` よりも優先的に評価** されます。また、同一 `kind` の Multi Provider を複数登録した場合も、後に登録したものほど優先して評価されます。
