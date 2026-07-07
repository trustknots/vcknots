---
sidebar_position: 10
---

# 05. ProviderRegistry の役割と仕組み

VC Knots のプラグインアーキテクチャの中核を担うのが `ProviderRegistry` です。単に `provider` を保持するだけの入れ物ではなく、初期化時のマージ処理、依存性注入 (DI) の自動解決、および AOP (アスペクト指向プログラミング) 的な拡張機能 (Extension) の織り込み (Weaving) を動的に行う「心臓部」として機能しています。

この章では、`ProviderRegistry` が内部で `provider` をどのように処理・調停しているのか、そのシステム設計と仕様について詳しく解説します。

---

## 1. 初期化とマージの仕様

VC Knots のコンテキスト初期化時 (`initializeContext`)、内部ではデフォルトの `provider` 群と、ユーザーが `options.providers` で渡したカスタム `provider` がマージされ、1つの統合された `ProviderRegistry` が構築されます。

マージは以下の 2 段階のロジック仕様に基づいて実行されます。

### 1. フラット化と Single Provider の上書き
すべてのデフォルト `provider` とユーザー定義 `provider` が、単一のリストへと統合されます。
- `single: true` (シングル `provider` ) : 同じ `kind` の `provider` が既に存在している場合、後から登録された `provider` で **完全に上書き（置き換え）** されます。
- `single: false` (マルチ `provider` ) : 既存の `provider` と競合せず、すべてが同一のリスト内に保持（共存）されます。

### 2. インデックス化と Multi Provider の優先順位の決定
共存可能なマルチ `provider` について、VC Knots がどの `provider` を優先して選択するかの「評価順位」がここで決定されます。
- 新しくマージされる（＝後からユーザーによって登録された） `provider` ほど、 **解決用リストの先頭に配置** されます。
- これにより、システム内部で解決を試みる際、自動的に「後から登録されたカスタム実装がデフォルト実装より優先して評価される」という **「後勝ち」** の優先ルールが成立します。

---

## 2. ProviderRegistry のメソッド

`ProviderRegistry` は、主に以下の 2 つのインターフェースを外部（および `provider` 同士）へ提供します。

### `get(kind)`
指定した `kind` の `provider` を取得します。
- Single Provider  (`single: true`) の場合: 登録されている唯一の `provider` インスタンスを 1 つ返します。
- Multi Provider  (`single: false`) の場合: 優先評価順（後勝ちルールでソートされた順）に並んだ `provider` の配列を返します。

### `select(kind, value)`
Multi Provider の中から、特定の条件 (`value`) を処理できる最適な `provider` を 1 つだけ動的に解決して返します。

#### 動的解決のフロー
1. 指定された `kind` のマルチ `provider` 配列（優先評価順）を取得します。
2. 配列の先頭から順に走査し、各 `provider` の `canHandle(value)` メソッドを呼び出します。
3. 最初に `true` を返した `provider` を、最適な解決先として返却します。
4. どの `provider` も `canHandle(value)` で `true` を返さなかった場合は、解決不可エラーを発生させます。

この仕組みにより、ユーザーが定義したカスタム `provider` が最優先で評価され、特定のケースのみカスタム処理に流し、それ以外はデフォルト `provider` にフォールバックさせる、といった高度な条件分岐が自動的に機能します。

---

## 3. 依存性注入と遅延解決

 `provider` 同士が協調して動作する際、手動で依存関係を結合するような配線コードを書く必要はありません。`ProviderRegistry` が、 `provider` を仲介する際に依存性を自動で注入します。

### `withProviderRegistry` ヘルパー
 `provider` が `ProviderRegistry` による自動注入の対象であることを示すために、 VC Knots は `withProviderRegistry` というヘルパーオブジェクトを提供しています。

カスタム `provider` を実装する際は、以下のように `withProviderRegistry` をオブジェクトに展開して定義し、`WithProviderRegistry` 型との積をとります。

```ts
import { WithProviderRegistry, withProviderRegistry } from '@trustknots/vcknots'

export const customProvider = (): MyProvider & WithProviderRegistry => {
  return {
    ...withProviderRegistry, // providers プレースホルダーを展開
    kind: 'my-provider',
    name: 'custom-provider',
    single: true,
    // ...
  }
}
```

### 自動注入の挙動
`ProviderRegistry` の API（`get` や `select`）を介して `provider` が **取り出される時** に、以下の解決処理が実行されます。

- 取得される `provider` オブジェクトが `providers` プロパティ（`withProviderRegistry` によって提供されたプレースホルダー）を保持しているかを判定します。
- 保持している場合、 `ProviderRegistry` 自身（`this`）の参照をそのプロパティへ動的にセットします。

この設計には以下の技術的なメリットがあります。
1. **循環参照の回避**:  `provider` A が `provider` B を参照し、 `provider` B も `provider` A を参照するような相互依存がある場合でも、初期化順序の競合を発生させずに安全に解決できます。
2. **遅延解決** : 他の `provider` が必要になった瞬間に `ProviderRegistry` を経由して取得するため、無駄な初期化コストがなく、 `provider` が動的に差し替えられた場合でも、常に最新の有効なインスタンスを安全に取得・参照できます。

これにより、 `provider` 内部の実装からは、単に `this.providers.get('other-provider')` や `this.providers.select(...)` と記述するだけで、他のあらゆる `provider` の機能を自由に、かつ安全に呼び出せます。

---

## 4. Extension の織り込み

VC Knots には、 `provider` のソースコードを一切変更することなく、メソッドの呼び出し前後で横断的な共通処理（ロギング、エラーハンドリング、監査ログ、処理時間計測など）を注入できる **`Extension`（拡張機能）** の仕組みがあります。

`ProviderRegistry` は、 `provider` を外部に返却する最終フェーズで、この Extension の織り込み（Weaving）を実行します。

### 具体例で見る Weaving の仕組み
Issuer メタデータを取得した際にログに記録する `traceFetchedIssuerMetadata` 拡張機能を例に、Weaving がどのように行われるかを見てみましょう。

```ts
import { CredentialIssuer, CredentialIssuerMetadata } from '../credential-issuer.types'
import { Extension } from './extension.types'

export const traceFetchedIssuerzMetadata = (): Extension<
  CredentialIssuer,
  Promise<CredentialIssuerMetadata | null>
> => {
  return {
    // 1. フック対象の `provider` とメソッドを、文字列で指定
    on: 'issuer-store-metadata-provider.fetch',

    // 2. 割り込ませるインターセプト（横断）ロジックを定義
    async intercept(original, xs) {
      // 元の `provider` メソッド (original) を実行
      const issuer = await original(xs)

      // 発行者が取得できた場合、JSON ログを出力する (横断関心事)
      if (issuer) {
        console.log(JSON.stringify(issuer, null, '\t'))
      }

      return issuer
    },
  }
}
```

この拡張機能がコンテキストに登録されると、`ProviderRegistry` の内部で Weaving が以下のように自動処理されます。

1. **取得フックの監視**:
   利用者が `context.providers.get('issuer-store-metadata-provider')` を呼び出して `provider` を取得する際、 `ProviderRegistry` は登録されている `Extension` を走査します。
2. **Proxy / ラッパーの動的生成 (Weaving)**:
   `on: 'issuer-store-metadata-provider.fetch'` にマッチする拡張機能（上記）が存在するため、 `ProviderRegistry` は元の `provider` オブジェクトをそのまま返すのではなく、`fetch` メソッドを `intercept` ロジックでラップした動的なラッパー（Proxy）を生成して返却します。
3. **透過的な実行**:
   利用者が `provider` の `fetch(...)` を実行すると、自動的に Extension の `intercept` メソッドが呼ばれ、その内部で元の処理が安全に実行されたのち、JSONログが出力されます。

### 開発者にとってのメリット (関心事の分離)
この Weaving 機構のおかげで、 `provider` を開発する側も利用する側も、拡張機能の存在や適用ロジックをコード内に意識して記述する必要がありません。

- ** `provider` 開発者**: ログ出力、例外監視、パフォーマンス測定などの「横断的関心事」を、 `provider` のロジック内に記述する必要がありません。純粋な機能実装（DID解決やメタデータストアなど）のみに集中できます。
- ** `provider` 利用者**: 通常通りのインターフェースを介して `provider` を呼び出すだけで、定義されたすべての共通機能（セキュリティ監査や監視など）が自動的に、かつ透過的に適用されます。
