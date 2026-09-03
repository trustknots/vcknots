---
sidebar_position: 43
---

# 03. Custom Provider の作成

この章では、独自の `provider` を作成して VC Knots に組み込む方法を説明します。

基本的な流れは次のとおりです。

1. プロジェクトにVC Knotsを導入する
2. `provider` を実装する
3. `VcknotsOptions.providers` に登録する
4. テストで動作を確認する

ここでは、`single: true` と `single: false` の代表的な例を用いて、それぞれの利用方法を紹介します。

## Provider 作成の準備

VC Knotsを利用する(独自 `provider` を実装する)プロジェクトを作成し、VC Knotsをインストールします。

```bash
npm install @trustknots/vcknots
```

以下はディレクトリ構成例です。

```text
my-vcknots-plugin/
├── package.json
├── tsconfig.json
├── src/
│   ├── providers/
│   │   ├── timestamp-nonce.provider.ts // Single Provider の例で作成します
│   │   └── did-web.provider.ts  // Multi Provider の例で作成します
│   ├── index.ts
│   └── main.ts
└── test/
    ├── timestamp-nonce.provider.test.ts
    └── integration.test.ts
```

各ファイルの役割は次のとおりです。

| ファイル | 役割 |
|----------|------|
| `src/providers/` | 独自 `provider` の実装 |
| `src/index.ts` | 自身のプロジェクトを外部へ公開するエントリポイント |
| `src/main.ts` | `initializeContext()` を行い、実際に VC Knots の利用を準備する場所 |
| `test/` | Unit Test / Integration Test |

## Single Provider の例

`single: true` の provider は、同じ `kind` に対して 1 つだけ登録できます。

`VcknotsOptions.providers` に同じ `kind` の provider を登録すると、デフォルトの provider は新しい provider に置き換えられます。

### ユースケース

`nonce-provider` は、OID4VCI の `c_nonce` を生成する provider です。

例えば、生成する `c_nonce` にタイムスタンプを含めることで、外部データベースで時系列順にソートしやすい識別子を生成できます。

また、他にも外部の乱数生成器を利用したり、乱数アルゴリズムを社内標準へ変更したりする用途にも利用できます。

### 実装例

`timestamp-nonce.provider.ts`
```ts
import { randomUUID } from 'node:crypto'
import { Nonce } from '../nonce.types'
import { NonceProvider } from './provider.types'

const DEFAULT_NONCE_EXPIRES_IN_MS = 60 * 5 * 1000 // 5 minutes

export const timestampNonce = (): NonceProvider => {
  return {
    kind: 'nonce-provider',
    name: 'timestamp-nonce-provider',
    single: true,

    async generate(options?: { nonce_expires_in?: number }): Promise<Nonce> {
      const timestamp = Date.now()
      const uuid = randomUUID().replaceAll('-', '')

      return Nonce({
        nonce: `${timestamp}-${uuid}`,
        nonce_expires_in:
          options?.nonce_expires_in ?? DEFAULT_NONCE_EXPIRES_IN_MS,
      })
    },
  }
}
```

登録例の詳細は [Issuer機能のセットアップと使用方法](../issuer.md) を参考にしてください。

### 登録例

`main.ts`
```ts
import { initializeContext } from '@trustknots/vcknots'

const context = initializeContext({
  providers: [
    timestampNonce(),
  ],
})
```

登録後は、デフォルトの `nonce-provider` の代わりに、この provider が利用されます。

## Multi Provider の例

`single: false` の provider は、同じ `kind` の provider を複数登録できます。

追加した provider はデフォルトの provider を置き換えるのではなく、デフォルト provider と共存します。

同一 `kind` の provider の選択時には、後から登録した provider ほど優先して評価されます。条件に一致しない場合はデフォルト provider が利用されます。

### ユースケース

`did-provider` は、デフォルトでは `did:key` の DID 解決に対応しています。provider を追加することで `did:web` などの DID Method を解決できるようになります。

デフォルトの `did-provider` を削除する必要はなく、対応可能な方式を追加する用途に適しています。

独自の処理を提供したい場合は、Multi Provider においても Single Provider と同様にインターフェースに従って provider を作成し、 `VcknotsOptions.providers` へ登録してください。

### 実装例

`did-web.provider.ts`
```ts
import { DidDocument } from '../did.types'
import { DidProvider } from './provider.types'


export const didWeb = (): DidProvider => {
  return {
    kind: 'did-provider',
    name: 'did-web-provider',
    single: false,

    async resolveDid(did: string): Promise<DidDocument | null> {
        // did:web から取得先URLを組み立ててDID Documentを取得する処理を実装する
        const response = await fetch(
          `https://example.com`
        )
      
        const document = await response.json()

        // 取得した DID document のバリデーションを実装する

        return document as DidDocument
      }

    canHandle(method: string): boolean {
      return method === 'web'
    },
  }
}
```

### 登録例

`main.ts`
```ts
import { initializeContext } from '@trustknots/vcknots'

const context = initializeContext({
  providers: [
    didWeb(),
  ],
})
```

## Provider 間の協調動作

provider は、他の provider と協調して動作することができます。

VC Knots の `ProviderRegistry` は、登録された provider インスタンスが `providers` プロパティを持っている場合、自動的に自身（`ProviderRegistry`）をそのプロパティに注入します。

これにより、独自 provider の内部から、他の登録済み provider （例: `did-provider` や `jwt-signature-provider`）を簡単に取得して利用することができます。

### 実装パターン

他 provider との連携が必要な独自 provider を実装する場合、以下のように `withProviderRegistry` を展開（スプレッド）したファクトリ関数として実装することを推奨します。

```ts
import {
  WithProviderRegistry,
  withProviderRegistry,
  selectProvider,
} from '@trustknots/vcknots'

// ファクトリ関数形式で定義
export const myCustomProvider = (): MyCustomProvider & WithProviderRegistry => {
  return {
    ...withProviderRegistry, // 自動注入される providers のプレースホルダーを展開

    kind: 'some-custom-provider',
    name: 'my-custom-provider',
    single: true,

    async doSomething() {
      // 注入された providers から、別の provider （例: DID 解決 provider ）を取得する
      const didProvider = selectProvider(
        this.providers.get('did-provider'),
        'key'
      )
      const didDocument = await didProvider.resolveDid('did:example:123')

      // 取得した他の provider と連携して処理を行う
      // ...
    }
  }
}
```

このパターンを使用することで、型安全に自動注入される `providers` の初期値を定義しつつ、他の provider （例: DID 解決や鍵管理）と疎結合に協調動作させることができます。
ProviderRegistry の詳細については [05. ProviderRegistry の役割と仕組み](./05-provider-registry.md) を参照してください。

## テスト

独自 provider を作成した場合は、provider の Unit Test と Integration Test の両方を実施することを推奨します。

### Unit Test

provider が期待どおりの値を返すことや、異常系を含めた provider 単体のロジックを確認します。

### Integration Test

provider を VC Knots に登録し、Issuer や Verifier のフローの中で期待どおりに利用されることを確認します。