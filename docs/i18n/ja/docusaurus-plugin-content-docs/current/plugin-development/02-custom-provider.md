---
sidebar_position: 6
---

# 02. Custom Provider の作成

この章では、独自の `provider` を作成して VCKnots に組み込む方法を説明します。

基本的な流れは次のとおりです。

1. `provider` を実装する
2. `VcknotsOptions.providers` に登録する
3. テストで動作を確認する

ここでは、`single: true` と `single: false` の代表的な例を用いて、それぞれの利用方法を紹介します。

## Single Provider の例

`single: true` の provider は、同じ `kind` に対して 1 つだけ登録できます。

`VcknotsOptions.providers` に同じ `kind` の provider を登録すると、デフォルトの provider は新しい provider に置き換えられます。

### ユースケース

`nonce-provider` は、OID4VCI の `c_nonce` を生成する provider です。

例えば、生成する `c_nonce` にタイムスタンプを含めることで、外部データベースで時系列順にソートしやすい識別子を生成できます。

また、他にも外部の乱数生成器を利用したり、乱数アルゴリズムを社内標準へ変更したりする用途にも利用できます。

### 実装例

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

### 登録例

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

`issuer-signature-key-provider` は、Credential 発行時に利用する署名鍵を生成する provider です。

デフォルトでは ES256 の署名鍵生成に対応しています。provider を追加することで ES384 や EdDSA など別のアルゴリズムを利用できるようになります。

デフォルトの ES256 を削除する必要はなく、利用可能なアルゴリズムを追加する用途に適しています。

利用したいアルゴリズムに対して `issuer-signature-key-provider` のデフォルト実装で対応できる場合、引数にアルゴリズム名を指定することで、そのアルゴリズムに対応した provider を登録できます。

なお、利用したいアルゴリズムそれぞれに対応する provider は事前にすべて `VcknotsOptions.providers` へ登録する必要があります。

独自の鍵生成処理を提供したい場合は、Single Provider の例と同様に、インターフェースに従って provider を作成し、 `VcknotsOptions.providers` へ登録してください。

### 登録例

```ts
import { initializeContext } from '@trustknots/vcknots'

const context = initializeContext({
  providers: [
    issuerSignatureKey({ alg: "ES384" }),
    issuerSignatureKey({ alg: "EdDSA" }),
  ],
})
```

## プロバイダー間の協調動作

プロバイダーは、他のプロバイダーと協調して動作することができます。

VCKnots のプロバイダーレジストリ（`ProviderRegistry`）は、登録されたプロバイダーインスタンスが `providers` プロパティを持っている場合、自動的に自身（`ProviderRegistry`）をそのプロパティに注入します。

これにより、独自プロバイダーの内部から、他の登録済みプロバイダー（例: `did-provider` や `jwt-signature-provider`）を簡単に取得して利用することができます。

### 実装パターン

他プロバイダーとの連携が必要な独自プロバイダーを実装する場合、以下のように `withProviderRegistry` を展開（スプレッド）したファクトリ関数として実装することを推奨します。

```ts
import {
  ProviderRegistry,
  WithProviderRegistry,
  withProviderRegistry,
} from '@trustknots/vcknots'

// ファクトリ関数形式で定義
export const myCustomProvider = (): MyCustomProvider & WithProviderRegistry => {
  return {
    ...withProviderRegistry, // 自動注入される providers のプレースホルダーを展開

    kind: 'some-custom-provider',
    name: 'my-custom-provider',
    single: true,

    async doSomething() {
      // 注入された providers から、別のプロバイダー（例: DID 解決プロバイダー）を取得する
      const didProvider = this.providers.get('did-provider')
      const didDocument = await didProvider.resolveDid('did:example:123')

      // 取得した他のプロバイダーと連携して処理を行う
      // ...
    }
  }
}
```

このパターンを使用することで、型安全に自動注入される `providers` の初期値を定義しつつ、他のプロバイダー（例: DID 解決や鍵管理）と疎結合に協調動作させることができます。
ProviderRegistry の詳細については [05. ProviderRegistry の役割と仕組み](./05-provider-registry.md) を参照してください。

## テスト

独自 provider を作成した場合は、provider の Unit Test と Integration Test の両方を実施することを推奨します。

### Unit Test

provider が期待どおりの値を返すことや、異常系を含めた provider 単体のロジックを確認します。

### Integration Test

provider を VCKnots に登録し、Issuer や Verifier の処理の中で期待どおりに利用されることを確認します。