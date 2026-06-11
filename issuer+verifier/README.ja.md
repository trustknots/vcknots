# @trustknots/vcknots

OpenID for Verifiable Credential Issuance (OID4VCI) 1.0 および OpenID for Verifiable Presentations (OID4VP) Draft 24 を実装するための柔軟で拡張可能なライブラリです。

このパッケージは Issuer と Verifier の両方のコアロジックを提供し、準拠した SSI（Self-Sovereign Identity）アプリケーションの構築を可能にします。プロバイダーベースのアーキテクチャで設計されており、ストレージ、鍵管理、その他のインフラ依存関係の実装を簡単に差し替えることができます。

## 機能

*   **OID4VCI (Issuer):**
    *   Issuer メタデータの管理
    *   クレデンシャルオファーの作成（事前認可コードフロー）
    *   検証可能クレデンシャルの発行（JWT-VC 形式）
    *   c_nonce 管理のための nonce エンドポイントのサポート
    *   DPoP Proof 検証、DPoP nonce、DPoP-bound access token のサポート
    *   リゾルバーによる `did:key` およびその他の DID メソッドのサポート
*   **OID4VP (Verifier):**
    *   Verifier メタデータの管理
    *   認可リクエストの作成（JAR - Signed Request Objects）
    *   検証可能プレゼンテーションの検証（VP Token）
    *   Presentation Exchange および DCQL のサポート（近日対応予定）
*   **拡張可能なアーキテクチャ:**
    *   すべての外部依存関係（データベース、鍵管理、DID リゾルバー）は「プロバイダー」として抽象化されています
    *   迅速なプロトタイピングとテストのためのデフォルトのインメモリ実装を同梱しています

## インストール

```bash
npm install @trustknots/vcknots
# または
pnpm add @trustknots/vcknots
# または
yarn add @trustknots/vcknots
```

## クイックスタート

最も簡単な始め方は、メタデータ、鍵、セッションデータにインメモリストレージを使用するデフォルト設定を使うことです。

```typescript
import { vcknots } from '@trustknots/vcknots'

// デフォルト（インメモリ）プロバイダーで初期化
const { issuer, verifier } = vcknots()
```

## チュートリアル

このライブラリの使い方のステップバイステップガイドについては、ドキュメントを参照してください: [https://trustknots.github.io/vcknots/](https://trustknots.github.io/vcknots/)

## 使い方

Issuer と Verifier の両方のフローに関する包括的な例と詳細な設定については、[`server/single`](https://github.com/trustknots/vcknots/tree/main/server/single) または [`server/multi`](https://github.com/trustknots/vcknots/tree/main/server/multi) ディレクトリにあるサンプル実装を参照してください。

### Issuer フロー

#### 1. Issuer メタデータと鍵のセットアップ
まず、Issuer のメタデータを定義し、署名鍵を生成します。

```typescript
const base = 'https://myissuer.example.com'
const issuerId = CredentialIssuer(base)

// メタデータの定義（簡略化した例）
const metadata: CredentialIssuerMetadata = {
  credential_issuer: issuerId,
  authorization_servers: [base],
  credential_endpoint: `${base}/credentials`,
  credential_configurations_supported: {
    'MyCredential': {
      format: 'jwt_vc_json',
      credential_definition: { type: ['VerifiableCredential', 'MyCredential'] },
      credential_signing_alg_values_supported: ['ES256'],
      proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } }
    }
  }
}

// メタデータを保存し、設定されたストアに鍵を生成・保存します
await issuer.createIssuerMetadata(metadata)
```

#### 2. クレデンシャルオファーの作成
Wallet に送信するクレデンシャルオファーを生成します。

```typescript
const offer = await issuer.offerCredential(issuerId, ['MyCredential'])
const encoded = encodeURIComponent(JSON.stringify(offer))
const scheme = `openid-credential-offer://?credential_offer=${encoded}`
console.log('Credential Offer:', scheme)
```

#### 3. クレデンシャルの発行
Wallet がクレデンシャルリクエストを送信した場合（オファーを処理した後）、クレデンシャルを発行します。

```typescript
// `req` は Wallet から送信された HTTP リクエストを表します
const request = CredentialRequest(req.json() /* ボディを JSON として取得 */)
const credential = await issuer.issueCredential(
  issuerId,
  request, 
  {
    alg: 'ES256',
    claims: {
      name: 'Alice',
      from: 'Wonderland'
    },
    // JWT proof（`proofs.jwt`）検証用。usePreAuth は grant type が pre-authorized_code かどうかを表します。
    // anonymous access token の場合は clientId を省略し、登録済み client の access token の場合は clientId を渡します。
    proofJwt: { usePreAuth: true },
  }
)

console.log('Issued Credential:', credential)
```

**JWT クレデンシャルプルーフ（`proofs.jwt`）と `options.proofJwt`**

OID4VCI の JWT proof では、`aud` は Credential Issuer Identifier と一致し、`iss` はフローと access token の取得方法に応じて扱われます。`issueCredential` は内部で `credential-proof-provider` の `verifyProof` に **検証コンテキスト**（Credential Issuer、事前認可コードグラントかどうか、必要なら OAuth `client_id`）を渡すため、JWT proof を検証するときは次の `options.proofJwt` を実際のトークン取得フローに合わせて指定してください。

`usePreAuth` は grant type が `pre-authorized_code` かどうかを表します。anonymous access かどうかは `clientId` の有無で表します。

| 状況 | 指定の目安 |
|------|------------|
| アクセストークンが **事前認可コード（Pre-Authorized Code）** グラント、かつ token endpoint で anonymous access により得られた場合 | `proofJwt: { usePreAuth: true }`。access token に `client_id` がないため、proof JWT に **`iss` は含めません**。 |
| アクセストークンが **事前認可コード（Pre-Authorized Code）** グラント、かつ登録済み OAuth client として得られた場合 | `proofJwt: { usePreAuth: true, clientId: '<access token の client_id>' }`。proof JWT に `iss` がある場合は、その `clientId` と一致する必要があります。`iss` の省略も許容されます。 |
| **認可コード** 等、通常の OAuth クライアント文脈の場合 | `proofJwt: { usePreAuth: false, clientId: '<そのリクエストの client_id>' }`。`iss` はその `client_id` または Credential Issuer Identifier と一致する必要があります。 |

`proofJwt` を誤ると `aud` / `iss` の検証が意図とずれ、`invalid_proof` となります。

#### 4. Nonce 管理（オプション）

OID4VCI の [nonce endpoint](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint) を使用する場合、Wallet はクレデンシャルリクエストを送信する前に `c_nonce` を取得できます。複数のクレデンシャルをリクエストする際に便利です。同一の nonce を有効期限内で再利用できます。

HTTP サーバー実装で DPoP 用 nonce を返したい場合は、Authorization Server の OAuth policy store で DPoP mode を管理します。サーバー実装側でこの policy を参照すると、`POST /nonce` の JSON ボディ `c_nonce` に加えて、レスポンスヘッダー `DPoP-Nonce` を返すかどうかを制御できます。`c_nonce` と `DPoP-Nonce` は別の値です。実装例は [server/core/src/routes/issue.ts](../server/core/src/routes/issue.ts) を参照してください。

Issuer メタデータに `nonce_endpoint` を設定してください:

```typescript
const metadata: CredentialIssuerMetadata = {
  credential_issuer: issuerId,
  credential_endpoint: `${base}/credentials`,
  nonce_endpoint: `${base}/nonce`,  // オプション: nonce エンドポイントを有効化
  // ... その他のメタデータ
}
```

**nonce の作成**（例: `POST /nonce` 用）:

```typescript
const NONCE_TTL_MS = 2 * 60 * 1000  // 2分
const cnonce = await issuer.createNonce(NONCE_TTL_MS)
// 戻り値: string（例: "3ccc7973abef4102ad70a871e200304b"）
```

**nonce の検証**（例: `GET /nonce/:nonce` または proof の検証時）:

```typescript
const valid = await issuer.validateNonce(nonce)
// 戻り値: boolean
```

**nonce の取り消し**（例: `DELETE /nonce/:nonce` 用）:

```typescript
const deleted = await issuer.revokeNonce(nonce)
// 戻り値: boolean（取り消し成功時 true、nonce が見つからない場合 false）
```

**DPoP nonce の消費**（例: token endpoint の DPoP Proof 検証時）:

```typescript
const consumed = await nonceStore.consume(nonce)
// 戻り値: boolean（存在し、有効期限内で、消費に成功した場合 true）
```

DPoP Proof の `nonce` は replay を避けるため、検証時に一度だけ消費します。Credential proof 用の `c_nonce` は複数 credential 取得で再利用できる一方、DPoP Proof 用 nonce は token request の Proof に紐づく値として扱います。

#### 5. DPoP Proof と DPoP-bound access token

token endpoint 実装では、HTTP リクエストの `DPoP` ヘッダーから取得した Proof JWT を `createAccessToken` に渡すことで、DPoP Proof の検証と DPoP-bound access token の発行を行えます。

```typescript
const accessToken = await authz.createAccessToken(issuer, tokenRequest, {
  dpopProof: {
    proofJwt,
    htm: 'POST',
    htu: `${base}/token`,
    nonceRequired: true,
  },
})
```

DPoP Proof の検証では、`typ: dpop+jwt`、非対称署名アルゴリズム、JOSE ヘッダーの公開鍵 `jwk`、署名、`jti` / `iat` / `htm` / `htu`、nonce を確認します。`jti` は `dpop-proof-jti-store-provider` に保存し、同じ公開鍵 thumbprint と `jti` の組み合わせが再利用された場合は拒否します。

検証に成功した場合、レスポンスの `token_type` は `DPoP` になり、access token の payload には DPoP Proof の公開鍵に対応する JWK Thumbprint が `cnf.jkt` として含まれます。

```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 86400
}
```

### Verifier フロー

#### 1. Verifier メタデータのセットアップ
Verifier の識別情報を初期化します。

```typescript
const base = 'https://myverifier.example.com'
const verifierId = VerifierClientId(base)
const metadata: VerifierMetadata = {
	client_name: 'MyVerifier',
	client_uri: base,
	vp_formats: {
		jwt_vp: {
			alg: ['ES256']
		}
	},
	client_id_scheme: 'redirect_uri'
}

// Verifier 用の署名鍵を生成します（JAR 用）
await verifier.createVerifierMetadata(verifierId, metadata)
```

#### 2. 認可リクエストの作成
Wallet が何かを証明するためのリクエスト（通常は QR コードに変換）を作成します。

```typescript
const base = 'https://myverifier.example.com'
const verifierId = VerifierClientId(base)
const request = await verifier.createAuthzRequest(
  verifierId,
  'vp_token',
  `redirect_uri:${base}`, // client_id
  'direct_post',
  {
    // Presentation Exchange Definition
    presentation_definition: {
      id: 'request',
      input_descriptors: [{
        id: 'id-card',
        constraints: { fields: [{ path: ['$.vc.type'], filter: { type: 'string', pattern: 'MyCredential' } }] }
      }]
    }
  },
  false, // use request_uri (JAR)
  { base_url: base }
)

// 認可リクエストオブジェクトをエンコード
const encoded = Object.entries(request)
  .map(([key, value]) => {
    const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
    return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
  })
  .join('&')

const scheme = `openid4vp://authorize?${encoded}`

console.log('Authorization Request', scheme)
```

#### 3. プレゼンテーションの検証
Wallet から送信されたレスポンスを検証します。

```typescript
// req は Wallet が送信した HTTP リクエストを表します
const response = VerifierAuthorizationResponse(req.json())
await verifier.verifyPresentations(verifierId, response)
console.log('Verification Successful!')
```

## 設定とプロバイダー

永続ストレージ（Redis、PostgreSQL など）や外部 KMS を使用するには、デフォルトのプロバイダーをオーバーライドできます。

```typescript
import { vcknots, Provider } from '@trustknots/vcknots'

const customMetadataStore: IssuerMetadataStoreProvider = {
  kind: 'issuer-metadata-store-provider',
  single: true,
  fetch(issuer) { ... },
  save(metadata) { ... },
}

const { issuer } = vcknots({
  providers: [
    customMetadataStore,
    // ... その他のカスタムプロバイダー
  ]
})
```

## 開発とテスト

ユニットテストを実行するには:

```bash
pnpm test
```

統合テストを実行するには:

```bash
pnpm it
```

## 関連プロジェクト

* **Wallet 実装:** OID4VC Wallet のリファレンス実装については、このリポジトリのルートにある [`wallet`](https://github.com/trustknots/vcknots/tree/main/wallet) ディレクトリを参照してください。
* **サーバーサンプル:** [`server/single`](https://github.com/trustknots/vcknots/tree/main/server/single) および [`server/multi`](https://github.com/trustknots/vcknots/tree/main/server/multi) ディレクトリに、Issuer と Verifier のサンプル実装があります。

## コントリビューション

コントリビューションを歓迎します！詳細については [CONTRIBUTING.md](https://github.com/trustknots/vcknots/tree/main/CONTRIBUTING.md) をご覧ください。

## ライセンス

[Apache-2.0](https://github.com/trustknots/vcknots/blob/main/LICENSE)
