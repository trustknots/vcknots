---
sidebar_position: 31
---

# アーキテクチャ概要

VC Knots は、Verifiable Credentials（VC）エコシステムを構築するためのプラガブルなフレームワークです。

VC エコシステムでは、OpenID4VCI / OpenID4VP などの標準プロトコルによる相互運用性が重要である一方、実際のシステム構成は用途や環境によって異なります。

例えば、利用するクラウド環境、ストレージ、鍵管理方式、Credential の発行ルールなどは、導入するシステムごとに異なる要件が存在します。

VC Knots では、このような差異を吸収するため、以下の拡張ポイントを提供しています。

- **Provider**
  - `issuer+verifier` 内部のコアロジックに対する拡張ポイントを提供します。
  - 鍵生成、Nonce 生成、識別子管理、Credential 発行ポリシーなど、システム固有のビジネスロジックを差し替え可能にします。

- **Infrastructure Integrations**
  - データストア、KMS など外部インフラへの接続を抽象化します。
  - AWS や Google Cloud など異なる実行環境へ柔軟に対応できます。


この設計により、OpenID4VCI / OpenID4VP などの標準プロトコル処理と、インフラ依存やシステム固有のビジネスロジックを分離できます。

また、Core Libraries を組み合わせることで Issuer、Wallet、Verifier を効率的に実装でき、Samples により利用方法や推奨されるデプロイ構成を確認できます。

# 全体構成

VC Knots には次のレイヤーが存在します。

| レイヤー      | 役割     |
| --- | --- |
| **App**   | VC Knots を利用して作成される Issuer・Wallet・Verifier のアプリケーションです。    |
| **Feature** | OpenID4VCI / OpenID4VP のプロトコルや Wallet 機能を提供します。 |
| **Infrastructure Integrations**      | データベースや KMS などの外部サービスとの接続を提供します。  |
| **Infrastructure** | データベース、ストレージ、鍵管理サービスなど、Infrastructure Integrations が接続する外部インフラです。  |

![overview](../../../../images/overview.drawio.svg)

# パッケージ構成

## Core Libraries / Infrastructure Integrations

| パッケージ    | 言語   | 役割   |
| --- | --- | --- |
| `vcknots`  | TypeScript | OpenID4VCI / OpenID4VP、Issuer、Verifier、Authorization Server の実装 |
| `wallet`        | Go  | Wallet 機能、DID・鍵管理、Credential の管理   |
| `aws`    | TypeScript | DynamoDB、KMS、Secrets Manager など AWS サービスとの連携を提供   |
| `google-cloud`    | TypeScript | Cloud Firestore、Cloud KMS、Secret Manager など Google Cloud サービスとの連携を提供    |


## Samples

| パッケージ  | 言語    | 役割  |
| --- | --- | --- |
| `server/core`  | TypeScript | サンプルサーバーで共通利用するフレームワークおよび共通コンポーネントを提供   |
| `server/single` | TypeScript | シングルテナント構成のサンプルサーバー   |
| `server/multi`  | TypeScript | マルチテナント構成のサンプルサーバー   |
| `server/aws`    | TypeScript | サンプルサーバーを AWS（Lambda + CDK）へデプロイするための構成例  |
| `server/google-cloud` | TypeScript | サンプルサーバーを Google Cloud へデプロイするための構成例  |
---

# Credential 発行フロー（OpenID4VCI）

Credential 発行（OpenID4VCI）の処理は、次の流れで実行されます。

1. Wallet は OpenID4VCI の認可・トークン取得を経て、Issuer に Credential Request を送信します。
2. Issuer は `vcknots` に Credential 発行処理を委譲します。
3. `vcknots` は Infrastructure Integrations を利用して、Credential の発行に必要なデータの取得や鍵管理サービスへのアクセスを行います。
4. `vcknots` は取得した情報を基に Verifiable Credential を生成・署名します。
5. 生成された Verifiable Credential が Wallet に返却されます。


```mermaid
sequenceDiagram

    participant wallet as App<br/>wallet
    participant issuer as App<br/>wallet
    participant vcknots as VC Knots<br/>Feature
    participant infra as VC Knots<br/>Infrastructure Integrations

    wallet->>issuer: Authz Request
    issuer->>vcknots: Process Authz Request
    vcknots-->>wallet: Authz Response

    wallet->>issuer: Token Request
    issuer->>vcknots: Issue Token
    vcknots-->>wallet: Token Response

    wallet->>issuer: Credential Request
    issuer->>vcknots: Issue Credential

    vcknots->>infra: Access Data<br/>Access Signing Key
    infra-->>vcknots: Result

    vcknots-->>wallet: Credential Response
```

# Presentation 検証フロー（OpenID4VP）

```mermaid
sequenceDiagram

    participant wallet as App<br/>wallet
    participant verifier as App<br/>verifier
    participant vcknots as VC Knots<br/>issuer+verifier

    verifier->>wallet: Authz Request

    wallet->>verifier: Authz Response<br/>(Verifiable Presentation)

    verifier->>vcknots: Validate Presentation

    vcknots->>vcknots: Resolve DID<br/>Validate Credential<br/>Verify Signature

    vcknots-->>verifier: Verification Result

    verifier-->>wallet: Accept / Reject
```

Presentation 検証（OpenID4VP）の処理は、次の流れで実行されます。

1. Verifier は Wallet に Authz Request を送信し、Presentation を要求します。
2. Wallet は Verifiable Presentation を含む Authz Response を Verifier に返却します。
3. Verifier は `vcknots` に Presentation の検証処理を委譲します。
4. `vcknots` は DID Resolver や Trust Registry を利用して DID を解決し、Presentation の署名や Credential の妥当性を検証します。
5. 検証結果が Verifier に返却され、Verifier は検証結果に基づいて Presentation を受け入れるかどうかを判断します。