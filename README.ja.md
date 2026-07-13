# VC Knots

<h3 align="center">Verifiable Credentials エコシステム構築のためのプラッガブルなフレームワーク</h3>

## 概要

VCKnots は、Verifiable Credentials エコシステムの開発をサポートするオープンソースライブラリです。OID4VCI（OpenID for Verifiable Credential Issuance）と OID4VP（OpenID for Verifiable Presentations）の実装を提供し、識別子や鍵の管理など、ウォレットのコア機能をサポートします。

データシリアライズフォーマット、プロトコルフレーバー、暗号アルゴリズムなどの可変点をプラグイン方式で拡張できる設計になっています。

**主な特徴:**
- OID4VCI と OID4VP の実装
- ウォレットコア機能（識別子・鍵管理）
- Pluggable Architecture（フォーマット、プロトコル、アルゴリズムを拡張可能）

## はじめに

目的に応じて、以下のドキュメントからお読みください。

| 目的 | ドキュメント |
| --- | --- |
| VCKnotsの使い方を確認したい | [ユーザードキュメント](https://trustknots.github.io/vcknots/ja/) |
| Issuerを構築したい | [Issuerガイド](https://trustknots.github.io/vcknots/ja/docs/issuer) |
| Walletを実装したい | [Walletガイド](https://trustknots.github.io/vcknots/ja/docs/wallet) |
| Verifierを構築したい | [Verifierガイド](https://trustknots.github.io/vcknots/ja/docs/verifier) |
| OID4VCI / OID4VPの対応状況を確認したい | [サポートマトリクス](https://trustknots.github.io/vcknots/ja/docs/support-matrix) |
| サンプルサーバーを動かしたい | [Single Server README](./server/single/README.ja.md) |

## インストール

```bash
# TypeScript
npm install @trustknots/vcknots

# Go
go get github.com/trustknots/vcknots/wallet
```

## リポジトリ構成

```
vcknots/
├── issuer+verifier/    # @trustknots/vcknots (TypeScript)
│                       # Issuer、Verifier、Authorization Server 用のライブラリ
├── wallet/             # Wallet ライブラリ (Go)
│                       # Credential の受信・保管・提示、識別子・鍵管理機能
├── aws/                # @trustknots/aws (TypeScript)
│                       # AWS プロバイダー (DynamoDB、KMS、Secrets Manager)
└── server/             # サンプルサーバー実装 (TypeScript)
    ├── single/         # @trustknots/server-single — シングルテナントサーバー
    ├── google-cloud/   # @trustknots/server-google-cloud — Google Cloud 統合
    └── aws/            # @trustknots/server-aws — AWS Lambda ハンドラー + CDK スタック
```

## コントリビューション

バグ修正から新機能追加まで、あらゆる貢献を歓迎します。

詳しくは [CONTRIBUTING.md](./CONTRIBUTING.md) と [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) を参照してください。

## ライセンス

[Apache License 2.0](./LICENSE)

## 連絡先

このプロジェクトは、Trust Knots プロジェクトの一環として、有志の個人メンバーで構成された VCKnots Project Team によって管理されています。

- **バグ報告や機能リクエストなど　VCKnots　ソフトウェアに関すること**: [GitHub Issues](https://github.com/trustknots/vcknots/issues)
- **一般的な問い合わせ**: vcknots@googlegroups.com
