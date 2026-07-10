---
sidebar_position: 5
---


# 01. 概要

## プラグインとは？

VC Knots の機能を拡張するための仕組みを指します。
ただし、本ライブラリではパッケージごとに拡張ポイントの呼び方が異なります。

### Issuer 機能 / Verifier 機能

`issuer+verifier` パッケージでは、拡張ポイントを `provider` と呼びます。
`provider` を差し替え・追加することで、ストレージ、鍵管理、DID Resolution、署名・検証などの処理を変更・追加することが可能です。
つまり `provider` を使うことで、VC Knots のコアロジックを変更せずに、周辺の実装だけの入れ替えや、対応範囲の拡張ができます。[03. Custom Provider の作成](./03-custom-provider.md) を参考にしてください

### Wallet 機能

Wallet 機能における拡張ポイントの詳細は、今後追加予定です。
