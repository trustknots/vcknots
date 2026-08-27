---
sidebar_position: 44
---


# 04. Provider の選択

ここでは、変更したい処理に応じて、どの種類の `provider` を差し替え・追加すべきかを説明します。

## Provider kind 一覧

| 変更したいこと | provider kind |
| --- | --- |
| Issuerメタデータの保存・取得処理を変更したい | [`issuer-metadata-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20issuer-metadata-store-provider&type=code) |
| Authorization Serverメタデータの保存・取得処理を変更したい | [`authz-server-metadata-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-server-metadata-store-provider&type=code) |
| Verifierメタデータの保存・取得処理を変更したい | [`verifier-metadata-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verifier-metadata-store-provider&type=code) |
| OAuth Client 情報の保存・取得処理を変更したい | [`authz-oauth-client-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-oauth-client-store-provider&type=code) |
| OAuth Policy の保存・取得処理を変更したい | [`authz-oauth-policy-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-oauth-policy-store-provider&type=code) |
| Pre-Authorized Code の生成方法を変更したい | [`pre-authorized-code-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20pre-authorized-code-provider&type=code) |
| Pre-Authorized Code の保存・消費処理を変更したい | [`pre-authorized-code-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20pre-authorized-code-store-provider&type=code) |
| Access Token の payload 生成処理を変更したい | [`access-token-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20access-token-provider&type=code) |
| Access Token ごとに発行可能な `credential_configuration_id` を保存・取得したい | [`allowed-credential-configuration-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20allowed-credential-configuration-store-provider&type=code) |
| Credential Offer の生成処理を変更したい | [`credential-offer-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20credential-offer-provider&type=code) |
| `c_nonce` の生成方法を変更したい | [`nonce-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20nonce-provider&type=code) |
| `c_nonce` の保存・検証・失効・消費処理を変更したい | [`nonce-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20nonce-store-provider&type=code) |
| DPoP Proof JWT の検証処理を変更したい | [`dpop-proof-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20dpop-proof-provider&type=code) |
| DPoP Proof JWT の replay 防止に利用する `jti` の保存処理を変更したい | [`dpop-proof-jti-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20dpop-proof-jti-store-provider&type=code) |
| Client Assertion の replay 防止に利用する `jti` の保存処理を変更したい | [`oauth-client-assertion-jti-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20oauth-client-assertion-jti-store-provider&type=code) |
| Issuer の署名鍵の保存・取得・署名処理を変更したい | [`issuer-signature-key-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20issuer-signature-key-store-provider&type=code) |
| Authorization Server の署名鍵の保存・取得・署名処理を変更したい | [`authz-signature-key-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-signature-key-store-provider&type=code) |
| Verifier の署名鍵の保存・取得・署名処理を変更したい | [`verifier-signature-key-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verifier-signature-key-store-provider&type=code) |
| Issuer の署名鍵の生成方法を変更したい | [`issuer-signature-key-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20issuer-signature-key-provider&type=code) |
| Authorization Server の署名鍵の生成方法を変更したい | [`authz-signature-key-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-signature-key-provider&type=code) |
| Verifier の署名鍵の生成方法を変更したい | [`verifier-signature-key-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verifier-signature-key-provider&type=code) |
| JWT の署名検証処理を変更したい | [`jwt-signature-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20jwt-signature-provider&type=code) |
| DID method ごとの解決処理を追加・変更したい | [`did-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20did-provider&type=code) |
| Credential Request に含まれる proof の検証処理を追加・変更したい | [`credential-proof-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20credential-proof-provider&type=code) |
| Credential format ごとの発行処理を追加・変更したい | [`issue-credential-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20issue-credential-provider&type=code) |
| Verifiable Credential の検証処理を追加・変更したい | [`verify-verifiable-credential-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verify-verifiable-credential-provider&type=code) |
| Verifiable Presentation の検証処理を追加・変更したい | [`verify-verifiable-presentation-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verify-verifiable-presentation-provider&type=code) |
| Holder Binding の検証処理を変更したい | [`holder-binding-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20holder-binding-provider&type=code) |
| Credential Query の生成処理を追加・変更したい | [`credential-query-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20credential-query-provider&type=code) |
| Request Object の保存・取得・削除処理を変更したい | [`request-object-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20request-object-store-provider&type=code) |
| Request Object ID の生成方法を変更したい | [`request-object-id-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20request-object-id-provider&type=code) |
| Authorization Request の JAR 生成処理を追加・変更したい | [`authz-request-jar-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-request-jar-provider&type=code) |
| Verifier に紐づく証明書の保存・取得処理を変更したい | [`verifier-certificate-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verifier-certificate-store-provider&type=code) |
| 証明書の検証や、証明書から公開鍵を取得する処理を変更したい | [`certificate-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20certificate-provider&type=code) |
| Transaction Code の生成方法を変更したい | [`transaction-code-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20transaction-code-provider&type=code) |
| Transaction Data の生成方法を変更したい | [`transaction-data-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20transaction-data-provider&type=code) |
