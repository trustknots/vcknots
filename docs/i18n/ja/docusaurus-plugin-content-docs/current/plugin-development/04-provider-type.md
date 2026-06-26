---
sidebar_position: 8
---


# 04. Provider の選択

ここでは、変更したい処理に応じて、どの種類の `provider` を差し替え・追加すべきかを説明します。

VCKnots の `provider` は、用途ごとに `kind` が定義されています。
たとえば、Credential の発行処理を変更したい場合は `issue-credential-provider`、DID method を追加したい場合は `did-provider` のように、目的に応じた `kind` の provider を選択します。

なお、`kind` は provider の用途を表す分類であり、`provider` を常に一意に識別するものではありません。
同じ `kind` の provider を複数登録できる場合もあります。その場合は `canHandle(...)` などによって適切な provider が選択されます。

## Provider kind 一覧

| 変更したいこと | provider kind |
| --- | --- |
| Issuer Metadata の保存・取得処理を変更したい | `issuer-metadata-store-provider` |
| Authorization Server Metadata の保存・取得処理を変更したい | `authz-server-metadata-store-provider` |
| Verifier Metadata の保存・取得処理を変更したい | `verifier-metadata-store-provider` |
| OAuth Client 情報の保存・取得処理を変更したい | `authz-oauth-client-store-provider` |
| OAuth Policy の保存・取得処理を変更したい | `authz-oauth-policy-store-provider` |
| Pre-Authorized Code の生成方法を変更したい | `pre-authorized-code-provider` |
| Pre-Authorized Code の保存・消費処理を変更したい | `pre-authorized-code-store-provider` |
| Access Token の payload 生成処理を変更したい | `access-token-provider` |
| Access Token ごとに発行可能な `credential_configuration_id` を保存・取得したい | `allowed-credential-configuration-store-provider` |
| Credential Offer の生成処理を変更したい | `credential-offer-provider` |
| `c_nonce` の生成方法を変更したい | `nonce-provider` |
| `c_nonce` の保存・検証・失効・消費処理を変更したい | `nonce-store-provider` |
| DPoP Proof JWT の検証処理を変更したい | `dpop-proof-provider` |
| DPoP Proof JWT の replay 防止に利用する `jti` の保存処理を変更したい | `dpop-proof-jti-store-provider` |
| Client Assertion の replay 防止に利用する `jti` の保存処理を変更したい | `oauth-client-assertion-jti-store-provider` |
| Issuer の署名鍵の保存・取得・署名処理を変更したい | `issuer-signature-key-store-provider` |
| Authorization Server の署名鍵の保存・取得・署名処理を変更したい | `authz-signature-key-store-provider` |
| Verifier の署名鍵の保存・取得・署名処理を変更したい | `verifier-signature-key-store-provider` |
| Issuer の署名鍵の生成方法を変更したい | `issuer-signature-key-provider` |
| Authorization Server の署名鍵の生成方法を変更したい | `authz-signature-key-provider` |
| Verifier の署名鍵の生成方法を変更したい | `verifier-signature-key-provider` |
| JWT の署名検証処理を変更したい | `jwt-signature-provider` |
| DID method ごとの解決処理を追加・変更したい | `did-provider` |
| Credential Request に含まれる proof の検証処理を追加・変更したい | `credential-proof-provider` |
| Credential format ごとの発行処理を追加・変更したい | `issue-credential-provider` |
| Verifiable Credential の検証処理を追加・変更したい | `verify-verifiable-credential-provider` |
| Verifiable Presentation の検証処理を追加・変更したい | `verify-verifiable-presentation-provider` |
| Holder Binding の検証処理を変更したい | `holder-binding-provider` |
| Credential Query の生成処理を追加・変更したい | `credential-query-provider` |
| Request Object の保存・取得・削除処理を変更したい | `request-object-store-provider` |
| Request Object ID の生成方法を変更したい | `request-object-id-provider` |
| Authorization Request の JAR 生成処理を追加・変更したい | `authz-request-jar-provider` |
| Verifier に紐づく証明書の保存・取得処理を変更したい | `verifier-certificate-store-provider` |
| 証明書の検証や、証明書から公開鍵を取得する処理を変更したい | `certificate-provider` |
| Transaction Code の生成方法を変更したい | `transaction-code-provider` |
| Transaction Data の生成方法を変更したい | `transaction-data-provider` |
