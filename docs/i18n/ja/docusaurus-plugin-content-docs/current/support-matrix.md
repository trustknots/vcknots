---
sidebar_position: 21
---

# VC Knots のサポート範囲

下記の表は、[OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) および [OpenID for Verifiable Presentations - draft 24](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html) を基準に、このリポジトリの現在の実装範囲を整理したものです。

`✅` は該当ロールで実装済み、`❌` は未実装またはエンドツーエンドでは利用できないことを示します。設定に依存する機能は、備考欄に条件を記載しています。

## OpenID for Verifiable Credential Issuance 1.0

| 仕様セクション | 機能領域 | 仕様上の役割・機能 | Issuer | Wallet | 備考 |
| --- | --- | --- | --- | --- | --- |
| [3.5](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.5) | Issuance Flow | Pre-Authorized Code Flow | `v0.6.0` 以降<br />✅ | ✅ | 現在の標準フロー。 |
| [3.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.4) | Issuance Flow | Authorization Code Flow | ❌ | ❌ | エンドツーエンドでは未対応。 |
| [4.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1) | Credential Offer | `credential_offer`（Pre-Authorized Code） | `v0.6.0` 以降<br />✅ 生成 | ✅ 解析 | `credential_offer_uri` による参照方式は対象外。 |
| [3.5](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.5) | Transaction Code | `tx_code` | `v0.6.0` 以降<br />✅ 発行・検証 | ✅ 送信 | Pre-Authorized Code Flow で使用。 |
| [A.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1) | Credential Format | `jwt_vc_json` | `v0.6.0` 以降<br />✅ 発行 | ✅ 受領 |  |
| [A.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.3) | Credential Format | `dc+sd-jwt`（SD-JWT VC） | `v0.6.0` 以降<br />✅ 発行 | ✅ 受領 |  |
| [A.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-mobile-documents-or-mdocs-i) | Credential Format | `mso_mdoc` | ❌ | ❌ |  |
| [6](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6) | Token Endpoint | Access Token の発行 | `v0.6.0` 以降<br />✅ | ✅ | Pre-Authorized Code に対応。 |
| [13.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.2) | Client Authentication | `private_key_jwt` | `v0.6.0` 以降<br />✅ 検証 | ❌ 送信 | 登録済み OAuth client の Token Endpoint 認証方式。関連節: [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) |
| [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) | Client Authentication | 匿名の Pre-Authorized Token Request | `v0.6.0` 以降<br />✅ 条件付き | ✅ 送信 | Authorization Server Metadata の `pre-authorized_grant_anonymous_access_supported` が `true` の場合のみ。関連節: [12.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.3) |
| [13.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.2) | Sender Constraint | DPoPによる送信者制約付き Access Token | `v0.6.0` 以降<br />✅ | ✅ | `off` / `optional` / `required` を設定可能。Token Endpoint と Credential Endpoint に適用。関連節: [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1), [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2), [8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2)。外部仕様: [RFC 9449](https://www.rfc-editor.org/info/rfc9449) |
| [8](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8) | Credential Endpoint | Credential Request / Response | `v0.6.0` 以降<br />✅ | ✅ |  |
| [8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2) | Credential Proof | JWT Proof | `v0.6.0` 以降<br />✅ 検証 | ✅ 生成 | Credential の鍵所有証明。現在は単一 Proof が対象。 |
| [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2) | Nonce | OpenID4VCI `c_nonce` | `v0.6.0` 以降<br />✅ 発行 | ✅ 取得・使用 | `POST /nonce` の JSON body で返す Credential Proof 用 nonce。 |
| [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2) | Nonce | DPoP-Nonce | `v0.6.0` 以降<br />✅ 条件付き | ✅ 条件付き | DPoPのチャレンジ用レスポンスヘッダー。`c_nonce` とは別の値。外部仕様: [RFC 9449](https://www.rfc-editor.org/info/rfc9449) |
| [12.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2) | Metadata | Credential Issuer Metadata | `v0.6.0` 以降<br />✅ 署名なし JSON | ✅ 取得 | 署名付き Metadata は未対応。 |
| [6.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1.1) | Credential Selection | `authorization_details` | ❌ | ❌ | Token Request / Response のエンドツーエンド対応は未実装。 |
| [3.3.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.4) | Credential Selection | `credential_identifier` | ❌ | 部分対応 | Token Response での `credential_identifiers` 連携が未実装。関連節: [6.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2) |
| [3.3.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.2) | Credential Issuance | Batch Credential Issuance | ❌ | ❌ |  |
| [9](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9) | Credential Issuance | Deferred Credential Endpoint | ❌ | ❌ |  |
| [10](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10) | Encryption | Credential Request の暗号化 | ❌ | ❌ |  |
| [10](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10) | Encryption | Credential Response の暗号化 | ❌ | ❌ |  |
| [11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11) | Notification | Notification Endpoint | ❌ | ❌ |  |

## OpenID for Verifiable Presentations - draft 24

| 仕様セクション | 機能領域 | 仕様上の役割・機能 | Verifier | Wallet | 備考 |
| --- | --- | --- | --- | --- | --- |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5) | Authorization Request | Authorization Request | `v0.6.0` 以降<br />✅ `request_uri`、URL エンコードされたパラメータ | ✅ `request`、`request_uri`、URL エンコードされたパラメータ |  |
| [6](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-6) | Credential Query | DCQL | ❌ | ❌ |  |
| [5.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.4) | Credential Query | Presentation Exchange | `v0.6.0` 以降<br />✅ | ✅ | 外部仕様: [DIF Presentation Exchange](https://identity.foundation/presentation-exchange/spec/v2.1.1) |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5) | Authorization Request | 署名付き Authorization Request（JAR） | `v0.6.0` 以降<br />✅ | ✅ | Request Objectを使用。外部仕様: [RFC 9101](https://www.rfc-editor.org/info/rfc9101) |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5) | Authorization Request | 暗号化された Authorization Request（JAR） | ❌ | ❌ | 外部仕様: [RFC 9101](https://www.rfc-editor.org/info/rfc9101) |
| [5.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.6) | Credential Query | スコープを使用した Authorization Request | ❌ | ❌ |  |
| [5.10.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.10.4) | Client Identification | Client Identifier Scheme | `v0.6.0` 以降<br />✅ `redirect_uri`、`x509_san_dns` | ✅ `redirect_uri`、`x509_san_dns` |  |
| [5.11](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.11) | Request URI | Request URI Method | `v0.6.0` 以降<br />✅ GET | ✅ GET、POST |  |
| [10](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-10) | Metadata | Wallet Metadata | ❌ | ❌ |  |
| [8.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-8.1) | Authorization Response | Authorization Response | `v0.6.0` 以降<br />✅ | ✅ |  |
| [8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-8.5) | Authorization Response | Authorization Error Response | ❌ | ❌ |  |
| [8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-8.3) | Authorization Response | 暗号化された Authorization Response | ❌ | ✅ |  |
| [8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-8.2) | Response Mode | Response Mode | `v0.6.0` 以降<br />✅ `direct_post` | ✅ `direct_post` |  |
| [8.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-8.4) | Transaction Data | Transaction Data | `v0.6.0` 以降<br />✅ | ✅ |  |
| [12](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-12) | Client Authentication | Verifier Attestation JWT | ❌ | ❌ |  |
| [Appendix A](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#appendix-A) | Digital Credentials API | Digital Credential API／DC API | ❌ | ❌ |  |
| [Appendix B.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#appendix-B.4) | Credential Format | SD-JWT-VC形式（`dc+sd-jwt`） | `v0.6.0` 以降<br />✅ | ✅ |  |
| [Appendix B.4.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#appendix-B.4.5) | Holder Binding | SD-JWT VC Key Binding／KB-JWT | `v0.6.0` 以降<br />✅ | ✅ |  |
| [Appendix B.1.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#appendix-B.1.1) | Credential Format | `jwt_vc_json`形式 | `v0.6.0` 以降<br />✅ | ✅ |  |
