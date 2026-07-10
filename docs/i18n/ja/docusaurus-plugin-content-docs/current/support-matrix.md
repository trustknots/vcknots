---
sidebar_position: 9
---

# VC Knots のサポート範囲

下記の表は、 [OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)  および [OID4VP Draft 24](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html) を基準に整理しています。

## OID4VCI (1.0)

| 機能 | Issuer | Wallet |
| --- | --- | --- |
| Pre-Authorized Code フロー | ✅ | ✅ |
| Authorization Code フロー | ❌ | ❌ |
| Tx Code | ✅ | ✅ |
| Credential Offer | ✅ `pre-authorized_code` | ✅ `pre-authorized_code` |
| mso_mdoc 形式 | ❌ | ❌ |
| SD-JWT-VC 形式（`dc+sd-jwt`） | ✅ | ✅ |
| jwt_vc_json 形式 | ✅ | ✅ |
| Token Endpoint | ✅ | ✅ |
| 匿名の Pre-Authorized Token Request | ✅ | ✅ |
| Token Endpoint の認証方式 | ✅ `private_key_jwt` | ❌ |
| Credential Endpoint | ✅ | ✅ |
| Credential Issuer Metadata | ✅ 署名なしメタデータ | ✅ |
| Nonce Endpoint | ✅ | ✅ |
| Deferred Credential Endpoint | ❌ | ❌ |
| Proof | ✅ JWT | ✅ |
| DPoP | ✅ | ✅ |
| Credential Response の暗号化 | ❌ | ❌ |
| Credential Request の暗号化 | ❌ | ❌ |
| Notification Endpoint | ❌ | ❌ |

## OID4VP (Draft 24)

| 機能 | Verifier | Wallet |
| --- | --- | --- |
| Authorization Request | ✅ `request_uri`、URL エンコードされたパラメータ | ✅ `request`、`request_uri`、URL エンコードされたパラメータ |
| DCQL | ✅ DCQL を使用した Authorization Request の生成のみ | ❌ |
| Presentation Exchange | ✅ | ✅ |
| 署名付き Authorization Request（JAR） | ✅ | ✅ |
| 暗号化された Authorization Request（JAR） | ❌ | ❌ |
| スコープを使用した Authorization Request | ❌ | ❌ |
| Client Authentication Prefix | ✅ `redirect_uri`、`x509_san_dns`、`x509_san_uri` | ✅ `redirect_uri`、`x509_san_dns` |
| Request URI Method | ✅ GET | ✅ GET、POST |
| Wallet Metadata | ❌ | ❌ |
| Authorization Response | ✅ | ✅ |
| Authorization Error Response | ❌ | ❌ |
| 暗号化された Authorization Response | ❌ | ✅ |
| Response Mode | ✅ `direct_post` | ✅ `direct_post` |
| Transaction Data | ✅ | ✅ |
| Verifier Attestation JWT | ❌ | ❌ |
| Digital Credential API／DC API | ❌ | ❌ |
| SD-JWT-VC 形式（`dc+sd-jwt`） | ✅ | ✅ |
| SD-JWT VC Key Binding／KB-JWT | ✅ | ✅ |
| jwt_vc_json 形式 | ✅ | ✅ |
