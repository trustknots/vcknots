---
sidebar_position: 21
---

# VC Knots のサポート範囲

下記の表は、[OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) および [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) を基準に、このリポジトリの現在の実装範囲を整理したものです。

`✅` は該当ロールで実装済み、`❌` は未実装またはエンドツーエンドでは利用できないことを示します。設定に依存する機能は、備考欄に条件を記載しています。OpenID for Verifiable Presentations の表の Wallet 列では、一部でも実装している機能を `✅` とし、列挙できる場合は実装している値やプロパティを続けて記載し、`❌` はその機能をまったく実装していないことを示します。仕様からの逸脱・制約・条件は備考欄に記載します。

OpenID for Verifiable Presentations の表の備考欄では、`[Verifier]` または `[Wallet]` で始まる備考はそのロールだけに、ラベルの無い備考は両方のロールに当てはまります。長くなる Wallet の備考はその表の下の [Wallet の備考](#oid4vp-wallet-notes) に記載し、該当する行からリンクしています。

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
| [13.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.2) | Client Authentication | `private_key_jwt` | `v0.6.0` 以降<br />✅ 検証 | ✅ 送信 | 登録済み OAuth client の Token Endpoint 認証方式。Wallet が対応するのは `private_key_jwt` と `none`（既定）だけで、`client_secret_basic` には対応していません。そのため `token_endpoint_auth_methods_supported` を省略する Authorization Server は利用できません（RFC 8414 §2）。関連節: [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) |
| [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) | Client Authentication | 匿名の Pre-Authorized Token Request | `v0.6.0` 以降<br />✅ 条件付き | ✅ 送信 | `client_id` を省略するのは、Authorization Server Metadata の `pre-authorized_grant_anonymous_access_supported` が `true` のときだけです（既定値は `false`）。それ以外は `client_id` を付けて送信し、`client_id` が未設定なら送信前にエラーを返します。関連節: [12.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.3) |
| [13.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.2) | Sender Constraint | DPoPによる送信者制約付き Access Token | `v0.6.0` 以降<br />✅ | ✅ | 関連節: [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1), [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2), [8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2)。外部仕様: [RFC 9449](https://www.rfc-editor.org/info/rfc9449) |
| [8](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8) | Credential Endpoint | Credential Request / Response | `v0.6.0` 以降<br />✅ | ✅ |  |
| [8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2) | Credential Proof | JWT Proof | `v0.6.0` 以降<br />✅ 検証 | ✅ 生成 | 現在は単一 Proof が対象。`iss` を省略するのは匿名の Pre-Authorized Token Request の場合だけです。関連節: [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) |
| [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2) | Nonce | OpenID4VCI `c_nonce` | `v0.6.0` 以降<br />✅ 発行 | ✅ 取得・使用 | `POST /nonce` の JSON body で返す Credential Proof 用 nonce。 |
| [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2) | Nonce | DPoP-Nonce | `v0.6.0` 以降<br />✅ 条件付き | ✅ 条件付き | 外部仕様: [RFC 9449](https://www.rfc-editor.org/info/rfc9449) |
| [12.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2) | Metadata | Credential Issuer Metadata | `v0.6.0` 以降<br />✅ 署名なし JSON | ✅ 取得 | 署名付き Metadata は未対応。`credential_issuer` が Credential Offer の識別子と一致しないメタデータは拒否します。 |
| [6.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1.1) | Credential Selection | `authorization_details` | ❌ | ❌ | Token Request / Response のエンドツーエンド対応は未実装。 |
| [3.3.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.4) | Credential Selection | `credential_identifier` | ❌ | 部分対応 | Token Response での `credential_identifiers` 連携が未実装。関連節: [6.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2) |
| [3.3.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.2) | Credential Issuance | Batch Credential Issuance | ❌ | ❌ |  |
| [9](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9) | Credential Issuance | Deferred Credential Endpoint | ❌ | ❌ |  |
| [10](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10) | Encryption | Credential Request の暗号化 | ❌ | ❌ |  |
| [10](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10) | Encryption | Credential Response の暗号化 | ❌ | ❌ |  |
| [11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11) | Notification | Notification Endpoint | ❌ | ❌ |  |

## OpenID for Verifiable Presentations 1.0

| 仕様セクション | 機能領域 | 仕様上の役割・機能 | Verifier | Wallet | 備考 |
| --- | --- | --- | --- | --- | --- |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | Authorization Request | `v0.7.0` 以降<br />✅ `request_uri`、URL エンコードされたパラメータ | ✅ `request`、`request_uri`、URL エンコードされたパラメータ | [Wallet] [詳細](#wallet-authorization-request) |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | 署名付き Authorization Request（JAR） | `v0.7.0` 以降<br />✅ | ✅ `request`、`request_uri` | Request Objectを使用。外部仕様: [RFC 9101](https://www.rfc-editor.org/info/rfc9101)<br />[Wallet] [詳細](#wallet-signed-request) |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | 暗号化された Authorization Request（JAR） | ❌ | ❌ | 外部仕様: [RFC 9101](https://www.rfc-editor.org/info/rfc9101)<br />[Wallet] Request Object を復号できないため、暗号化されたものは拒否する。 |
| [5.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.5) | Credential Query | スコープを使用した Authorization Request | ❌ | ❌ | [Wallet] 空文字列以外の `scope` を含むリクエストは `invalid_scope` で拒否する。Credential を要求できるのは `dcql_query` だけである。 |
| [5.9.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3) | Client Identification | Client Identifier Prefix | `v0.7.0` 以降<br />✅ `redirect_uri`、`x509_san_dns` | ✅ `redirect_uri`、`x509_san_dns` | [Wallet] [詳細](#wallet-client-identifier-prefix) |
| [5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10) | Request URI | Request URI Method | `v0.7.0` 以降<br />✅ GET | ✅ GET、POST | [Wallet] [詳細](#wallet-request-uri-method) |
| [6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l) | Credential Query | DCQL | `v0.7.0` 以降<br />✅ | ✅ `credentials`、`credential_sets`、`claims`、`claim_sets`、`meta.vct_values` | `dcql_query` パラメータを使用。<br />[Wallet] [詳細](#wallet-dcql) |
| [8.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1) | Authorization Response | Authorization Response | `v0.7.0` 以降<br />✅ | ✅ `vp_token`、`state` | [Wallet] [詳細](#wallet-authorization-response) |
| [8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2) | Response Mode | Response Mode | `v0.7.0` 以降<br />✅ `direct_post` | ✅ `direct_post` | [Wallet] [詳細](#wallet-response-mode) |
| [8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3) | Authorization Response | 暗号化された Authorization Response | ❌ | ✅ `ECDH-ES`、`ECDH-ES+A128KW`、`ECDH-ES+A192KW`、`ECDH-ES+A256KW` | [Wallet] [詳細](#wallet-encrypted-response) |
| [8.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4) | Transaction Data | Transaction Data | `v0.7.0` 以降<br />✅ | ✅ `dc+sd-jwt` | `dc+sd-jwt` のみ対応。<br />[Wallet] [詳細](#wallet-transaction-data) |
| [8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.5) | Authorization Response | Authorization Error Response | ❌ | ✅ `invalid_request`、`invalid_scope`、`vp_formats_not_supported`、`invalid_transaction_data`、`access_denied` | [Wallet] [詳細](#wallet-error-response) |
| [10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10) | Metadata | Wallet Metadata | ❌ | ❌ | [Wallet] メタデータは公開せず、`request_uri_method=post` で Request Object を取得するときも `wallet_metadata` を送らない（Section 5.10）。 |
| [11](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-11) | Metadata | Verifier Metadata — `client_metadata` | `v0.7.0` 以降<br />✅ | ✅ `jwks` | [Wallet] [詳細](#wallet-verifier-metadata) |
| [12](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12) | Client Authentication | Verifier Attestation JWT | ❌ | ❌ | [Wallet] Client Identifier が `verifier_attestation` のプレフィックスを使うリクエストは拒否する。 |
| [Appendix A](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A) | Digital Credentials API | Digital Credential API／DC API | ❌ | ❌ | [Wallet] Wallet は Authorization Request の URI でのみ起動され、Digital Credentials API の入口を持たない。予約された `origin` の Client Identifier Prefix は、Section 5.9.3 の要求どおり拒否する。 |
| [Appendix B.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1) | Credential Format | `jwt_vc_json`形式 | `v0.7.0` 以降<br />✅ | ✅ | [Wallet] [詳細](#wallet-jwt-vc-json) |
| [Appendix B.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2) | Credential Format | `mso_mdoc`（Mobile Documents／mdocs） | ❌ | ❌ | [Wallet] このフォーマットの Credential Query を含む要求は `vp_formats_not_supported` で拒否する（[DCQL](#wallet-dcql) を参照）。 |
| [Appendix B.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3) | Credential Format | SD-JWT-VC形式（`dc+sd-jwt`） | `v0.7.0` 以降<br />✅ | ✅ | [Verifier] 署名アルゴリズムは ES256 のみ対応。 |
| [Appendix B.3.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.6) | Holder Binding | SD-JWT VC Key Binding／KB-JWT | `v0.7.0` 以降<br />✅ | ✅ | [Verifier] 署名アルゴリズムは ES256 のみ対応。<br />[Wallet] [詳細](#wallet-key-binding) |

### Wallet の備考 {#oid4vp-wallet-notes}

表からリンクしている行について、Wallet の実装の仕方（仕様からの逸脱・制約・条件）を記載します。

#### 5 Authorization Request {#wallet-authorization-request}

- 認識しないパラメータは無視する（Section 5）が、`presentation_definition`、`presentation_definition_uri`、`presentation_submission` は `invalid_request` で拒否する。
- URL エンコードされたパラメータで渡すリクエストがパラメータを繰り返している場合は、エラー応答を返さずに拒否する。
- `request` / `request_uri` で渡す Request Object は、ES256 か RS256 で署名されていなければならない（[署名付き Authorization Request（JAR）](#wallet-signed-request) を参照）。

#### 5 署名付き Authorization Request（JAR） {#wallet-signed-request}

- Request Object を受け入れるのは、署名されていて `x509_san_dns` の Client Identifier Prefix を使う場合だけである（[Client Identifier Prefix](#wallet-client-identifier-prefix) を参照）。
- `typ` ヘッダは `oauth-authz-req+jwt` でなければならず、`iss` クレームは無視する（Section 5）。
- `x5c` の証明書チェーンは、有効期間を含めて `Oid4vpPresenter.X509TrustChainRoots` に対して検証し、このフィールドが未設定のとき（既定）はシステムの信頼ストアに対して検証する。Extended Key Usage に `serverAuth` を含まないリーフ証明書は拒否する。
- 失効は、チェーンの各証明書について、その証明書が示す OCSP レスポンダで確認し、OCSP レスポンダを示していない証明書は CRL 配布点で確認する。OCSP では、有効で期限内の `good` か `revoked` の応答のうち最初のものが結果を決め、そのような応答を返すレスポンダが無ければリクエストを拒否する。OCSP が無い場合は、すべての配布点から発行者が署名した期限内の CRL を取得でき、その証明書が載っていない場合を除いて、リクエストを拒否する。
- テスト専用の `Oid4vpPresenter.InsecureSkipX509Verify` を設定すると、チェーンの検証と失効の確認は省かれる。
- 署名はリーフ証明書の鍵で検証する。`exp` が過ぎているか、`nbf` か `iat` が未来の時刻である Request Object は、1 分の時計のずれを許したうえで拒否する。
- クエリパラメータの `client_id` と Request Object の `client_id` クレームは照合しないが、RFC 9101 Section 6.3 はこの 2 つが同一であることを求めており、Section 5.10.1 も `request_uri_method=post` で取得する Request Object について同じことを繰り返している。クエリパラメータに `client_id` の無い Request Object も受け入れる。

#### 5.9.3 Client Identifier Prefix {#wallet-client-identifier-prefix}

- `x509_san_dns`：Request Object を受け入れるのは、プレフィックスを除いた Client Identifier が `x5c` のリーフ証明書の dNSName SAN と一致し、`response_uri` のホストがその値と等しい場合だけである（Section 5.9.3、8.2）。
- `redirect_uri`：`client_id` クレームがこのプレフィックスを使う Request Object は拒否する（Section 5.9.3）。
- URL エンコードされたパラメータで渡すリクエストは、`redirect_uri` の Client Identifier Prefix でだけ受け入れる。`response_uri` は省略してよいが、ある場合はプレフィックスを除いた Client Identifier と等しくなければならず（Section 5.9.3、8.2）、異なる場合はエラー応答を返さずに拒否する。
- Wallet は事前登録されたクライアントを持たないので、プレフィックスの無い `client_id` は拒否する（Section 5.9.2）。
- `decentralized_identifier`、`verifier_attestation`、`x509_hash`、`openid_federation` と認識しないプレフィックスを使う Client Identifier は拒否し、証明書や `response_uri` が Client Identifier と一致しない Request Object も拒否する。Section 8.5 はどちらにも `invalid_request` を定めているが、どちらの拒否も Verifier には送らない。

#### 5.10 Request URI Method {#wallet-request-uri-method}

- `request_uri_method` が無いときは、`request_uri` を GET で取得する。`post` のときは空のボディで POST し、`wallet_metadata` も `wallet_nonce` も渡さない（どちらも任意、Section 5.10）。
- `request_uri` は `https` の URL でなければならない。`VCKNOTS_WALLET_HTTP_ALLOWED` か `VCKNOTS_WALLET_DEBUG` が `true` のときは `http` の URL も受け入れる。
- HTTP のエラー応答を受けると、要求の処理を終える（Section 5.10.2）。リダイレクトは追わず、受けた時点で処理を終える。応答のコンテンツタイプは確認しないが、Section 5.10.1 は `post` の要求に対する応答が `application/oauth-authz-req+jwt` であることを求めている。
- `request_uri_method` は大文字小文字を区別せずに受け入れ、空の値は `get` とみなすが、Section 5.1 が定める値は大文字小文字を区別する `get` と `post` だけである。それ以外の値は `invalid_request_uri_method` を送らずに拒否する（Section 8.5）。

#### 6 DCQL {#wallet-dcql}

- 対応フォーマットは `dc+sd-jwt` と `jwt_vc_json` である。`mso_mdoc` など他のフォーマットの Credential Query を含む要求は、そのクエリが無くても答えられる場合でも `vp_formats_not_supported` で拒否する。構造が不正なクエリは `invalid_request` で拒否するが、`meta` はオブジェクトであることしか確認せず、`trusted_authorities` と Claims Query の `values` は確認しない。
- Wallet が答える Credential Query は 1 つだけで、それに Credential 1 件で答え、`multiple` は無視する。
- `credential_sets` がある場合は、必須セットすべてを Credential 1 件で満たせる選択肢を採る。一致する保有 Credential のどれも要求されたクレームを開示できない選択肢と、参照しない transaction data のエントリが 1 つでもある選択肢は、読み飛ばして次の選択肢に移る。要求を拒否するのは選択肢が残らなくなったときだけで、最初に読み飛ばした選択肢が transaction data の参照していないものなら `invalid_transaction_data`、それ以外なら `access_denied` で拒否する。読み飛ばした選択肢が無く、2 件以上の Credential を使わないと答えられない場合は、エラー応答を送らない（[Authorization Response](#wallet-authorization-response) を参照）。
- `dc+sd-jwt` では `meta.vct_values` を照合し、要求された `claims` だけを開示する。要求を満たせる Credential のうち最も新しく保存したものを、その Credential が満たせる最初の `claim_sets` の選択肢で提示する。古い Credential に移るのは、要求されたクレームを開示できない場合だけである。`jwt_vc_json` の Credential は `format` だけで照合し、Credential 全体を提示する。
- Appendix B.3.5 が必須とする `vct_values` を持たない `dc+sd-jwt` の Credential Query は、保有するどの `dc+sd-jwt` Credential にも一致する。`vct_values` が空または配列でない Credential Query はどれにも一致しないため、そのクエリを必要とする要求は `invalid_request` ではなく `access_denied` で拒否する。
- `trusted_authorities`（Section 6.1）と Claims Query の `values` は無視し、要求されたクレームを値にかかわらず開示する（Section 6.4.1）。
- `require_cryptographic_holder_binding` だけでは Key Binding JWT を付与しない（[SD-JWT VC Key Binding](#wallet-key-binding) を参照）。

#### 8.1 Authorization Response {#wallet-authorization-response}

- `vp_token` は、答えた Credential Query の id をキーとするエントリを 1 件だけ持つ JSON オブジェクトで、その値は Presentation 1 件の配列である。要求に `state` があれば `state` も含める。
- `response_type` は必須だが、値は確認しない。値にかかわらず Authorization Response で `vp_token` を返すため、`code` と `vp_token id_token`（Section 8）には対応していない。
- DCQL クエリに答えるのに 2 件以上の Credential が必要な場合は、`vp_token` を送らない。エラー応答を送るのは、保有していない Credential に対する `access_denied` のように、別の理由でも拒否される場合だけである。この制約そのものに対応するエラーコードは OID4VP に無い。

#### 8.2 Response Mode {#wallet-response-mode}

- Authorization Response を `application/x-www-form-urlencoded` で `response_uri` に POST し、HTTP のエラー応答を失敗として扱う。リダイレクトは追わずに失敗として扱い、Authorization Error Response でも同じである。
- `response_uri` は `https` の URL でなければならない。`VCKNOTS_WALLET_HTTP_ALLOWED` か `VCKNOTS_WALLET_DEBUG` が `true` のときは、この検査を行わない。
- `redirect_uri` を含む要求は `invalid_request` で拒否する（Section 8.2）。
- 成功応答に対して Response URI が返した `redirect_uri` は、呼び出し元に返し、`PresentCredentialOptions.OnRedirect` にも渡す。Wallet 自身はこれを開かないため、User Agent をそこへリダイレクトするのはアプリケーションの役割である（Section 8.2）。
- Authorization Error Response に対して返された `redirect_uri` は捨てるが、Section 8.2 はこれについても User Agent をリダイレクトするよう Wallet に求めている。
- `fragment`、`query`、`direct_post.jwt` など他の Response Mode を使う要求は拒否する。

#### 8.3 暗号化された Authorization Response {#wallet-encrypted-response}

- 暗号化は Section 8.3 ではなく JARM のクライアントメタデータに従う。暗号化するのは、OID4VP 1.0 が使わない JARM のメンバー `authorization_encrypted_response_alg` と `authorization_encrypted_response_enc` が `client_metadata` にある場合だけである。そのときは `vp_token` と、要求にあれば `state` を入れた無署名の JWE を `response` パラメータで送る。
- `authorization_encrypted_response_alg` だけの場合、Wallet 列に無い `alg` の場合、`client_metadata.jwks` に鍵が無い場合は、提示に失敗し、何も送らない。
- JWE の `alg` と `enc` はこの 2 つのメンバーから取り、選んだ JWK の `alg` や `encrypted_response_enc_values_supported` は使わず、既定値の `A128GCM` も適用しない。
- 鍵は `client_metadata.jwks` のうち `use` が `enc` の最初の鍵で、該当が無ければ先頭の鍵を使い、その `kid` を JWE ヘッダに入れる。
- Response Mode `direct_post.jwt`（Section 8.3.1）を使う要求は拒否する。

#### 8.4 Transaction Data {#wallet-transaction-data}

- `invalid_transaction_data` を返すのは次の場合である。
  - type が `Oid4vpPresenter.SupportedTransactionDataTypes` にも `Oid4vpPresenter.RegisterTransactionDataType` の登録にも無いとき。どちらも既定で空なので、受け入れる type を設定するまで、`transaction_data` を含むリクエストはすべて拒否される。
  - エントリがその type の定義に適合しないとき。Section 5.1 は type ごとの定義をその type を規定する文書に委ねているので、検査するのは登録された validator である。列挙しただけの type は Section 5.1 と Appendix B.3.3.1 が定めるメンバーと大文字小文字を区別せずに照合し、それ以外を持てば拒否する。
  - エントリが base64url の JSON でないか、`credential_ids` を持たないとき。
  - エントリが参照する Credential Query が存在しないか、`dc+sd-jwt` でないか、`require_cryptographic_holder_binding` を false にしているとき（Appendix B.3.3）。
  - 全エントリが提示していて serializer が計算できる（`sha-256`、`sha-384`、`sha-512`）`transaction_data_hashes_alg` が 1 つも無いとき。
- 参照していないエントリが 1 つでもある Credential Set の選択肢は読み飛ばし、すべてのエントリが参照する選択肢がどれも提示できなくなってから拒否する（Section 5.1）。最初に読み飛ばしたのが参照されていない選択肢なら `invalid_transaction_data`、それ以外なら `access_denied` で拒否するが、読み飛ばした選択肢が無く、2 件以上の Credential を使わないと答えられない場合はエラー応答を送らない（[DCQL](#wallet-dcql) を参照）。
- 仕様が用いる base64url はパディングを持たない（Section 2）が、末尾の `=` のパディングや改行を含むエントリも、パディングの後ろに改行がある場合を除いて受理する。ハッシュは受け取った文字列そのものに対して計算する（Appendix B.3.3.1）ので、Verifier が送ったエントリから計算するハッシュと一致する。
- Appendix B.3.3.1 は `transaction_data_hashes_alg` を文字列の空でない配列と定めているが、値が `null` なら省略とみなして `sha-256` を使い、配列の `null` の要素は読み飛ばす。

#### 8.5 Authorization Error Response {#wallet-error-response}

- `response_mode=direct_post` のとき、Wallet は `error` と、要求にあれば `state` を `response_uri` に POST し、`error_description` も添えるが、理由からユーザーがどの Credential を保有しているかが分かってしまう `access_denied` には添えない（Section 15.9）。他の response mode を使う要求は、エラー応答を返さずに拒否する。
- `x509_san_dns` の Client Identifier Prefix を使う Request Object（`request` / `request_uri`）に対しても、パラメータ検証の失敗にエラー応答を返すが、それは証明書チェーン（`Oid4vpPresenter.InsecureSkipX509Verify` を設定した場合を除く）・署名・`client_id`・応答先をすべて検証した後に限られる。それより前に見つかった失敗は、検証が終わるまで保持される。
- `redirect_uri` プレフィックスを使うもののように検証鍵を一切名乗らない Request Object は、代わりに即座に拒否され、エラー応答を送る先を何も認証していないため、エラー応答は返らない。
- Wallet がコードを付けない拒否は一切送られない。これにあたるものには、Wallet が対応していない Client Identifier Prefix（Section 8.5 はこれに `invalid_request` を割り当てている）と、大文字小文字を問わず `get` でも `post` でもない、空でない `request_uri_method` がある（`invalid_request_uri_method` は送出しない）。
- URL エンコードされたパラメータで渡すリクエストがエラー応答を受けるのは、Client Identifier が `redirect_uri` プレフィックスを使い、`response_uri` があればそれがプレフィックスを除いた Client Identifier と等しい場合だけである（それ以外の `response_uri` を認証するものは無いため）。認識しないプレフィックス、`origin`、プレフィックスの無い `client_id` は他の検査より前に拒否される。
- Credential Query のどれか 1 つでも `dc+sd-jwt` と `jwt_vc_json` 以外のフォーマットを指定すると、そのクエリが Credential Set の選択肢の 1 つにすぎない場合や必須でない Credential Set に属する場合でも、`vp_formats_not_supported` を返す。Section 8.5 はこのコードを要求されたフォーマットを 1 つも扱えない Wallet のために定めており、Section 6.4.2 は Credential Set をどの選択肢で満たしてもよいとしている。

#### 11 Verifier Metadata — `client_metadata` {#wallet-verifier-metadata}

- `client_metadata` は、Request Object では JSON オブジェクトとして、URL エンコードされたパラメータでは JSON 文字列として受け付ける。
- Section 5.1 が定めるメンバーのうち使うのは `jwks` だけで、用途は Authorization Response を暗号化する鍵に限る。`client_metadata` のどの鍵も、署名付きリクエストの検証には使わない（Section 5.1）。
- 暗号化するのは、`client_metadata` が、Section 5.1 が挙げるメンバーに含まれない JARM のメンバー `authorization_encrypted_response_alg` も持つときだけである（[暗号化された Authorization Response](#wallet-encrypted-response) を参照）。`vp_formats_supported` と `encrypted_response_enc_values_supported` は読まない。
- `jwks` に Wallet が解析できない鍵（Section 8.3 の例にある `X25519` の鍵など）があると、リクエストを拒否する。RFC 7591 の登録メンバー（`client_name` など）の値の型が誤っている場合も、Section 5.1 が挙げていないメンバーは無視するよう定めているにもかかわらず拒否する。

#### Appendix B.1 `jwt_vc_json`形式 {#wallet-jwt-vc-json}

- このフォーマットの Credential Query は `format` だけで照合し、`meta` も `claims` も適用せず、保存済みで最も新しい `jwt_vc_json` Credential を全体のまま提示する。
- Appendix B.1 は `require_cryptographic_holder_binding` が false のとき Holder Binding の無い Credential を返すよう求めているが、Wallet はこの Credential を常に Verifiable Presentation に入れて提示する。

#### Appendix B.3.6 SD-JWT VC Key Binding／KB-JWT {#wallet-key-binding}

- holder の鍵は P-256 でなければならないため、KB-JWT は ES256 だけに対応する。
- KB-JWT は `sdjwtvc.SdJwtVcPresentationOptions.RequireKeyBinding` を指定したときに付与する（既定のオプションでは付与しない）。リクエストに `transaction_data` がある場合は、そのハッシュを KB-JWT で返すため強制的に付与する。
- `require_cryptographic_holder_binding` が既定どおり Cryptographic Holder Binding を要求していても（Section 6.1）、それだけでは KB-JWT を付与しないが、Appendix B.3 はその場合に KB-JWT 付きの SD-JWT を返すよう求めている。
