# 公開 Wallet API driver

この独立した Go モジュールは、公開 Wallet API を実行します。
stdin から JSON の操作を 1 つ読み、stdout に JSON の結果を 1 つ書きます。
プロトコルのエラーでは終了コード 1 で `{"operation": ..., "error": ...}` を書き、コマンドや構成の入力が不正な場合は終了コード 2 で終了します。

driver は、OpenID4VCI 1.0 の Pre-Authorized Code Flow と Authorization Code Flow で Credential を受領し、保存済み Credential を列挙し、起動 URI または W3C Digital Credentials API を通じて OpenID4VP 1.0 で提示し、指定があれば HAIP 1.0 プロファイルを適用します。
ソフトウェアの JWK を使うため、ハードウェアによる保護はありません。

## 構成と実行

`wallet/mise.toml` に固定された Go（Go 1.26.6）を使います。
このディレクトリで次を実行します。

```sh
go build -o official_driver .
```

holder、DPoP、client の鍵として、別々の EC 署名用 JWK ファイルを用意します。
鍵ファイルは秘密鍵の成分を含み、client の公開 JWK は issuer に登録されていなければなりません。
テストに本番の鍵を使わないでください。
構成では絶対パスを使います。

### 構成フィールド

| フィールド | 型 | 既定値 | 効果 |
| --- | --- | --- | --- |
| `stateDirectory` | string | 必須 | bbolt の Credential ストアのディレクトリです。 |
| `clientId` | string | 必須 | `wallet.Config.ClientAuth.ClientID` です。 |
| `holderKeyFile` | string | 必須 | holder 鍵（`CredentialRequest.HolderKeys`、`Presentation.Key`）の秘密 JWK です。 |
| `dpopKeyFile` | string | 必須 | `wallet.Config.DPoP.Key` の秘密 JWK です。 |
| `clientKeyFile` | string | 必須 | `private_key_jwt` の鍵（`Config.ClientAuth.Key`）と、client attestation が束縛する鍵（`Config.Attestation.ClientKey`）の秘密 JWK です。 |
| `tlsCAFiles` | []string | `[]` | TLS のためにシステムのルートに追加する PEM で、CRL の取得にも使います。 |
| `profile` | string | `""` | `""`、`"final"`、`"haip"` のいずれかです。`Config.Profile` と driver が構築する両 plugin に適用します。未知の値は拒否します。 |
| `verifierCAFiles` | []string | `[]` | 署名付き Request Object の PEM トラストアンカー（`oid4vp.RequestObjectValidationOptions.TrustAnchors`）です。証明書を含まないファイルは拒否します。空の場合 `RequestObjectValidation` は nil のままで、X.509 の Request Object は拒否されます。 |
| `verifierAllowUnadvertisedRevocation` | bool | `false` | `RequestObjectValidationOptions.AllowUnadvertisedRevocation` です。`verifierCAFiles` が必要です。 |
| `walletAudience` | []string | `[]` | `RequestObjectValidationOptions.WalletAudience` です。`verifierCAFiles` が必要です。 |
| `issuerCAFiles` | []string | `[]` | Credential の `x5c` チェーンに対する PEM の Issuer トラストアンカー（`acceptance.IssuerX509TrustOptions.TrustAnchors`）です。 |
| `issuerAllowUnadvertisedRevocation` | bool | `false` | `acceptance.IssuerX509TrustOptions.AllowUnadvertisedRevocation` です。`issuerCAFiles` が必要です。 |
| `issuerJWKSFiles` | []string | `[]` | `x5c` のない Credential のための Issuer 公開鍵の JWKS ファイルです。構成したすべての鍵を返す `acceptance.Policy.ResolveIssuerKeys` を設定します。秘密鍵は拒否します。 |
| `requireHolderBinding` | bool | `false` | `acceptance.Policy.RequireHolderBinding` です。 |
| `redirectUri` | string | `""` | `Config.Issuance.RedirectURI` です。`receive-code` と `receive-code-wallet-initiated` で必須です。 |
| `authorizationRequestType` | string | `""` | `IssuanceRequest.AuthorizationRequestType` で、`""`、`"scope"`、`"authorization_details"` のいずれかです。HAIP が受け付けるのは `scope` だけです。 |
| `attesterKeyFile` | string | `""` | テスト専用の `attestation.StaticClientAttester`（`Config.Attestation.Client`）の秘密 JWK です。`x5c` チェーンがあれば attestation の `x5c` になり、HAIP ではそれが必須です。`attesterIssuer` と一緒に設定します。 |
| `attesterIssuer` | string | `""` | 静的 client attester の `iss` です。 |
| `keyAttesterKeyFile` | string | `""` | テスト専用の `attestation.StaticKeyAttester`（`Config.Attestation.Key`）の秘密 JWK です。`keyAttesterIssuer` と一緒に設定します。 |
| `keyAttesterIssuer` | string | `""` | 静的 key attester の `iss` です。 |
| `includeKeyAttestation` | bool | `false` | `CredentialRequest.IncludeKeyAttestation` で、Issuer が要求しなくても key attestation を送ります。 |
| `deferredPollAttempts` | int | `10` | 発行が保留中の間に driver が送る Deferred Credential Request の回数です。ゼロ以下なら 10 です。 |
| `credentialResponseEncryption` | bool | `false` | `Config.Issuance.CredentialEncryption.Response` を `CredentialEncryptionRequired` にし、応答の暗号化を提供しない Issuer を拒否します。応答用の鍵は一時鍵です。 |
| `additionalHolderKeys` | int | `0` | `receive-code` と `receive-code-wallet-initiated` の batch 要求に使う、追加の一時 P-256 holder 鍵の数です。 |
| `followRedirect` | bool | `true` | `present` が返された `redirect_uri` を開くかどうかです。 |

OpenID4VCI 1.0 のメソッドは `Config.CredentialAcceptance` がないと実行を拒否するため、driver は常にこれを設定します。
`issuerCAFiles` か `issuerJWKSFiles` があれば、ポリシーは Issuer の鍵を認証します。
どちらもなければ driver は `acceptance.Policy.UnverifiedIssuer` を設定し、鍵を認証できないテスト用 Issuer に対して実行していることを 1 か所で明示します。
HAIP では、SD-JWT VC にはそれでも `issuerCAFiles` が必要です。
`requireHolderBinding` はどちらの場合にも適用されます。

TLS を構成した HTTP クライアントは、plugin の `HTTPClient` であり、`IssuerX509TrustOptions` と `RequestObjectValidationOptions` の CRL 用クライアントでもあるので、CRL の取得も `tlsCAFiles` に従います。
矛盾するオプション（CA ファイルのない `*AllowUnadvertisedRevocation`、`verifierCAFiles` のない `walletAudience`、issuer のない attester 鍵）と、`redirectUri` のない Authorization Code の操作は、どの操作を実行するよりも前に拒否します。

`StaticClientAttester` と `StaticKeyAttester` は、ローカルに保持した attester 鍵で attestation を自己発行します。
これらはテストと単一運用者の構成のためのものです。
本番の wallet はリモートの attester から attestation を取得し、attester の秘密鍵を保持しません。

構成の例です。

```json
{
  "stateDirectory": "/path/to/isolated-wallet-state",
  "tlsCAFiles": ["/path/to/test-transport-ca.pem"],
  "verifierCAFiles": ["/path/to/verifier-trust-anchor.pem"],
  "verifierAllowUnadvertisedRevocation": false,
  "walletAudience": ["https://self-issued.me/v2"],
  "issuerCAFiles": ["/path/to/issuer-trust-anchor.pem"],
  "issuerAllowUnadvertisedRevocation": false,
  "issuerJWKSFiles": ["/path/to/issuer-jwks.json"],
  "requireHolderBinding": true,
  "profile": "final",
  "holderKeyFile": "/path/to/holder.jwk",
  "dpopKeyFile": "/path/to/dpop.jwk",
  "clientKeyFile": "/path/to/client.jwk",
  "clientId": "registered-wallet-client",
  "redirectUri": "https://wallet.example/callback",
  "authorizationRequestType": "",
  "attesterKeyFile": "/path/to/attester.jwk",
  "attesterIssuer": "https://attester.example",
  "keyAttesterKeyFile": "/path/to/key-attester.jwk",
  "keyAttesterIssuer": "https://attester.example",
  "includeKeyAttestation": false,
  "deferredPollAttempts": 10,
  "credentialResponseEncryption": false
}
```

通信の検証にはシステムのルートと `tlsCAFiles` を使います。
driver は TLS や X.509 の検査を無効にしません。
Credential はライブラリの bbolt ローカルストレージ plugin で保存します。

### 操作と出力

```sh
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"public-keys"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"receive-preauth","uri":"openid-credential-offer://?credential_offer=...","txCode":"issuer-supplied-code"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"receive-code","uri":"openid-credential-offer://?credential_offer_uri=..."}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"receive-code-wallet-initiated","credentialIssuer":"https://issuer.example/","credentialConfigurationId":"eudi_pid"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"list"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"present","uri":"openid4vp://?client_id=...&request_uri=..."}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"present-dcapi","dcapiRequest":{"protocol":"openid4vp-v1-unsigned","data":{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"...","client_metadata":{...},"dcql_query":{...}}},"origin":"https://localhost:33513"}
JSON
```

`public-keys` は holder、DPoP、client の鍵の公開 JWK を返します。

`receive-preauth` は値渡しの Offer を `wallet.ParseCredentialOfferURL` で解析し、`txCode` を `tx_code` として `AuthorizePreAuthorizedIssuance` を呼び、holder 鍵で `RequestCredential` を呼びます。
token リクエストは `clientId` で client を名乗り、DPoP proof を付け、`attesterKeyFile` があれば client attestation のヘッダーも付けます。

`receive-code` は Offer URI を `ResolveCredentialOffer` で解決し（`credential_offer_uri` は取得します）、`BeginIssuance` を呼び、返された認可 URL を自ら開きます。
TLS を構成したクライアントで GET を送り、認可サーバー内のリダイレクトには最大 5 回まで従い、認可サーバーの外へ出る最初の `Location` をリダイレクトとして受け取ります。
これはユーザー操作なしで応答するテスト用 Issuer で機能します。
ユーザーのいる wallet は、代わりにシステムブラウザで URL を開きます。
driver はその後、そのリダイレクトで `AuthorizeIssuance` を呼び、holder 鍵と `additionalHolderKeys` の鍵で `RequestCredential` を呼びます。

`receive-code-wallet-initiated` は、同じフローを Credential Offer なしで実行します（OpenID4VCI 1.0 §5）。
`uri` の代わりに `credentialIssuer` と `credentialConfigurationId` を受け取ります。

3 つの受領操作は、`RequestCredential` の後、保留中の発行を自らポーリングします。
Issuer が指定した間隔（最短 1 秒、最長 1 分）だけ待って `RequestDeferredCredential` を呼び、これを最大 `deferredPollAttempts` 回繰り返します。
その後 `NotifyIssuer` で結果を報告します。
Credential を保存したら `credential_accepted`、拒否したら `credential_failure` です。
保存後の通知の失敗はエラーとして報告します。
出力は `credentialIds`、Credential 順の `verification` 配列（`acceptance.Verification`）、Issuer が通知を求めた場合の `notificationId`、最後のポーリングの後も保留中の場合の `transactionId` と `pending: true` です。

`present` は holder 鍵で `PresentCredential` を呼びます。
要求を解析して受け付け、DCQL クエリを満たす保存済み Credential を選び、応答を送ります。
`redirectUri`、`redirectFollowed`、`redirectStatus`（リダイレクトを開かなかった場合は `0`）を返します。
`followRedirect` が有効な場合、driver は返された `redirect_uri` を同一端末のブラウザと同じように開きます。
TLS を構成したクライアントで GET を送り、`Accept: text/html,*/*`、`User-Agent: official_driver`、15 秒のタイムアウト、最大 5 回のリダイレクトを使います。
フラグメントは送信しません。
最終的なステータスが 2xx と 3xx 以外ならエラーです。

`present-dcapi` は W3C Digital Credentials API の呼出しに応答します。
`dcapiRequest` は platform の要求 entry（`protocol` とプロトコルの `data` オブジェクト）で、`origin` は platform が認証した呼出し元の origin です。
driver は `ParseDCAPIRequest`、`SelectCredentials`、`SubmitPresentation` を呼び、`SubmitResult.DCAPIResponse` を出力します。
`dc_api` では `{"protocol":...,"data":{"vp_token":{...}}}`、`dc_api.jwt` では `{"protocol":...,"data":{"response":"<JWE>"}}` です。
HTTP 呼出しは行いません。
Key Binding JWT の `aud` は `origin:<origin>` です（OpenID4VP 1.0 Appendix A.4）。

`list` は `credentialIds` と `total` を返します。

呼出しのたびに新しいプロセスになるので、列挙と提示は永続化された Credential を使います。
Issuer や Verifier の起動 URI はそのまま渡してください。
driver は要求を修正せず、プロトコルの失敗を再試行せず、提示の応答を自ら組み立てることもしません。

### additionalHolderKeys

`additionalHolderKeys` を指定すると、Authorization Code の操作は一時 P-256 鍵による key proof をその数だけ追加で送り、`batch_credential_issuance` を広告する Issuer が複数の Credential を返すようにします（OpenID4VCI 1.0 §8.2）。
一時鍵は実行後に破棄されるため、得られた Credential は保存されますが、後で提示することはできません。
batch 発行を試すときだけ使ってください。
