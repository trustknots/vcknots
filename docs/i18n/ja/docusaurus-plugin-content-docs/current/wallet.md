---
sidebar_position: 13
---

# Wallet機能のセットアップと使用方法

このチュートリアルは、VCKnots の wallet ライブラリ（Go ライブラリ）のセットアップ、Credential の受領と提示の実装、本番環境での利用に向けた考慮事項を説明します。

wallet は OpenID for Verifiable Credentials の各仕様を実装しています。

* **Credential の受領（OpenID4VCI）:** Pre-Authorized Code Flow または Authorization Code Flow で Issuer から Credential を受け取ります。
* **Credential の提示（OpenID4VP）:** Authorization Request（`openid4vp:` URI、Request Object、W3C Digital Credentials API の呼出し）に Verifiable Presentation で応答します。

受領と提示のどちらも **JWT-VC**（`jwt_vc_json`、`application/vc+jwt`）と **SD-JWT VC**（`dc+sd-jwt`、`application/dc+sd-jwt`）に対応し、SD-JWT VC の選択的開示と Key Binding JWT も利用できます。

## 対応プロトコルとプロファイル

wallet は **OpenID4VCI 1.0** と **OpenID4VP 1.0** を実装しています。
**HAIP 1.0** は `Config.Profile` で選ぶプロファイルです。
`profile.Profile` のゼロ値は `profile.Final` で、`profile.HAIP` を選ぶと HAIP の制約が加わります。
OpenID4VCI Draft 13 と OpenID4VP Draft 24 は `Draft13()` と `Draft24()` のビューから利用でき、以前からある `ReceiveCredential` / `PresentCredential` も残っています。

| プロトコル / 機能 | 公開 API | 備考 |
| --- | --- | --- |
| OpenID4VCI 1.0 Pre-Authorized Code Flow | `AuthorizePreAuthorizedIssuance` + `RequestCredential` | `tx_code` は Offer が宣言しているときに限り必須です。 |
| OpenID4VCI 1.0 Authorization Code Flow（PKCE、PAR、RFC 9207 `iss`） | `BeginIssuance` + `AuthorizeIssuance` + `RequestCredential` | ライブラリはブラウザを開きません。PKCE は常に `S256` です。PAR は認可サーバーが広告する場合に使い、HAIP では必須です。Offer なしの wallet 起点の発行にも対応します。 |
| Credential Offer の値渡しと参照渡し | `ResolveCredentialOffer`、`ParseCredentialOfferURL` | `ParseCredentialOfferURL` は I/O を行いません。 |
| クライアント認証、DPoP | `Config.ClientAuth`、`Config.DPoP`、`Config.Attestation.Client` | `private_key_jwt` または OAuth 2.0 Attestation-Based Client Authentication です。`Config.DPoP.Key` があれば常に DPoP proof を送ります。 |
| Batch 発行 | `CredentialRequest.HolderKeys` | holder 鍵ごとに key proof を 1 つ送り、`batch_credential_issuance.batch_size` を上限とします。 |
| Key attestation（Appendix D） | `Config.Attestation.Key`、`CredentialRequest.KeyAttestation` | 送信前に attestation を認証します（`attestation.TrustPolicy`）。 |
| Credential Request / Response の暗号化 | `Config.Issuance.CredentialEncryption` | 応答用の鍵は一時鍵です。 |
| Deferred 発行 | `RequestDeferredCredential` | 1 回の呼出しで 1 リクエストを送ります。ライブラリはポーリングしません。 |
| Notification | `NotifyIssuer` | ライブラリが自ら通知することはありません。 |
| 署名付き Credential Issuer Metadata | `oid4vci.Oid4vciReceiver.IssuerMetadataSigning` | OpenID4VCI 1.0 §12.2.3 です。 |
| 保存前の Credential 受理判定 | `Config.CredentialAcceptance`（`acceptance.Policy`）、`VerifyCredentialForAcceptance` | OpenID4VCI 1.0 と Draft 13 ビューのすべてのメソッドが要求します。 |
| `direct_post` / `direct_post.jwt` 上の OpenID4VP 1.0 | `ParsePresentationRequest`、`ParsePresentationRequestObject`、`SelectCredentials`、`SubmitPresentation`、`DeclinePresentation`、`PresentCredential` | 要求には `*oid4vp.AdmittedRequest` ハンドルを通じて応答します。 |
| Verifier の認証 | `oid4vp.Oid4vpPresenter`（`RequestObjectValidation`、`PreRegisteredClients`） | `x509_san_dns`、`x509_hash`、`redirect_uri`、pre-registered client、`verifier_attestation`、`openid_federation` に対応します。[Verifier の認証](#verifier-authentication)を参照してください。 |
| `request_uri` の GET / POST と `wallet_nonce` | `ParsePresentationRequest` | POST では毎回新しい `wallet_nonce` と、設定があれば `wallet_metadata` を送ります。 |
| DCQL | `SelectCredentials`、`oid4vp.ResolveSatisfiableDCQLCredentials`、`oid4vp.ValidateDCQLMatches` | `credential_sets`、`claims`、`claim_sets`、`values`、nested / array の claim path、`multiple`、`aki` と `openid_federation` 種別の `trusted_authorities` に対応します。 |
| `transaction_data` | `Config.SupportedTransactionDataTypes` | key binding つきの `dc+sd-jwt` 提示に限ります。 |
| W3C Digital Credentials API（`dc_api`、`dc_api.jwt`、unsigned / signed / multi-signed） | `ParseDCAPIRequest` + `SubmitPresentation` | プロトコル処理のみです。platform が認証した origin は呼出し側が渡します。 |
| OpenID4VCI Draft 13 | `Draft13()`、`ReceiveCredential` | HAIP では拒否します。 |
| OpenID4VP Draft 24（Presentation Exchange） | `Draft24()` + `SubmitPresentation` | HAIP では拒否します。 |
| 形式 | `credential.SDJwtVC`、`credential.JwtVc`、`credential.LdpVc` | SD-JWT VC の issuer `typ` は `dc+sd-jwt` または `vc+sd-jwt` です。`ldp_vc` は Data Integrity の `eddsa-rdfc-2022` proof を使います。 |

**未実装。**
ISO mdoc（`mso_mdoc`）は mdoc / COSE / CBOR の serializer がないため、mdoc の提示を構築できません。
`decentralized_identifier` の Client Identifier Prefix は解析したうえで拒否します。
DCQL の `trusted_authorities` で評価するのは `aki` と `openid_federation` 種別で、他の種別（`etsi_tl`）の entry はどの Credential にも一致しません。

### プロファイル（Final と HAIP）

* **Final** は追加制約のない OpenID4VCI 1.0 と OpenID4VP 1.0 です。既定値であり、`profile.Profile` のゼロ値は `profile.Final` に正規化されます。
* **HAIP** は HAIP 1.0 の制約を加えます。`Config.Profile` で選び、receiver と presenter の plugin も同じ profile で構築します（`oid4vci.Oid4vciReceiver.Profile`、`oid4vp.Oid4vpPresenter.Profile`）。wallet が自ら構築する plugin には wallet の profile が設定されます。
* wallet は渡された plugin を変更しません。`NewWalletWithConfig` が確認する内容は[プロファイルの規則](#profile-rules)を参照してください。

## 1. 前提条件

* **対応している仕様:**
    - 受領: [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)（HAIP 1.0 は任意プロファイル）、OpenID4VCI Draft 13
    - 提示: [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)（HAIP 1.0 は任意プロファイル）、OpenID4VP Draft 24
    - 各機能の実装範囲の詳細は [VC Knots Coverage](./support-matrix.md) を参照してください。

### 1-1. Go環境の要件

* **Goのバージョン:** vcknots/wallet ライブラリは、`wallet/mise.toml` に固定されたバージョンの Go（Go 1.26.6）を要求します。
* **開発環境管理 (mise):**
    - 開発環境の管理には [mise](https://mise.jdx.dev/) の使用を推奨します。
    - `wallet` ディレクトリで `mise install` を実行すると、必要な Go バージョンがインストールされ、環境変数も設定されます。

```bash
# macOS
brew install mise

# Install via curl
curl https://mise.jdx.dev/install.sh | sh

# (From the root of the vcknots repository)
cd wallet
mise install
```

* **GOPRIVATE 環境変数:**
    - mise を使用しない場合は、以下の環境変数を手動で設定してください。設定しないと `go mod download` が失敗します。

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 1-2. サンプル実行環境の要件 (Issuer/Verifierサーバー)

このチュートリアルのサンプルコードは、対話する相手（Issuer と Verifier）が存在することを前提としています。
このリポジトリの Node.js ベースのサンプルサーバー（`server/`）が両方の役割を提供します。

wallet のサンプルコードを実行する前に、サーバーを起動してください。

```bash
# From the root of the vcknots repository
pnpm install

# Build the issuer+verifier module, the server-core module, and the server module
pnpm -F @trustknots/vcknots build
pnpm -F @trustknots/server-core build
pnpm -F @trustknots/server build

# Start the server (listens on http://localhost:8080)
pnpm -F @trustknots/server start
```

サーバーは、このチュートリアルで使用する以下のエンドポイントを提供します。

* `POST /configurations/:configurationId/offer`：Credential Offer の作成
* `POST /token`, `POST /nonce`, `POST /credentials`：OpenID4VCI の token、nonce、credential エンドポイント
* `POST /request`, `POST /request-object`：OpenID4VP の Authorization Request の作成
* `POST /callback`：Verifier の応答受け取りエンドポイント
* `GET /.well-known/openid-credential-issuer`, `GET /.well-known/oauth-authorization-server`：メタデータエンドポイント

* **ローカルテストでの HTTP 許可:** wallet はデフォルトで、Issuer と Verifier のエンドポイントに HTTPS を要求します。
ローカルのサンプルサーバーは HTTP で動作するため、ローカルテスト時は明示的に HTTP を許可してください。

```bash
export VCKNOTS_WALLET_HTTP_ALLOWED=true
```

この変数は、既定のディスパッチャや plugin を構築するとき（`NewWallet`、`receiver.WithDefaultConfig`、`presenter.WithDefaultConfig`）に読み取られます。
自分で構築した plugin は、この変数ではなく自身の `AllowHTTP` フィールドに従います。
テストコードからは `env.SetHTTPAllowed(true)`（パッケージ `github.com/trustknots/vcknots/wallet/env`）で設定できます。

> ⚠️ **セキュリティ警告**: 本番環境では `VCKNOTS_WALLET_HTTP_ALLOWED` も `AllowHTTP` も有効化しないでください。HAIP はどちらも拒否します。

## 2. 初期設定

このセクションでは、ライブラリの依存関係をインストールし、`Wallet` インスタンスを初期化する手順を説明します。

### 2-1. 依存関係のインストール

GOPRIVATE を設定した後、`wallet` ディレクトリで以下のコマンドを実行し、`go.mod` にリストされている依存ライブラリをダウンロードします。

```bash
go mod download
```

### 2-2. Walletの初期化

トップレベル API は `github.com/trustknots/vcknots/wallet` パッケージにあります。
`wallet.NewWallet()` は、すべてのディスパッチャを既定の plugin で初期化します。

```go
import "github.com/trustknots/vcknots/wallet"

func newDefaultWallet() (*wallet.Wallet, error) {
	return wallet.NewWallet()
}
```

`Wallet` は 6 つのディスパッチャを協調させます。

* `credstore.CredStoreDispatcher`：Credential の永続化（デフォルトは bbolt を使うローカルストレージ）
* `receiver.ReceivingDispatcher`：Credential 発行プロトコル（OpenID4VCI）
* `presenter.PresentationDispatcher`：Credential 提示プロトコル（OpenID4VP）
* `serializer.SerializationDispatcher`：Credential のシリアライズ（JWT-VC、SD-JWT VC、LDP-VC）
* `verifier.VerificationDispatcher`：署名の検証
* `idprof.IdentityProfileDispatcher`：DID とアイデンティティプロファイル（`did:key`、`did:jwk`）

plugin を設定するとき（たとえば OpenID4VP の Request Object に使うトラストルートを設定するとき）は、ディスパッチャを自分で構築して `wallet.NewWalletWithConfig` に渡します。
`wallet.Config` で `nil` のままにしたディスパッチャには既定の実装が補われます。
`wallet/examples/` 配下のサンプルは、次のように wallet を構築しています。

```go
package main

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/idprof"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

func newWallet(certPath string) (*wallet.Wallet, error) {
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	receiverDisp, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	serializerDisp, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	verifierDisp, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	// Trust roots for the x5c chain of signed OpenID4VP Request Objects.
	certFile, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certFile) {
		return nil, fmt.Errorf("failed to parse certificate: %s", certPath)
	}

	oid4vpPresenter := &oid4vp.Oid4vpPresenter{
		AllowHTTP:           env.IsHTTPAllowed(), // local sample server only
		X509TrustChainRoots: certPool,
	}
	presenterDisp, err := presenter.NewPresentationDispatcher(
		presenter.WithPlugin(presenter.Oid4vp, oid4vpPresenter),
	)
	if err != nil {
		return nil, err
	}

	return wallet.NewWalletWithConfig(wallet.Config{
		CredStore:  credStore,
		IDProfiler: idProf,
		Receiver:   receiverDisp,
		Serializer: serializerDisp,
		Verifier:   verifierDisp,
		Presenter:  presenterDisp,
	})
}
```

* **保存先:** 既定の Credential ストアは、`go.etcd.io/bbolt` を使って `<ユーザー設定ディレクトリ>/vcknots/wallet/.local_credstore.db`（Linux では `~/.config/vcknots/wallet/.local_credstore.db` など）に永続化します。`Config.Storeless` はストアを持たない wallet を構築します。受領した Credential は返されるだけで保存されず、提示には Credential を値で渡します。

## 3. Wallet機能のサンプル実装

このセクションでは、`wallet/examples/server_integration_sdjwt/server_integration_sdjwt.go` と `wallet/examples/common/common.go` をもとに、最小の受領と提示のサンプルを示します。
ここで使う `ReceiveCredential` と `PresentCredential` は、フロー全体を 1 回の呼出しで実行します。
ユーザーのいる wallet に必要な段階的 API は、[OpenID4VCI 1.0 の発行](#openid4vci-10-issuance)と [OpenID4VP 1.0 の提示](#openid4vp-10-presentation)で説明します。

### 3-1. テスト用の鍵の準備 (IKeyEntryインターフェース)

wallet が署名に使う鍵（holder、DPoP、クライアント認証、attester）はすべて `IKeyEntry` です。

```go
import "github.com/go-jose/go-jose/v4"

// IKeyEntry is a signing key.
type IKeyEntry interface {
	ID() string
	PublicKey() jose.JSONWebKey
	Sign(data []byte) ([]byte, error)
}
```

* **署名の形式:** ECDSA の `Sign` 実装は、DER エンコードの ASN.1 署名と生の IEEE P1363（`R || S`）署名のどちらを返してもかまいません。ライブラリが DER を P1363 に変換します。
* **アルゴリズム:** `PublicKey().Algorithm` が JWS アルゴリズムを決めます。空の場合は曲線で決まります（P-256、P-384、P-521 はそれぞれ ES256、ES384、ES512、Ed25519 は EdDSA）。RSA 鍵では必ず設定します。

`keystore.NewKeyEntryFromJWK` は EC の秘密鍵 JWK から `IKeyEntry` を作ります。
このチュートリアルでは、`wallet/examples/common/common.go` の `MockKeyEntry` に相当するインメモリの鍵を使います。

```go
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// MockKeyEntry is a test implementation of IKeyEntry.
type MockKeyEntry struct {
	id         string
	privateKey *ecdsa.PrivateKey
}

func NewMockKeyEntry() (*MockKeyEntry, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &MockKeyEntry{
		id:         "test-key-id-" + uuid.NewString(),
		privateKey: privKey,
	}, nil
}

func (m *MockKeyEntry) ID() string { return m.id }

func (m *MockKeyEntry) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       &m.privateKey.PublicKey,
		Algorithm: "ES256",
		Use:       "sig",
	}
}

// Sign hashes with SHA-256, signs with ECDSA and returns the IEEE P1363 form.
func (m *MockKeyEntry) Sign(payload []byte) ([]byte, error) {
	hash := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	const keySize = 32 // P-256
	signature := make([]byte, 2*keySize)
	r.FillBytes(signature[:keySize])
	s.FillBytes(signature[keySize:])
	return signature, nil
}
```

### 3-2. Credentialの受領 (OID4VCI)

`ReceiveCredential` は Pre-Authorized Code の発行を 1 回の呼出しで実行します。
実際の運用では Offer URI は QR コードやディープリンクから得ます。
ローカルのサンプルサーバーでは `POST /configurations/:configurationId/offer` で作成できます。

```go
import (
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/receiver"
)

func receiveSDJwtCredential(w *wallet.Wallet, key wallet.IKeyEntry, offerURI string) (*wallet.SavedCredential, error) {
	// openid-credential-offer://?credential_offer=...
	offer, err := wallet.ParseCredentialOfferURL(offerURI)
	if err != nil {
		return nil, err
	}

	return w.ReceiveCredential(wallet.ReceiveCredentialRequest{
		CredentialOffer: offer,
		Type:            receiver.Oid4vci,
		Key:             key,                // signs the key proof
		RequestedFormat: credential.SDJwtVC, // "application/dc+sd-jwt"
	})
}
```

`ReceiveCredentialRequest` の補足です。

* **RequestedFormat:** `credential.SDJwtVC` または `credential.JwtVc` を指定します。空の場合は、最初に提示された configuration の形式を使います。
* **TxCode:** Offer が要求する場合に、token エンドポイントへ `tx_code` として送ります。
* **CachedIssuerMetadata:** 設定すると Issuer メタデータを取得しません（セクション 4 を参照）。

`ReceiveCredential` は Issuer と認可サーバーのメタデータを取得し、pre-authorized code でアクセストークンを取得し、`Key` で key proof に署名して Credential を要求し、検査してから保存します。
検査には、`Config.CredentialAcceptance` が設定されていればそれを使います。
ポリシーがない場合は Credential を解析するだけで（`typ`、`alg`、`Key` と一致すべき `cnf`）、Issuer は認証しません。
`ReceiveCredential` は HAIP では拒否されます。
新しいコードでは `AuthorizePreAuthorizedIssuance` と `RequestCredential` を使います。

### 3-3. Credentialの提示 (OpenID4VP)

Verifier から `openid4vp:?...` 形式のリクエスト URI（ローカルのサンプルサーバーでは `POST /request` または `POST /request-object` で取得）を受け取ったら、`PresentCredential` を呼び出します。

```go
import (
	"log"

	"github.com/trustknots/vcknots/wallet"
	sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func presentCredential(w *wallet.Wallet, key wallet.IKeyEntry, oid4vpURI string) error {
	// Limits SD-JWT VC disclosure to these claims.
	options := &sdjwtvc.SdJwtVcPresentationOptions{
		SelectedClaims: []string{"given_name", "family_name"},
	}

	redirectURI, err := w.PresentCredential(oid4vpURI, key, options)
	if err != nil {
		return err
	}
	if redirectURI != "" {
		log.Printf("Verifier requested redirect: %s\n", redirectURI)
	}
	return nil
}
```

`PresentCredential` は `ParsePresentationRequest`、`SelectCredentials`、`SubmitPresentation` を 1 回の呼出しで行います。
presenter の信頼ポリシーの下で要求を受け付け（[Verifier の認証](#verifier-authentication)を参照）、DCQL クエリを満たす保存済み Credential を選び、Credential ごとに `key` で署名した提示を作り、要求が指定したエンドポイントへ応答を送ります。
Verifier が返す `redirect_uri` には接続しません。
その URI は戻り値として返り、ない場合は空文字列です。

* **提示オプション:** 第 3 引数は形式ごとのオプション値で、`nil` なら serializer の既定値を使います。KB-JWT の audience と nonce は常に要求から取ります。SD-JWT VC では、空でない `SelectedClaims` が開示を制限し、その範囲外のクレームを要求されると失敗します。Key Binding JWT は、DCQL クエリが holder binding を要求するとき（既定）、`RequireKeyBinding` を設定したとき、`transaction_data` を提示するとき、そして HAIP では Credential が `cnf` を持つときに常に付与します。
* **リダイレクトの扱い:** `PresentCredentialWithOptions` に `&wallet.PresentCredentialOptions{OnRedirect: func(uri string) error {...}}` を渡すと、Verifier のリダイレクト URI でコールバックします。
* **Draft 24:** `PresentCredential` が解析するのは OpenID4VP 1.0 の要求だけです。Presentation Exchange の要求には `Draft24()` を使います。

### 3-4. 保存されたCredentialの参照

`GetCredentialEntries` は、ページネーション（`Offset`、`Limit`）と Go のフィルタ（`Filter`）で保存済み Credential を列挙します。
`GetCredentialEntry` は ID で 1 件を返し、該当がない場合は `nil` とエラーなしを返します。

```go
import (
	"log"

	"github.com/trustknots/vcknots/wallet"
)

func listSavedCredentials(w *wallet.Wallet) ([]*wallet.SavedCredential, error) {
	limit := 10
	entries, total, err := w.GetCredentialEntries(wallet.GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  &limit,
		Filter: func(sc *wallet.SavedCredential) bool {
			return true // Example: return sc.Entry.MimeType == string(credential.SDJwtVC)
		},
	})
	if err != nil {
		return nil, err
	}

	log.Printf("Found %d matching entries (Total: %d)\n", len(entries), total)
	for _, entry := range entries {
		log.Printf(" - Entry ID: %s, MimeType: %s\n", entry.Entry.Id, entry.Entry.MimeType)
	}
	return entries, nil
}
```

## 4. Issuerメタデータの取得

`FetchCredentialIssuerMetadata` は Issuer の `.well-known/openid-credential-issuer` 文書を取得します。
`ReceiveCredential` は `ReceiveCredentialRequest.CachedIssuerMetadata` が設定されていなければ自分で取得します。
OpenID4VCI 1.0 のメソッドは常にメタデータを再取得し、キャッシュしたメタデータを受け取りません。

```go
import (
	"log"
	"net/url"

	"github.com/trustknots/vcknots/wallet"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func fetchIssuerMetadata(w *wallet.Wallet) (*receiverTypes.CredentialIssuerMetadata, error) {
	// The Credential Issuer Identifier; the well-known path is inserted internally.
	issuerURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		return nil, err
	}

	metadata, err := w.FetchCredentialIssuerMetadata(issuerURL, receiverTypes.Oid4vci)
	if err != nil {
		return nil, err
	}

	log.Printf("Fetched metadata for issuer: %s\n", metadata.CredentialIssuer)
	return metadata, nil
}
```

receiver は、`credential_issuer` が要求した識別子と異なるメタデータを拒否します（OpenID4VCI 1.0 §12.2.4）。

## 5. 型定義の説明

このセクションは `wallet` パッケージの主な型を挙げます。
フィールド単位の説明は [wallet/](https://github.com/trustknots/vcknots/tree/main/wallet) の Go doc にあります。

### IKeyEntry {#IKeyEntry}

署名鍵です（`ID()`、`PublicKey()`、`Sign()`）。
`keystore.KeyEntry` と同じメソッド集合を持つため、相互に変換できます。
[鍵と署名](#keys-and-signing)を参照してください。

### Config {#Config}

`NewWalletWithConfig` の入力です。
すべてのフィールドは任意です。

| フィールド | 意味 |
| --- | --- |
| `CredStore`、`IDProfiler`、`Receiver`、`Serializer`、`Verifier`、`Presenter` | ディスパッチャです。`nil` なら既定のものを構築します。注入した `Presenter` の OpenID4VP plugin は `*oid4vp.Oid4vpPresenter` でなければなりません。提示メソッドはその `*oid4vp.AdmittedRequest` handle に応答するためです。 |
| `Profile` | `profile.Final`（ゼロ値）または `profile.HAIP` です。 |
| `Storeless` | Credential ストアを持ちません。このとき `CredStore` は `nil` でなければならず、ストアを必要とするメソッドは `ErrNoCredentialStore` を返します。 |
| `CredentialAcceptance` | 受領した Credential を返す、または保存する前に適用する `*acceptance.Policy` です。`nil` の場合、OpenID4VCI 1.0 の全メソッド、`Draft13()` の全メソッド、`VerifyCredentialForAcceptance` が `ErrCredentialAcceptancePolicyRequired` で失敗します。 |
| `SupportedTransactionDataTypes` | wallet が構築する presenter の `transaction_data` の type です。`Presenter` と同時に設定すると拒否します。注入した plugin には `Oid4vpPresenter.SupportedTransactionDataTypes` を設定します。 |
| `DPoP` | [DPoPConfig](#DPoPConfig) です。 |
| `ClientAuth` | [ClientAuthConfig](#ClientAuthConfig) です。`ClientID` はすべての OpenID4VCI バージョンで wallet の `client_id` になります。 |
| `Issuance` | `IssuanceConfig{RedirectURI, CredentialEncryption}` で、Authorization Code Flow の `redirect_uri` と holder の `CredentialEncryptionPolicy` です。 |
| `Attestation` | `AttestationConfig{Client, ClientKey, Key, Trust}` で、client attestation と key attestation の provider、client attestation が束縛する鍵（`nil` なら `DPoP.Key`）、それらを認証する `attestation.TrustPolicy` です。 |
| `TestHooks` | `*TestHooks{KeyProof, PresentationExchangeResponse}` で、相手側の挙動を試すために Draft 13 の key proof と Draft 24 の応答を構築後に書き換えます。HAIP では拒否します。 |

### ReceiveCredentialRequest {#ReceiveCredentialRequest}

`ReceiveCredential` の入力です。
[CredentialOffer](#CredentialOffer)、受領プロトコル（`Type`）、key proof の鍵（`Key`）、要求する形式（`RequestedFormat`）、任意の `CachedIssuerMetadata` と `TxCode` を持ちます。

### CredentialOffer {#CredentialOffer}

Credential Offer です。
Issuer の URL（`CredentialIssuer`）、configuration ID（`CredentialConfigurationIDs`）、grant（`Grants`）を持ちます。
`CredentialOfferGrant` は `PreAuthorizedCode`、`TxCode`、`IssuerState`、`AuthorizationServer` のヒントを持ちます。

### SavedCredential {#SavedCredential}

受領または保存された Credential です。
`Credential`（解析結果）、`Entry`（保存エントリ: ID、生のバイト列、MIME タイプ、受領日時）、`Verification`（`*acceptance.Verification`、保存前に認証した内容。ストアから読み込んだ Credential では `nil`）を持ちます。

### GetCredentialEntriesRequest {#GetCredentialEntriesRequest}

`GetCredentialEntries` の検索条件です（`Offset`、`Limit`、`Filter`）。

### PresentCredentialOptions {#PresentCredentialOptions}

`PresentCredentialWithOptions` の入力です。
`SerializeOptions` と任意の `OnRedirect` コールバックを持ちます。

### SdJwtVcPresentationOptions {#SdJwtVcPresentationOptions}

SD-JWT VC の提示オプションです（パッケージ `serializer/plugins/sdjwtvc`）。
`SelectedClaims`、`RequireKeyBinding`、`LimitDisclosureToSelectedClaims`、`RequireRootClaimMatch` と、wallet が要求から埋める `Audience`、`Nonce`、`TransactionData`、`TransactionDataHashesAlg` を持ちます。

### DIDCreateOptions {#DIDCreateOptions}

`GenerateDID` のオプションです。
DID の種類（`TypeID`、例 `"did:key"`）と公開鍵（`PublicKey`）を指定します。

### DPoPConfig {#DPoPConfig}

`Key` は wallet の DPoP 鍵です。
OpenID4VCI 1.0 のメソッドは、`Key` が設定されていれば常に DPoP proof を送り、HAIP では `Key` が必須です（`ErrDPoPKeyRequired`）。
`Enabled` は `Key` が `nil` のときにインメモリ鍵を生成し、`Draft13()` と `ReceiveCredential` の経路で DPoP を強制します。
これらの経路は、`Enabled` がなければ認可サーバーが広告するときだけ DPoP を使います。

### ClientAuthConfig {#ClientAuthConfig}

token エンドポイントでのクライアント認証です。
`Method`（`""` は認証なし、または `receiverTypes.PrivateKeyJwt`）、`ClientID`、`Key`、`AssertionAudience`、`SigningAlg`（ES256、ES384、ES512）を持ちます。
`private_key_jwt` では、認可サーバーがその方式と署名アルゴリズムの両方を広告していなければならず、そうでなければ token リクエストを送りません（`client_authentication_unavailable`）。

## 6. Walletのメソッド

`*Wallet` のメソッドは 25 個です。

| 領域 | メソッド |
| --- | --- |
| 構築とストレージ | `SetReceiver`（非推奨）、`GetCredentialEntries`、`GetCredentialEntry`、`GenerateDID` |
| Credential の検査 | `VerifyCredential`、`VerifyCredentialForAcceptance` |
| OpenID4VCI 1.0 | `ResolveCredentialOffer`、`BeginIssuance`、`AuthorizeIssuance`、`AuthorizePreAuthorizedIssuance`、`RequestCredential`、`RequestDeferredCredential`、`NotifyIssuer` |
| OpenID4VCI の一括呼出しとメタデータ | `ReceiveCredential`、`FetchCredentialIssuerMetadata` |
| OpenID4VP 1.0 | `ParsePresentationRequest`、`ParsePresentationRequestObject`、`ParseDCAPIRequest`、`SelectCredentials`、`SubmitPresentation`、`DeclinePresentation` |
| OpenID4VP の一括呼出し | `PresentCredential`、`PresentCredentialWithOptions` |
| Draft ビュー | `Draft13()`（`BeginIssuance`、`AuthorizeIssuance`、`AuthorizePreAuthorizedIssuance`、`RequestCredential`、`RequestDeferredCredential`、`NotifyIssuer`）、`Draft24()`（`ParsePresentationRequest`、`ParsePresentationRequestObject`） |

`context.Context` を受け取るメソッドは、その context がキャンセルされると停止します。
メソッドが返すエラーにはすべてコードがあります（[エラーコード](#error-codes)を参照）。

### ReceiveCredential

Pre-Authorized Code Flow で Credential を受領し、保存します。

```go
func (w *Wallet) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error)
```

**パラメータ**:
- `req`: 受領リクエスト（[ReceiveCredentialRequest](#ReceiveCredentialRequest)）

**戻り値**:
- 受領し保存した Credential（[SavedCredential](#SavedCredential)）

### PresentCredential

OpenID4VP 1.0 の Authorization Request に、ライブラリ自身が選んだ Credential で応答します。

```go
func (w *Wallet) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error)
```

**パラメータ**:
- `uriString`: リクエスト URI（`openid4vp:?...`）
- `key`: holder 鍵（[IKeyEntry](#IKeyEntry)）
- `options`: 形式ごとの提示オプション（SD-JWT VC では [SdJwtVcPresentationOptions](#SdJwtVcPresentationOptions)）、または `nil`

**戻り値**:
- Verifier が返したリダイレクト URI、またはない場合は空文字列

### PresentCredentialWithOptions

`PresentCredential` と同じ処理を行い、Verifier のリダイレクト URI で `OnRedirect` を呼び出します。

```go
func (w *Wallet) PresentCredentialWithOptions(uriString string, key IKeyEntry, options *PresentCredentialOptions) (string, error)
```

### GetCredentialEntries

保存済み Credential を、任意のページネーションとフィルタで取得します。

```go
func (w *Wallet) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error)
```

**戻り値**:
- 一致した Credential と、一致した総数

### GetCredentialEntry

保存済み Credential を ID で 1 件取得します。該当がなければ `nil` とエラーなしを返します。

```go
func (w *Wallet) GetCredentialEntry(id string) (*SavedCredential, error)
```

### FetchCredentialIssuerMetadata

Credential Issuer Metadata を取得します。

```go
func (w *Wallet) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error)
```

### GenerateDID

公開鍵から DID を生成します。

```go
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error)
```

### VerifyCredential

Credential の proof が公開鍵で検証できるかを返します。受け付けるのは `acceptance.DefaultSigningAlgorithms()`（ES256）だけです。

```go
func (w *Wallet) VerifyCredential(credential *credential.Credential, pubKey jose.JSONWebKey) bool
```

### VerifyCredentialForAcceptance

発行時に保存前に行う検査と同じく、`Config.CredentialAcceptance` を生の Credential に適用します。何も保存しません。

```go
func (w *Wallet) VerifyCredentialForAcceptance(ctx context.Context, raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey) (*credential.Credential, *acceptance.Verification, error)
```

### SetReceiver

plugin を `NewWalletWithConfig` と同じく検査したうえで、receiver ディスパッチャを差し替えます。
拒否されたディスパッチャは設定されず、receiver を必要とするメソッドはすべてその拒否を返します。
非推奨です。`Config.Receiver` を使ってください。

```go
func (w *Wallet) SetReceiver(r *receiver.ReceivingDispatcher)
```

OpenID4VCI 1.0 と OpenID4VP 1.0 のメソッドは、次のセクションで説明します。

## OpenID4VCI 1.0 の発行 {#openid4vci-10-issuance}

### 段階的なフローと状態

OpenID4VCI 1.0 の発行は段階ごとに進み、各段階は次の段階が受け取る状態を返します。

| 段階 | メソッド | 戻り値 |
| --- | --- | --- |
| Offer の解決 | `ResolveCredentialOffer(ctx, raw)` | `*CredentialOffer` |
| Authorization Code Flow の開始 | `BeginIssuance(ctx, IssuanceRequest)` | `*IssuanceAuthorization` |
| 認可コードの交換 | `AuthorizeIssuance(ctx, authorization, redirectURL)` | `*IssuanceGrant` |
| pre-authorized code の交換 | `AuthorizePreAuthorizedIssuance(ctx, PreAuthorizedIssuanceRequest)` | `*IssuanceGrant` |
| Credential の要求 | `RequestCredential(ctx, grant, CredentialRequest)` | `*IssuanceResult` |
| Deferred トランザクションの 1 回の問合せ | `RequestDeferredCredential(ctx, deferred)` | `*IssuanceResult` |
| Issuer への通知 | `NotifyIssuer(ctx, notification, event, description)` | `error` |

状態の型（`IssuanceAuthorization`、`IssuanceGrant`、`DeferredIssuance`、`IssuanceNotification`）は JSON にシリアライズでき、`Version` を持つので、段階を別プロセスで実行できます。
状態が持つのは識別子と秘密だけです。
各段階は Issuer と認可サーバーのメタデータを再取得し、状態がまだ wallet に合っているか（同じ `ClientAuth.ClientID`、`Issuance.RedirectURI`、DPoP 鍵であり、Issuer がまだその認可サーバーに委任しているか）を確認して、合わなければ `ErrIssuanceStateMismatch` で拒否します。
別の OpenID4VCI バージョンの状態は `ErrIssuanceVersionMismatch` で拒否します。

**状態の JSON は bearer secret です。**
PKCE の `code_verifier`、アクセストークン、または応答復号用の一時鍵を含みます。
サーバー側か暗号化して保管し、ログに出さないでください。

OpenID4VCI 1.0 のすべてのメソッドは `Config.CredentialAcceptance` を要求します。
HAIP では、各段階が `Config.DPoP.Key` も要求し、PAR または token エンドポイントを呼ぶ段階（`BeginIssuance`、`AuthorizeIssuance`、`AuthorizePreAuthorizedIssuance`）はクライアント認証の手段（`private_key_jwt` または `Config.Attestation.Client`、HAIP §4.4.1）も要求します。

### Authorization Code Flow

`BeginIssuance` はメタデータを解決し、Credential Configuration を profile と `Config.Issuance.CredentialEncryption` に照らして確認し、サーバーが RFC 9126 PAR に対応していれば認可リクエストを push して（HAIP では必須）、holder のブラウザで開く URL を返します。
`AuthorizeIssuance` はブラウザが届けたリダイレクト URL 全体を受け取り、検査して（RFC 6749 §4.1.2、RFC 9207 の `iss`、`state`、`redirect_uri`）認可コードを交換します。

```go
import (
	"context"
	"encoding/json"

	"github.com/trustknots/vcknots/wallet"
)

// beginIssuance starts an Authorization Code Flow from a Credential Offer URI.
// The caller opens authorizationURL in the holder's browser and keeps state.
func beginIssuance(ctx context.Context, w *wallet.Wallet, offerURI string) (state []byte, authorizationURL string, err error) {
	offer, err := w.ResolveCredentialOffer(ctx, offerURI)
	if err != nil {
		return nil, "", err
	}
	authorization, err := w.BeginIssuance(ctx, wallet.IssuanceRequest{CredentialOffer: offer})
	if err != nil {
		return nil, "", err
	}
	state, err = json.Marshal(authorization) // a bearer secret
	return state, authorization.AuthorizationURL, err
}

// finishIssuance continues from the redirect the holder's browser delivered.
func finishIssuance(ctx context.Context, w *wallet.Wallet, state []byte, redirectURL string, holderKey wallet.IKeyEntry) (*wallet.IssuanceResult, error) {
	var authorization wallet.IssuanceAuthorization
	if err := json.Unmarshal(state, &authorization); err != nil {
		return nil, err
	}
	grant, err := w.AuthorizeIssuance(ctx, &authorization, redirectURL)
	if err != nil {
		return nil, err
	}
	return w.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{holderKey},
	})
}
```

* **wallet 起点の発行:** `CredentialOffer` を nil にし、`IssuanceRequest.CredentialIssuer` と `CredentialConfigurationID` を設定します。
* **`AuthorizationRequestType`:** 空の値は、configuration が `scope` を広告していれば `scope`、そうでなければ `authorization_details` を使います。`AuthorizationRequestScope` と `AuthorizationRequestDetails` はどちらかを強制します。HAIP が認めるのは `scope` だけです。
* **リダイレクトの検査:** `ErrAuthorizationRedirectInvalid`、`ErrAuthorizationRedirectURIMismatch`、`ErrAuthorizationStateMismatch`、`ErrAuthorizationIssMismatch`、`ErrAuthorizationIssMissing`、`ErrAuthorizationCodeMissing` は `errors.Is` で判定できます。`error=` のリダイレクトは `*AuthorizationResponseError` になります。
* **`request_uri` の有効期間:** `IssuanceAuthorization.RequestURIExpired(now)` は、push した `request_uri` をまだ開けるかを返します。制限するのは URL を開くことだけで、リダイレクトはその後に届いてもかまいません。
* **エンドポイントの拒否:** メタデータ、PAR、token、nonce の各エンドポイントは `Stage` を示す `*oid4vci.EndpointError` を報告し、Credential と Deferred Credential のエンドポイントは §8.3.1.2 のエラーコードを持つ `*receiverTypes.CredentialEndpointError` を報告します。

### Pre-Authorized Code Flow

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
)

func receivePreAuthorized(ctx context.Context, w *wallet.Wallet, offerURI, txCode string, holderKey wallet.IKeyEntry) (*wallet.IssuanceResult, error) {
	offer, err := w.ResolveCredentialOffer(ctx, offerURI)
	if err != nil {
		return nil, err
	}
	grant, err := w.AuthorizePreAuthorizedIssuance(ctx, wallet.PreAuthorizedIssuanceRequest{
		CredentialOffer: offer,
		TxCode:          txCode, // required exactly when the offer carries tx_code
	})
	if err != nil {
		return nil, err
	}
	return w.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{holderKey},
	})
}
```

`private_key_jwt` または `Config.Attestation.Client` で認証しない限り、クライアントは匿名です。
`Config.ClientAuth.ClientID` は設定されていれば送信し、HAIP ではその設定が必須です。

### Credential の要求、Deferred 発行、通知

`RequestCredential` は holder 鍵ごとに key proof を 1 つ送り（複数なら batch 要求になります）、必要に応じて key attestation を付け、`Config.Issuance.CredentialEncryption` に従ってリクエストと応答を暗号化します。
Credential は `Config.CredentialAcceptance` で検査し、storeless でなければ保存します。
`IssuanceResult` は `Credentials` か保留中の `Deferred` トランザクションのどちらかを持ち、Issuer が通知を求めた場合は `Notification` も持ちます。
Credential を拒否した場合は、`credential_failure` を報告するための `Notification` を持つ結果がエラーと一緒に返ります。

ライブラリが自らポーリングや通知を行うことはありません。

```go
import (
	"context"
	"time"

	"github.com/trustknots/vcknots/wallet"
)

// completeIssuance polls a deferred transaction and reports the outcome to the
// issuer.
func completeIssuance(ctx context.Context, w *wallet.Wallet, result *wallet.IssuanceResult, err error) error {
	for err == nil && result.Deferred != nil {
		wait := max(result.Deferred.Interval, 5*time.Second)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		result, err = w.RequestDeferredCredential(ctx, result.Deferred)
	}
	if err != nil {
		if result != nil && result.Notification != nil {
			_ = w.NotifyIssuer(ctx, result.Notification, wallet.NotificationCredentialFailure, "")
		}
		return err
	}
	if result.Notification != nil {
		return w.NotifyIssuer(ctx, result.Notification, wallet.NotificationCredentialAccepted, "")
	}
	return nil
}
```

`DeferredIssuance.Interval` は Issuer が求めた間隔で、どれだけ待つかは呼出し側が決めます。
`NotifyIssuer` は再取得したメタデータから `notification_endpoint` を見つけ、`credential_accepted`、`credential_failure`、`credential_deleted` のいずれかを送ります。

### Key attestation

Issuer が key attestation を要求していて（`key_attestations_required`、OpenID4VCI 1.0 Appendix D）、`CredentialRequest.KeyAttestation` と `Config.Attestation.Key` のどちらからも得られない場合、`RequestCredential` は何も送らずに `*KeyAttestationRequiredError` を返します。
このエラーは attestation が覆うべき内容を示すので、別プロセスの attester が署名できます。

```go
import (
	"context"
	"errors"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/attestation"
)

func requestWithKeyAttestation(ctx context.Context, w *wallet.Wallet, grant *wallet.IssuanceGrant, holderKey wallet.IKeyEntry,
	sign func(context.Context, attestation.KeyRequest) (string, error)) (*wallet.IssuanceResult, error) {
	request := wallet.CredentialRequest{HolderKeys: []wallet.IKeyEntry{holderKey}}
	result, err := w.RequestCredential(ctx, grant, request)
	var required *wallet.KeyAttestationRequiredError
	if !errors.As(err, &required) {
		return result, err
	}
	jwt, err := sign(ctx, attestation.KeyRequest{
		Keys:     required.HolderKeys,
		Nonce:    required.CNonce,
		Audience: required.Audience,
	})
	if err != nil {
		return nil, err
	}
	request.KeyAttestation = &attestation.KeyAttestation{JWT: jwt}
	return w.RequestCredential(ctx, required.Grant, request)
}
```

`NonceRejected` は、渡した attestation の nonce が異なっていたか、Issuer が `invalid_nonce` と答えたときに設定され、そのとき `Grant` は新しい `c_nonce` を持ちます。
`IssuerRequired` は、attestation を `IncludeKeyAttestation` で自発的に付けただけのとき false です。

### Credential の暗号化

`Config.Issuance.CredentialEncryption` は、Credential Request（§8.1）と Credential Response（§8.2）の暗号化に関する holder のポリシーです。
`Request` と `Response` はそれぞれ次のいずれかです。
`CredentialEncryptionFollowIssuer` は Issuer が広告するものを暗号化し、Issuer が要求すれば従います。
`CredentialEncryptionRequired` は暗号化を提供しない Issuer を拒否します（`ErrCredentialEncryptionUnavailable`）。
`CredentialEncryptionDisabled` は暗号化を要求する Issuer を拒否します（`ErrCredentialEncryptionDisallowed`）。
応答用の鍵は暗号化されたリクエストの中でしか運ばれないため、応答の暗号化を必須にするとリクエストの暗号化も必須になります。
矛盾は `BeginIssuance` または `AuthorizePreAuthorizedIssuance` で拒否します。
応答の復号鍵は一時鍵で、`DeferredIssuance` に含まれて運ばれます。
暗号化を要求した後の平文の応答は拒否します。

### クライアント認証、DPoP、attestation

* **`private_key_jwt`:** `Config.ClientAuth` に `Method: receiverTypes.PrivateKeyJwt`、`ClientID`、`Key` を設定します。パッケージ `clientconfig` は JSON の登録ファイルからこれを読み込みます。
* **Attestation-Based Client Authentication:** `Config.Attestation.Client`（`attestation.ClientProvider`）が、選択した認可サーバー向けの Wallet Attestation を提供します。PoP は `Config.Attestation.ClientKey`、それが nil なら `Config.DPoP.Key` で署名します。
* **Key attestation:** `Config.Attestation.Key`（`attestation.KeyProvider`）です。
* **DPoP:** proof は `Config.DPoP.Key` で署名し、DPoP に束縛された grant は同じ鍵で提示しなければなりません（`ErrDPoPKeyMismatch`）。サーバーが求めた場合は `use_dpop_nonce` による再試行を 1 回行います。

ライブラリが attester の秘密鍵を保持することはありません。
attestation は送信前に `Config.Attestation.Trust`（`attestation.TrustPolicy`）で認証します。
`x5c` を持つ attestation はその leaf 鍵で検証し、`TrustAnchors` か `RootCAs` があればチェーンも検証します。
`x5c` を持たない attestation には `ResolveKey` が必要です。
パッケージ `attestation` の `StaticClientAttester` と `StaticKeyAttester` は、テストと単一運用者の構成のために、ローカルの鍵で自己発行します。
これらの鍵は wallet が自ら解決します。
HAIP では、attestation は自己署名でない `x5c` leaf を持ち、トラストアンカーを含んではなりません。
拒否された attestation は `attestation.ErrClientAttestationInvalid` または `attestation.ErrKeyAttestationInvalid` になります。

### 署名付き Issuer メタデータ

`oid4vci.Oid4vciReceiver.IssuerMetadataSigning` は、OpenID4VCI 1.0 §12.2.3 の署名付き Credential Issuer Metadata を設定します。
`Request` は署名付きメタデータを求める `Accept` ヘッダーを送り、トラスト情報がなければ効果がありません。
`Require` は署名のない文書を拒否します。
署名者は `x5c` ヘッダーから `TrustAnchors` または `RootCAs` に照らして認証し、`sub` と `credential_issuer` はどちらも要求した識別子でなければなりません。
`RequireIssuerDNSBinding` と `ExpectedLeafDNSName` は leaf 証明書の DNS 束縛を加えます。
このポリシーは再取得のたびに適用されます。

署名付き文書の拒否はすべて `errors.Is(err, ErrIssuerMetadataSignatureInvalid)` を満たし、`ErrIssuerMetadataSubjectMismatch`、`ErrIssuerMetadataLeafDNSMismatch`、`ErrIssuerMetadataExpired` はこれをラップします。
`ErrIssuerMetadataSignatureRequired` は `Require` の結果です。
`CredentialIssuerMetadata.MetadataSignature` は受け入れた署名者を記録し、`RawDocument` は受け入れた文書を保持します。

`oid4vci.Oid4vciReceiver.IssuerMetadataFederation`（wallet の `TrustAnchors` と探索の上限を持つ `*federation.Resolver`）は、メタデータを OpenID Federation でだけ公開する Issuer に対応します。
メタデータ文書が 404 を返したとき、Trust Anchor のいずれかへの Trust Chain から、chain の metadata policy を適用して導いた `openid_credential_issuer` メタデータを使います。その `credential_issuer` も要求した識別子でなければなりません。
有効な chain がなければ探索は失敗します。
federation のメタデータは §12.2.3 の署名付きメタデータではないため、`IssuerMetadataSigning.Require` が設定されていれば参照しません。

### Draft 13

`w.Draft13()` は、同じ段階的メソッドと状態の型で OpenID4VCI Draft 13 を実行します。
状態は `IssuanceVersionDraft13` を持ちます。
Credential Offer が必須で、`c_nonce` は Token Response と Credential Response から得て、key proof は 1 つだけ送り、key attestation と Credential の暗号化はありません。
`Config.TestHooks.KeyProof` はテストのために key proof を書き換えます。

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
)

func receiveDraft13(ctx context.Context, w *wallet.Wallet, offerURI, txCode string, holderKey wallet.IKeyEntry) (*wallet.IssuanceResult, error) {
	offer, err := wallet.ParseCredentialOfferURL(offerURI)
	if err != nil {
		return nil, err
	}
	draft13 := w.Draft13()
	grant, err := draft13.AuthorizePreAuthorizedIssuance(ctx, wallet.PreAuthorizedIssuanceRequest{
		CredentialOffer: offer,
		TxCode:          txCode,
	})
	if err != nil {
		return nil, err
	}
	return draft13.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{holderKey},
	})
}
```

## Credential の受理

パッケージ `acceptance` は、受領した Credential を保存してよいかを判定します。
wallet を必要とせず、`acceptance.NewAcceptor(profile, serializer, verifier)` が返す `Acceptor` の `Verify(ctx, raw, policy, options)` が `acceptance.Policy` を適用します。
wallet は Credential を返す、または保存する前に、`Config.CredentialAcceptance` で同じ検査を実行します。

検査の内容は次のとおりです。

* **解析とヘッダー:** Credential が解析でき、issuer JWT が `Policy.SigningAlgorithms`（既定は `acceptance.DefaultSigningAlgorithms()`、ES256）のアルゴリズムを持ち、SD-JWT VC では `typ` が `dc+sd-jwt` または `vc+sd-jwt` であること。
* **Issuer の鍵:** `IssuerX509` は `x5c` チェーンを検証します（アンカー、CRL による失効確認、任意の EKU と `RequireIssuerDNSBinding`）。`ResolveIssuerKeys` と `ResolveIssuerKeysFromClaims` は、使える `x5c` がない Credential の候補鍵を提供します。`IssuerX509` が設定されていれば `x5c` を持つ Credential には使いませんが、どのアンカーにも届かないチェーンに `ResolveIssuerKeysWhenX5CUntrusted` が適用される場合は例外です。
* **holder binding:** `cnf.jwk` は Credential を要求した holder 鍵と一致しなければなりません。`RequireHolderBinding` は `cnf` のない Credential も拒否します。
* **有効性:** 署名、`exp` / `nbf`（`ClockSkew` を考慮）、SD-JWT の disclosure の整合性と `_sd_alg`、設定されていれば `ExpectedSDJWTVCType`。
* **`ldp_vc`:** `eddsa-rdfc-2022` の Data Integrity proof を、`ResolveIssuerKeys`（proof の `verificationMethod` を `kid`、`EdDSA` を `alg` として呼ばれます）が返す鍵と、`Policy.DataIntegrityContexts` に固定した JSON-LD context で検証します。`verificationMethod` は credential の `issuer` に属する必要があり、有効期間は `validFrom` / `validUntil` です。発行では holder との束縛を `did:key` または `did:jwk` の `credentialSubject.id` で判定します。`IssuerX509` は適用されず、`UnverifiedIssuer` は適用されます。

`acceptance.Verification`（`SavedCredential.Verification` も同じ）は、Issuer の鍵、証明書のフィンガープリント、失効確認の件数、holder binding の結果を記録します。
失敗はパッケージ `acceptance` のセンチネル（`ErrIssuerKeyUnresolved`、`ErrIssuerSignatureInvalid`、`ErrHolderBindingMismatch` など）をラップします。
信頼できない、または失効したチェーンは、パッケージ `common/x509` の `*x509.SigningChainError` または `*x509.CRLCheckError` になります。

### fail-closed の既定値

* OpenID4VCI 1.0 のメソッド、`Draft13()` のメソッド、`VerifyCredentialForAcceptance` でポリシーが `nil` の場合は、何も保存しません（`ErrCredentialAcceptancePolicyRequired`）。ポリシーのない `ReceiveCredential` は Credential を解析するだけです。
* `UnverifiedIssuer: true` は Issuer を認証せずに Credential を受け入れます。`IssuerX509` もリゾルバも設定されていないときだけ適用され、その他の検査は実行されます。
* HAIP では SD-JWT VC に `IssuerX509` が必要です（HAIP §6.1.1）。`x5c` を持たなければならず（`ErrHAIPX5CRequired`）、トラストアンカーを含んではならず（`ErrHAIPTrustAnchorInX5C`）、`UnverifiedIssuer` は適用されません。
* `AllowUnadvertisedRevocation` は、CRL 配布点を持たない証明書を信頼経路に残し、別に数えて報告します。OCSP は参照しません。

## OpenID4VP 1.0 の提示 {#openid4vp-10-presentation}

### 受け付けた要求

提示要求は一度だけ解析して受け付け、その解析が返したハンドルを通じて応答します。
`*oid4vp.AdmittedRequest` は、どの presenter が要求を受け付けたかと、応答の送り先を記録します。
エンドポイントを呼出し側から受け取ることはなく、ハンドルに応答できるのはそれを受け付けた presenter だけです（`oid4vp.ErrRequestNotAdmittedHere`）。

| メソッド | 目的 |
| --- | --- |
| `ParsePresentationRequest(ctx, uri)` | Authorization Request URI を解析して受け付けます。`request_uri` は参照先を取得します。 |
| `ParsePresentationRequestObject(ctx, requestObject, src)` | 呼出し側が既に持つ Request Object を認証します。 |
| `ParseDCAPIRequest(ctx, invocation)` | Digital Credentials API の要求を受け付けます。 |
| `SelectCredentials(ctx, h)` | ライブラリ自身が選ぶ保存済み Credential です。 |
| `SubmitPresentation(ctx, h, Presentation)` | 検査、シリアライズ、応答の送信を行います。 |
| `DeclinePresentation(ctx, h, code, description)` | OpenID4VP のエラー応答（§8.5）を送ります。 |

`h.Request()` は同意画面のために解析済み要求のコピーを返し、`h.ResponseEndpoint()` はエンドポイント（DC API では nil）を、`h.RequestObject()` は要求の認証に使った Request Object を返します。

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

func presentWithConsent(ctx context.Context, w *wallet.Wallet, uri string, holderKey wallet.IKeyEntry,
	consent func(oid4vp.CredentialPresentationRequest, []wallet.CredentialSelection) bool) (*presenterTypes.SubmitResult, error) {
	request, err := w.ParsePresentationRequest(ctx, uri)
	if err != nil {
		return nil, err
	}
	selections, err := w.SelectCredentials(ctx, request)
	if err != nil {
		return nil, err
	}
	if !consent(request.Request(), selections) {
		return w.DeclinePresentation(ctx, request, string(oid4vp.AccessDeniedError), "the holder declined")
	}
	return w.SubmitPresentation(ctx, request, wallet.Presentation{
		Key:         holderKey,
		Credentials: selections,
	})
}
```

`Presentation` は既定の holder 鍵 `Key`、`Credentials`、任意の `SerializeOptions` を持ちます。
各 `CredentialSelection` は、保存済み Credential を `CredentialID` で指定するか `Credential` で値として渡し（storeless の wallet では値渡しが必須）、答える DCQL の `QueryIDs` を列挙し、必要に応じて `DisclosedClaims`（holder が残した disclosure 名。nil なら要求されたクレームをすべて残します）と固有の `Key` を設定します。
選択が要求に答えていなければ、`SubmitPresentation` は何も送りません。
`SubmitResult` は Verifier の `RedirectURI`、DC API 要求の `DCAPIResponse`、`Encrypted` を持ちます。

### 解析と提示を分けるとき

ハンドルはシリアライズできません。
同意画面と提示を別のリクエストで行う wallet は、Request Object を保持しておき、もう一度解析します。
2 回目の解析では Request Object を `exp` も含めて再び認証します。

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

// requestSource records how the admitted Request Object reached the wallet.
func requestSource(request *oid4vp.AdmittedRequest) presenterTypes.RequestObjectSource {
	parsed := request.Request()
	source := presenterTypes.RequestObjectSource{ClientID: parsed.ClientID}
	if verification := parsed.RequestObjectVerification; verification != nil {
		source.DeliveredByReference = verification.Delivery == "reference"
		source.WalletNonce = verification.WalletNonce
	}
	return source
}

// presentLater answers a request admitted earlier from its kept Request Object.
func presentLater(ctx context.Context, w *wallet.Wallet, requestObject string, source presenterTypes.RequestObjectSource,
	p wallet.Presentation) (*presenterTypes.SubmitResult, error) {
	request, err := w.ParsePresentationRequestObject(ctx, requestObject, source)
	if err != nil {
		return nil, err
	}
	return w.SubmitPresentation(ctx, request, p)
}
```

プレーンなパラメータの要求には Request Object がない（`RequestObject()` が空）ので、その URI をもう一度解析します。
`RequestObjectSource.DeliveredByReference` は Request Object を `request_uri` から取得したことを表し、値で渡された Request Object でも HAIP §5.1 の配送規則を満たせるようにします。
wallet 自身の以前の解析がその取得を記録したときだけ設定してください。

### Verifier の認証 {#verifier-authentication}

`oid4vp.Oid4vpPresenter` は Client Identifier Prefix に応じて Verifier を認証します。

| Prefix | 認証 |
| --- | --- |
| `x509_san_dns`、`x509_hash` | 署名付き Request Object が必須です。`x5c` チェーンは `RequestObjectValidation.TrustAnchors` / `RootCAs`（または `X509TrustChainRoots`）に届かなければならず、CRL で失効を確認します。`x509_san_dns` は DNS SAN と応答エンドポイントを、`x509_hash` は leaf 証明書のハッシュを束縛します。HAIP は `x509_hash` を要求します。 |
| `redirect_uri` | 署名なしのみです。応答エンドポイントを識別子に束縛しますが、誰も認証しません。 |
| なし（pre-registered） | client は `PreRegisteredClients` にあるか、`ResolvePreRegisteredClient` で見つからなければなりません（`oid4vp.ErrPreRegisteredClientUnknown`）。登録された `Metadata` が要求のメタデータに代わり、その `Metadata.RedirectURIs` だけが応答エンドポイントとして受け入れられます。これがない登録はどの要求も受け入れません。署名付き Request Object は登録された `JWKS` で検証し、`RequireSignedRequestObject` は署名なしの要求を拒否します。 |
| `verifier_attestation` | 署名付き Request Object が必須です。Verifier Attestation JWT は `RequestObjectValidation.VerifierAttestationIssuers` のいずれかが発行したものでなければならず、Request Object はその `cnf` 鍵で署名されていなければなりません。 |
| `openid_federation` | `RequestObjectValidation.Federation.TrustAnchors` への Trust Chain で認証し、Request Object はチェーンの鍵で検証します。署名なしの要求は、`FederationTrustOptions.AllowUnsignedRequests` を設定しない限り拒否します。 |
| `decentralized_identifier` | 拒否します。 |
| `origin`、`web-origin` | 拒否します（`ErrClientIDPrefixReserved`）。 |

署名を要求する prefix の要求がプレーンなパラメータで届いた場合は、`ErrRequestObjectSignatureRequired` で拒否します。
解析済み要求の `RequestObjectVerification` は、認証した内容（証明書のフィンガープリントと `Certificate` の要約、失効確認の件数、echo された `WalletNonce`、`Delivery`、`ExpiresAt`、`VerifierAttestation` または `Federation` の証跡）を記録します。
要求のパラメータからこの値を設定することはできません。

`RequestObjectValidationOptions` は Relying Party 側のポリシーで、`TrustAnchors` または `RootCAs`、`CRL`、`AllowUnadvertisedRevocation`、`CertificateKeyUsages`、`WalletAudience`、`SigningAlgorithms`（既定は ES256 と RS256）、`RequireExpiry`、`MaxAge`（ゼロのとき HAIP は 10 分を使います）、`Now`、`ClockSkew` を持ちます。
`iat` が未来の Request Object は拒否するので、受け入れる Verifier の時計のずれに合わせて `ClockSkew` を設定してください。
`X509TrustChainRoots` だけを使う場合は、失効情報を公開していない証明書も受け入れます。
`RequestObjectValidation` のアンカーと併用はできません。

`InsecureSkipX509Verify` が適用されるのは Draft 24 の入口だけです。
これを設定すると OpenID4VP 1.0 の経路はすべての署名付き Request Object を拒否し、HAIP はその presenter を拒否します。

### DCQL

`SelectCredentials` は、`credential_sets`（`options`、`required`）、`claims`、`claim_sets`、`values`、nested と array の claim path（OpenID4VP 1.0 §7）、`multiple`、`meta`（`vct_values`、`type_values`）、`aki` と `openid_federation` 種別の `trusted_authorities` を評価します。`openid_federation` の値は、Credential の issuer から `RequestObjectValidation.Federation` の Trust Anchor への Trust Chain（その設定の下で解決）がその値を含むときに一致します（OpenID4VP 1.0 §6.1.1.3）。Trust Anchor が設定されていなければ何にも一致しません。`oid4vp.DCQLCredentialCandidate` を自分で組み立てる呼び出し側は、`Issuer` を設定し、照合の前に `AdmittedRequest.ResolveFederationTrustedAuthorities` を呼びます。
必須の各 credential query について、それを満たす Credential を、満たせる最初の claim set とともに選びます。
ストアが答えられない要求は、コード `access_denied` の `*oid4vp.AuthorizationRequestError` になります。
holder binding を要求する query からは、holder binding のない Credential を除外します。
`jwt_vc_json` と `ldp_vc` の claim path は Credential を起点にします（`["credentialSubject","given_name"]`）。

holder が候補から選ぶ wallet は `oid4vp.ResolveDCQLClaimSets` と `oid4vp.ValidateDCQLMatches` を使います。
`SubmitPresentation` は渡された選択に同じ検証を適用します（`oid4vp.ErrDCQLSelectionUnsatisfied`）。

### `transaction_data`

`Config.SupportedTransactionDataTypes`（注入した presenter では `Oid4vpPresenter.SupportedTransactionDataTypes`）は、wallet が処理する `transaction_data` の type を列挙します。
リストが空の場合、`transaction_data` を含む要求はすべて `invalid_transaction_data` で拒否します。
各 entry は要求内の credential query を参照しなければなりません。
transaction data を運ぶのは Key Binding JWT 付きの `dc+sd-jwt` の提示だけです。
参照される `dc+sd-jwt` の query は holder binding を要求していなければならず、他の形式に割り当てられた entry は何かを送る前に失敗します。
各 entry は提示する Credential の 1 つに束縛され（§5.1）、ハッシュアルゴリズムは entry の `transaction_data_hashes_alg` から決まります（既定は `sha-256`）。
Draft 24 の要求も同じ規則に従います。
`credential_ids` は input descriptor（または Draft 24 の credential query）を指し、それぞれ SD-JWT VC（`vc+sd-jwt`）を受け付けなければなりません。

### 応答モードと暗号化

リクエスト URI と Request Object は `direct_post` か `direct_post.jwt` を使い、DC API の要求は `dc_api` か `dc_api.jwt` を使います。
それぞれの経路は他方のモードを拒否します。
HAIP は `direct_post.jwt` を、DC API では `dc_api.jwt` を要求します。
`direct_post.jwt` と `dc_api.jwt` には `client_metadata.jwks` の暗号化鍵が必要です（`ErrResponseEncryptionKeyMissing`）。
応答は A128GCM または A256GCM の ECDH-ES JWE で、A256GCM を優先します。
HAIP では Verifier が両方を列挙していなければなりません（`ErrResponseEncryptionEncMissing`）。
これらの検査は同意の前、解析時に行います。

応答の POST と `request_uri` の取得はリダイレクトに従いません。
2xx 以外の応答は `*oid4vp.VerifierResponseError` になります。

### エラー応答

`DeclinePresentation` は受け付けた要求にエラー応答を返し、Verifier のメタデータが許せば `direct_post.jwt` で暗号化します（§8.3.1）。
受け付けに失敗した要求には、既定では応答しません。
そのエンドポイントは認証されていない要求が指定したものだからです。
`AuthorizationRequestError.SendErrorResponse(ctx, client)` は、`ResponseURI()` が設定された署名なしの `redirect_uri` 要求の拒否についてエラー応答を送ります。
`Oid4vpPresenter.SendParseErrorResponses` を設定すると、presenter が解析時にこれを行います。

### Digital Credentials API

`ParseDCAPIRequest` は W3C Digital Credentials API の呼出し（`openid4vp-v1-unsigned`、`openid4vp-v1-signed`、`openid4vp-v1-multisigned`）を受け付けます。
platform が認証した origin は呼出し側が渡し、要求の中から読むことはありません。
`SubmitPresentation` は HTTP 呼出しを行わず、platform に返すオブジェクトを返します。
`dc_api` では `{"vp_token": {...}}`、`dc_api.jwt` では `{"response": <JWE>}` です。
Key Binding JWT の `aud` は `origin:<origin>` です（OpenID4VP 1.0 Appendix A.4）。

```go
import (
	"context"
	"encoding/json"

	"github.com/trustknots/vcknots/wallet"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

func answerDCAPI(ctx context.Context, w *wallet.Wallet, protocol string, data json.RawMessage, origin string,
	holderKey wallet.IKeyEntry) (*presenterTypes.DCAPIResponse, error) {
	request, err := w.ParseDCAPIRequest(ctx, presenterTypes.DCAPIInvocation{
		Request: presenterTypes.DCAPIRequest{Protocol: protocol, Data: data},
		Origin:  origin, // authenticated by the platform
	})
	if err != nil {
		return nil, err
	}
	selections, err := w.SelectCredentials(ctx, request)
	if err != nil {
		return nil, err
	}
	result, err := w.SubmitPresentation(ctx, request, wallet.Presentation{Key: holderKey, Credentials: selections})
	if err != nil {
		return nil, err
	}
	return result.DCAPIResponse, nil
}
```

### Draft 24

`w.Draft24().ParsePresentationRequest` と `ParsePresentationRequestObject` は、Presentation Exchange の `presentation_definition` を持つ OpenID4VP Draft 24 の要求を受け付けます。
ハンドルには `SubmitPresentation`（`vp_token` と `presentation_submission`）と `DeclinePresentation` で応答します。
`SelectCredentials` は input descriptor ごとに最も新しい Credential を選び、`QueryIDs` は input descriptor の id を指定します。
SD-JWT VC では key binding が常に必須で、nil でない `DisclosedClaims` が開示を制限します。
Draft 24 の経路は pre-registered client を拒否し、`Config.TestHooks.PresentationExchangeResponse` はテストのために応答を書き換えます。

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

func presentDraft24(ctx context.Context, w *wallet.Wallet, uri string, holderKey wallet.IKeyEntry) (*presenterTypes.SubmitResult, error) {
	request, err := w.Draft24().ParsePresentationRequest(ctx, uri)
	if err != nil {
		return nil, err
	}
	selections, err := w.SelectCredentials(ctx, request)
	if err != nil {
		return nil, err
	}
	return w.SubmitPresentation(ctx, request, wallet.Presentation{Key: holderKey, Credentials: selections})
}
```

## 鍵と署名 {#keys-and-signing}

すべての鍵は `IKeyEntry` で、ライブラリが秘密鍵を必要とすることはありません。
`wallet` を import できないサブパッケージは、同じメソッド集合を持つ `keystore.KeyEntry` を使います。
ハードウェアモジュールやリモート署名サービスにある鍵は `keystore.ContextSigner` も実装できます。
その場合、ライブラリは操作の context で `SignContext` を呼ぶので、操作をキャンセルすると保留中の署名もキャンセルされます。

```go
import (
	"context"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/keystore"
)

// remoteKey signs in a remote signing service.
type remoteKey struct {
	id     string
	public jose.JSONWebKey
	sign   func(ctx context.Context, data []byte) ([]byte, error)
}

func (k *remoteKey) ID() string                 { return k.id }
func (k *remoteKey) PublicKey() jose.JSONWebKey { return k.public }
func (k *remoteKey) Sign(data []byte) ([]byte, error) {
	return k.sign(context.Background(), data)
}
func (k *remoteKey) SignContext(ctx context.Context, data []byte) ([]byte, error) {
	return k.sign(ctx, data)
}

var (
	_ wallet.IKeyEntry       = (*remoteKey)(nil)
	_ keystore.ContextSigner = (*remoteKey)(nil)
)
```

key proof のアルゴリズムは、Issuer が `proof_signing_alg_values_supported` に列挙しているものでなければなりません（`ErrProofAlgorithmNotSupported`）。

## プロファイルの規則 {#profile-rules}

`NewWalletWithConfig` は構成を `Config.Profile` に照らして確認します。

* 未知の profile は拒否します（`profile.ErrUnknownProfile`）。
* `profile.Carrier` を実装する receiver / presenter の plugin は、wallet の profile を報告しなければなりません（`ErrProfileMismatch`）。HAIP では `profile.Carrier` を実装しない plugin を拒否し（`ErrProfilePluginUnsupported`）、Final では受け入れます。
* HAIP では `TestHooks` を拒否し、`Draft13()` / `Draft24()` のすべてのメソッドと `ReceiveCredential` は `ErrProfileForbidsDraft` を返します。
* `Storeless` と `CredStore` の併用、`SupportedTransactionDataTypes` と `Presenter` の併用、`*oid4vp.Oid4vpPresenter` 以外の `Presenter` plugin は拒否します（`ErrInvalidArgument`）。

`SetReceiver` も同じ plugin の確認を行います。
plugin のフィールドは登録後に変更してはなりません。
HAIP はさらに、PAR、DPoP に束縛されたアクセストークン、クライアント認証の手段、すべての Credential Configuration の `scope`、key attestation が必要なときの Nonce Endpoint、`x509_hash`、`request_uri` で配送される署名付き要求、暗号化された応答モード、SD-JWT VC の issuer `x5c`、`cnf` を持つすべての SD-JWT VC への Key Binding JWT などを要求します。
`AllowHTTP` と `InsecureSkipX509Verify` は拒否します。

## エラーコード {#error-codes}

ライブラリが返すエラーはすべて、安定した機械可読のコードで状況を示します。

```go
// CodedError is an error with a stable code.
type CodedError interface {
	error
	ErrorCode() string
}
```

`wallet.ErrorCode(err)` はチェーンの最も外側の `CodedError` のコードと、見つかったかどうかを返します。
`wallet.ErrorCodes(err)` は、最も具体的なものから順にすべてのコードを返します。
`("", false)` はそのエラーがこのライブラリ由来でないことを意味します。
パッケージ `wallet` のメソッドが返す nil でないエラーには、必ずコードがあります。
より具体的なコードがないエラーは、`invalid_argument`（`ErrInvalidArgument`、I/O の前に拒否した入力）、`canceled`、`deadline_exceeded`（それぞれ `context.Canceled` / `context.DeadlineExceeded` にも一致します）、`network_error`、`unclassified`（ライブラリ側のコードの欠落）のいずれかです。
plugin のメソッドを直接呼んだ場合は、依存ライブラリのコードのないエラーが返ることがあります。
presenter の解析メソッドは、より具体的なコードのない拒否に `oid4vp_request_invalid`（`oid4vp.ErrAuthorizationRequestInvalid`）を付けます。

```go
import (
	"errors"

	"github.com/trustknots/vcknots/wallet"
)

func describe(err error) string {
	if errors.Is(err, wallet.ErrCredentialAcceptancePolicyRequired) {
		return "configure Config.CredentialAcceptance"
	}
	if code, ok := wallet.ErrorCode(err); ok {
		return code
	}
	return "not a wallet error"
}
```

コードは lower_snake_case で、モジュール全体で一意であり、再利用しません。
コードの削除は破壊的変更です。
`ErrorCode` はプロトコルの `Code` フィールドとは別物です。
フィールドは相手が送ったもの、`ErrorCode` はライブラリが下した判断です。
型付きのエラーは、報告する状況からコードを決めます。

| エラー | コード |
| --- | --- |
| `*wallet.AuthorizationResponseError` | `authorization_error_response` |
| `*wallet.KeyAttestationRequiredError` | `key_attestation_required`、`NonceRejected` のとき `key_attestation_nonce_rejected` |
| `*oid4vci.EndpointError` | `issuer_metadata_fetch_failed`、`authorization_server_metadata_fetch_failed`、`pushed_authorization_request_failed`、`token_endpoint_rejected`、`nonce_request_failed`（`Stage` による） |
| `*receiverTypes.CredentialEndpointError` | `invalid_nonce` なら `credential_nonce_rejected`、それ以外は `credential_endpoint_rejected` |
| `*receiverTypes.Draft13CredentialEndpointError` | `draft13_credential_invalid_proof`、`draft13_credential_issuance_pending`、それ以外は `draft13_credential_endpoint_failed` |
| `*oid4vp.AuthorizationRequestError` | `oid4vp_request_rejected` |
| `*oid4vp.VerifierResponseError` | `verifier_response_rejected` |
| `*x509.SigningChainError` | 失効のエラーをラップしていればそのコード、それ以外は `x509_chain_untrusted` |
| `*x509.CRLCheckError` | `x509_chain_revoked`、`crl_budget_exhausted`、それ以外は `x509_chain_revocation_unknown` |

センチネルエラー（`wallet`、`acceptance`、`attestation`、`profile`、`receiver/plugins/oid4vci`、`presenter/plugins/oid4vp` などのパッケージの `Err…` 変数）はそれぞれのコードを持ち、`errors.Is` も成り立ちます。
コンポーネントのパッケージ（`keystore`、`credstore`、`serializer`、`verifier`、`presenter`、`idprof`、`clientconfig`）は、コードの先頭にコンポーネント名を付けます。

## HTTP のやり取りの観測

パッケージ `common/observe` は、ライブラリが行う外向きの HTTP のやり取りを、プロトコル上の役割（`Endpoint`: `issuer_metadata`、`token`、`credential`、`request_object`、`response_endpoint` など）付きで報告します。
plugin に渡す `*http.Client` の transport をラップします。

```go
import (
	"net/http"

	"github.com/trustknots/vcknots/wallet/common/observe"
)

func observedClient(record func(endpoint observe.Endpoint, method, url string, status int, err error)) *http.Client {
	return &http.Client{Transport: observe.Transport(nil, observe.ObserverFunc(func(e observe.Exchange) {
		status := 0
		if e.Response != nil {
			status = e.Response.StatusCode
		}
		record(e.Endpoint, e.Request.Method, e.Request.URL.Redacted(), status, e.Err)
	}))}
}
```

observer は応答ヘッダーが届いた後に呼ばれます。
ボディを読んだり閉じたり、処理をブロックしたりしてはなりません。
ライブラリがラベルを付けなかったリクエスト（CRL の取得や自分で送ったリクエスト）は `EndpointOther` です。
同じクライアントで自分のリクエストを送るときは、`observe.WithEndpoint` でラベルを付けられます。

## 環境変数

環境変数は `wallet/env/env.go` で定義されています。

| 変数 | 既定値 | 説明 |
| :---- | :---- | :---- |
| `VCKNOTS_WALLET_HTTP_ALLOWED` | `false`（未設定 / 空） | `true` のとき、既定のディスパッチャと plugin が HTTP エンドポイントを許可します（ローカル開発のみ）。構築時に読み取られます。client assertion を平文 HTTP で送るのは loopback ホストに対してだけです。HAIP は HTTP を拒否します。 |
| `VCKNOTS_WALLET_DEBUG` | `false`（未設定 / 空） | デバッグログのみを有効化します。HTTPS の要件は緩和しません。 |

`env.IsHTTPAllowed()` が `true` になるのは `VCKNOTS_WALLET_HTTP_ALLOWED=true` のときだけです。
テストコードからは `env.SetHTTPAllowed(true)` と `env.SetDebugMode(true)` で設定できます。

## 以前の wallet API からの変更点

このセクションは、upstream のコミット `f0c7c53` 以降に、そこに存在した識別子に加えられた変更と、そのメソッドの挙動の変更を挙げます。
それ以降に追加された識別子は、ここまでのセクションで説明しています。
`f0c7c53` のエクスポートされたシグネチャはすべて変わっていません。

**パッケージ `wallet`**

* `Config` は `==` で比較できなくなりました。
* `Config` に新しいフィールド `Profile`、`Storeless`、`CredentialAcceptance`、`SupportedTransactionDataTypes`、`Issuance`、`Attestation`、`TestHooks` があります。`CredentialOfferGrant` に `IssuerState` と `AuthorizationServer` が、`SavedCredential` に `Verification` があります。
* `NewWalletWithConfig` は、未知の `Profile`、wallet と異なる profile の plugin、HAIP では `profile.Carrier` を実装しない plugin と `TestHooks` を拒否します。`CredStore` を伴う `Storeless`、注入した `Presenter` を伴う `SupportedTransactionDataTypes`、`*oid4vp.Oid4vpPresenter` 以外の presenter plugin も拒否します。エラーにはコードがあります。
* `SetReceiver` は非推奨です。ディスパッチャの plugin を `NewWalletWithConfig` と同じく確認し、拒否したディスパッチャは設定せず、receiver を必要とするメソッドはすべてその拒否を返します。
* `VerifyCredential` は、proof が検証できたときだけ、かつ `acceptance.DefaultSigningAlgorithms()`（ES256）に限り true を返します。nil の Credential には false を返します。
* `ReceiveCredential` は HAIP で `ErrProfileForbidsDraft` を返します。Credential は保存前に検査します。`Config.CredentialAcceptance` があればそれで、なければ解析（`typ`、`alg`、`Key` と一致すべき `cnf`）で検査し、失敗した Credential は保存しません。storeless の wallet は検査の後に `ErrNoCredentialStore` を返します。
* `PresentCredential` と `PresentCredentialWithOptions` は `ParsePresentationRequest`、`SelectCredentials`、`SubmitPresentation` を実行します。保存済み Credential は最新のものではなく DCQL クエリで選び、答える query ごとに提示を作り、query の要求どおりに Key Binding JWT を付けます。要求は [Verifier の認証](#verifier-authentication)の規則で受け付けます。
* `GetCredentialEntries` と `GetCredentialEntry` は、storeless の wallet で `ErrNoCredentialStore` を返します。
* `Wallet` のメソッドが返すエラーにはすべてコードがあります（`wallet.ErrorCode`）。

**plugin とサブパッケージ**

* `oid4vp.Oid4vpPresenter` は `==` で比較できなくなりました。`oid4vci.Oid4vciReceiver` と `oid4vp.Oid4vpPresenter` には新しいフィールド（`HTTPClient`、`AllowHTTP`、`Profile` など）とメソッドがあります。ゼロ値は `VCKNOTS_WALLET_HTTP_ALLOWED` の値にかかわらず HTTPS を要求します。`receiver.WithDefaultConfig`、`presenter.WithDefaultConfig`、`NewWallet` は plugin を構築するときにこの変数を読みます。
* receiver plugin は HTTP のリダイレクトをすべて拒否し（`ErrHTTPRedirectNotAllowed`）、応答ボディの大きさを制限し、`credential_issuer` が要求した識別子と異なる Credential Issuer Metadata と、`issuer` が要求したものと異なる認可サーバーメタデータを拒否します。
* `Oid4vpPresenter.ParsePresentationRequest` は [Verifier の認証](#verifier-authentication)のとおりに Verifier を認証します。署名付き Request Object は prefix ごとの仕組みで検証し、`client_metadata` の鍵では検証しません。`x509_*` の prefix は署名付き Request Object を要求し、コロンのない `client_id` は登録が必要な pre-registered client として扱い、`iat` が未来のものは拒否します。`InsecureSkipX509Verify` を設定すると OpenID4VP 1.0 の経路は署名付き Request Object を拒否し、この設定は Draft 24 の入口に適用されます。`X509TrustChainRoots` は失効情報のない証明書を引き続き受け入れます。
* presenter は解析に失敗しても、エラー応答を送らなくなりました。求める場合は `SendParseErrorResponses` または `AuthorizationRequestError.SendErrorResponse` が送ります。`request_uri` の取得と応答の POST（`Present`）はリダイレクトに従わず、`Present` への 2xx 以外の応答は `*oid4vp.VerifierResponseError` になります。
* `NewRequestBuilder` は `profile.Final` の下で OpenID4VP 1.0 の要求を構築します。
* `receiver.ReceivingDispatcher` と `presenter.PresentationDispatcher` に新しいメソッド（`Plugins`、transport と解析のアクセサ）があります。`sdjwtvc.SdJwtVcPresentationOptions` に `LimitDisclosureToSelectedClaims` と `RequireRootClaimMatch` が、`presenterTypes.PresentationRequest` に `ResponseMode` があります。`receiver/types` のメタデータの型に新しいフィールドがあります。
* `env.IsHTTPAllowed` は、`VCKNOTS_WALLET_DEBUG` によって true を返すことがなくなりました。
* コンポーネントのパッケージ（`keystore`、`credstore`、`presenter/types`、`common` など）のセンチネルエラーはコードを持ちます。`errors.Is` は引き続き一致します。

## 7. 注意事項

1. **モック鍵は本番環境で使用禁止 (CRITICAL):**
    - このチュートリアルのインメモリの鍵（および `wallet/examples/common/` の `MockKeyEntry`）は、秘密鍵を Go のヒープ上に平文で保持します。テストとデモンストレーションにだけ使ってください。
    - 本番環境では、`Sign` を OS のキーストア（iOS Secure Enclave、Android Keystore）や HSM に委譲し、秘密鍵がアプリケーションのメモリにロードされない形で `IKeyEntry` を実装してください。

2. **GOPRIVATE の設定:**
    - `go mod download` または `go build` が失敗する場合、最も可能性が高い原因は GOPRIVATE 環境変数の設定漏れです。

3. **永続化ストレージ (bbolt):**
    - `credstore.WithDefaultConfig()` は `<ユーザー設定ディレクトリ>/vcknots/wallet/.local_credstore.db` に Credential を永続化します。プロセスがこのディレクトリを作成し、書き込めるようにしてください。

4. **HTTPS の強制:**
    - wallet はデフォルトで Issuer と Verifier のエンドポイントに HTTPS を要求します。`VCKNOTS_WALLET_HTTP_ALLOWED=true` や plugin の `AllowHTTP` による緩和は、ローカル開発に限ってください。

5. **OpenID4VP `client_id` の厳格な検証:**
    - wallet は `client_id` を厳格に検証します。重複した prefix（例: `x509_san_dns:x509_san_dns:...`）、不正な形式、wallet 専用の prefix は拒否します。
    - `x509_san_dns` では、Request Object の `x5c` ヘッダーから証明書を取り出し、その DNS Subject Alternative Name のいずれかが `client_id` の値と一致しなければなりません。

6. **`InsecureSkipX509Verify`:**
    - Draft 24 の入口で証明書チェーンの検証を省略し、束縛と署名だけを確認します。これを設定している間、OpenID4VP 1.0 の経路は署名付き Request Object を拒否し、HAIP はこの設定を拒否します。
    - ⚠️ コンフォーマンステストかローカル開発でのみ使ってください。

## 8. トラブルシューティング

* **Q: `go mod download` が `package ... is private` または `404 Not Found` で失敗する。**
  * **A:** GOPRIVATE 環境変数が設定されていません。「1. 前提条件」を参照してください（または mise を使用してください）。

* **Q: 受領または提示が `connection refused` または `timeout` で失敗する。**
  * **A:** Issuer/Verifier サーバーが起動していません。`pnpm -F @trustknots/server start` で起動し、http://localhost:8080 が応答することを確認してください。

* **Q: 受領が `credential issuer must use https scheme` で失敗する。**
  * **A:** wallet はデフォルトで HTTPS を要求します。HTTP のローカルサンプルサーバーに対しては、wallet を構築する前に `VCKNOTS_WALLET_HTTP_ALLOWED=true` を設定するか、自分で構築する plugin に `AllowHTTP` を設定してください。

* **Q: 受領が `issuer_metadata_fetch_failed` で失敗する。**
  * **A:** `curl http://localhost:8080/.well-known/openid-credential-issuer` を実行して JSON メタデータが返ること、その `credential_issuer` が Offer の識別子と一致することを確認してください。

* **Q: OpenID4VCI 1.0 のメソッドが `credential_acceptance_policy_required` で失敗する。**
  * **A:** `Config.CredentialAcceptance` を設定してください。wallet が鍵を認証できないテスト用 Issuer には、`&acceptance.Policy{UnverifiedIssuer: true}` でその旨を明示します。

* **Q: OpenID4VP コンフォーマンステストで `client_id` の検証エラーが発生する。**
  * **A:** コンフォーマンステストは意図的に不正な `client_id` を送ります。`duplicate prefix detected` や SAN の不一致のようなエラーは期待どおりの動作です。

* **Q: コンフォーマンススイートの署名付き Request Object が X.509 のエラーで拒否される。**
  * **A:** スイートのルート証明書をトラストアンカーに設定してください。テスト用の証明書は通常 CRL を公開していないので、それも明示的に許可します。
    ```go
    import (
    	"crypto/x509"

    	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
    )

    func conformancePresenter(suiteRoot *x509.Certificate) *oid4vp.Oid4vpPresenter {
    	return &oid4vp.Oid4vpPresenter{
    		RequestObjectValidation: &oid4vp.RequestObjectValidationOptions{
    			TrustAnchors:                []*x509.Certificate{suiteRoot},
    			AllowUnadvertisedRevocation: true, // test certificates only
    		},
    	}
    }
    ```

実行可能なサンプルは [wallet/examples/README.ja.md](https://github.com/trustknots/vcknots/blob/main/wallet/examples/README.ja.md) を参照してください。
[公開 Wallet API driver](https://github.com/trustknots/vcknots/blob/main/wallet/examples/official_driver/README.ja.md) は完全な構成を組み立てています。
