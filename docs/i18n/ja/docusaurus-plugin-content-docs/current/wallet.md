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
`Config.Profiles` で、wallet が動かすプロトコルプロファイルを選びます。
1.0 のプロファイル 1 つ（`profile.Final()` か、1.0 仕様への制約の集合である HAIP 1.0 の `profile.HAIP()`）と、Draft のプロファイル `profile.Draft13()`（OpenID4VCI Draft 13。`Draft13()` ビュー）と `profile.Draft24()`（OpenID4VP Draft 24。`Draft24()` ビュー）です。
既定値は Final と 2 つの Draft です。
`Wallet` のメソッドは 1.0 のプロトコルの段階で、呼出し側が順に実行します。
Draft には 2 つのビューからだけ到達します。

| プロトコル / 機能 | 公開 API | 備考 |
| --- | --- | --- |
| OpenID4VCI 1.0 Pre-Authorized Code Flow | `AuthorizePreAuthorizedIssuance` + `RequestCredential` | `tx_code` は Offer が宣言しているときに限り必須です。 |
| OpenID4VCI 1.0 Authorization Code Flow（PKCE、PAR、RFC 9207 `iss`） | `BeginIssuance` + `AuthorizeIssuance` + `RequestCredential` | ライブラリはブラウザを開かず、`https` の認可 URL だけを返します。PKCE は常に `S256` です。PAR は認可サーバーが広告する場合に使い、HAIP のとき、またはサーバーが `require_pushed_authorization_requests` を示すときは必須です。Offer なしの wallet 起点の発行と、`grants` の無い Offer にも対応します。 |
| Credential Offer の値渡しと参照渡し | `ResolveCredentialOffer`、`ParseCredentialOfferURL` | `ParseCredentialOfferURL` は I/O を行いません。 |
| クライアント認証、DPoP | `Config.ClientAuth`、`Config.DPoP`、`Config.Attestation.Client` | `private_key_jwt` または OAuth 2.0 Attestation-Based Client Authentication（フローごとの一時的な Client Instance Key、サーバーが与える Challenge）です。`Config.DPoP.Key` があれば常に DPoP proof を送ります。 |
| Batch 発行 | `CredentialRequest.HolderKeys` | holder 鍵ごとに key proof を 1 つ送り、`batch_credential_issuance.batch_size` を上限とします。 |
| Key attestation（Appendix D） | `Config.Attestation.Key`、`CredentialRequest.KeyAttestation` | 送信前に attestation を認証します（`attestation.TrustPolicy`）。 |
| Credential Request / Response の暗号化 | `Config.Issuance.CredentialEncryption` | 応答用の鍵は一時鍵です。 |
| Deferred 発行 | `RequestDeferredCredential` | 1 回の呼出しで 1 リクエストを送ります。ライブラリはポーリングしません。 |
| Notification | `NotifyIssuer` | ライブラリが自ら通知することはありません。 |
| 署名付き Credential Issuer Metadata | `oid4vci.Oid4vciReceiver.IssuerMetadataSigning` | OpenID4VCI 1.0 §12.2.3（`application/jwt`）と Draft 13 §11.2.3（`signed_metadata`）です。 |
| 保存前の Credential 受理判定 | `Config.CredentialAcceptance` または `IssuanceRequest`、`PreAuthorizedIssuanceRequest`、`CredentialRequest` の `Acceptance`（`acceptance.Policy`）、`VerifyCredentialForAcceptance` | token request や PAR の前に必須なので、wallet が拒否する Credential のために認可を得ることはありません。Issuer の鍵は、`iss` と `x5c` が選ぶ方式で確立します（SD-JWT VC -19 §2.5）。 |
| `direct_post` / `direct_post.jwt` 上の OpenID4VP 1.0 | `ParsePresentationRequest`、`ParsePresentationRequestObject`、`SelectCredentials`、`SubmitPresentation`、`DeclinePresentation` | 要求には `*oid4vp.AdmittedRequest` ハンドルを通じて応答します。 |
| Verifier の認証 | `oid4vp.Oid4vpPresenter`（`RequestObjectValidation`、`PreRegisteredClients`） | `x509_san_dns`、`x509_hash`、`redirect_uri`、pre-registered client、`verifier_attestation`、`openid_federation` に対応します。[Verifier の認証](#verifier-authentication)を参照してください。 |
| `request_uri` の GET / POST と `wallet_nonce` | `ParsePresentationRequest`、`Draft24().ParsePresentationRequest` | `request_uri` はライブラリ自身が取得します。POST では毎回新しい `wallet_nonce` を送ります。ただし `Oid4vpPresenter.OmitWalletNonce` を設定すると送りません（OID4VP 1.0 §5.10 で Wallet 側は OPTIONAL）。`Oid4vpPresenter.WalletMetadata` があれば `wallet_metadata` も送ります。`RequestObjectValidationOptions.RequestURIPolicy` で、取得の前に `request_uri` と `client_id` の関連を確かめられます（`oid4vp.RequestURISameHost` は Client Identifier が名指す host に結び付けます）。 |
| DCQL | `SelectCredentials`、`oid4vp.ResolveSatisfiableDCQLCredentials`、`oid4vp.ValidateDCQLMatches` | `credential_sets`、`claims`、`claim_sets`、`values`、nested / array の claim path、`multiple`、`aki` と `openid_federation` 種別の `trusted_authorities` に対応します。 |
| `transaction_data` | `Config.SupportedTransactionDataTypes`、`CredentialSelection.TransactionData` | key binding つきの `dc+sd-jwt` 提示に限ります。各 entry を、提示するどの Credential で承認するかは Holder が割り当てます。 |
| W3C Digital Credentials API（`dc_api`、`dc_api.jwt`、unsigned / signed / multi-signed） | `ParseDCAPIRequest` + `SubmitPresentation` | プロトコル処理のみです。platform が認証した origin は呼出し側が渡します。 |
| OpenID4VCI Draft 13 | `Draft13()` | `Config.Profiles` に `profile.Draft13()` が必要です。HAIP とは併用できません。 |
| OpenID4VP Draft 24（Presentation Exchange） | `Draft24()` + `SubmitPresentation` | `Config.Profiles` に `profile.Draft24()` が必要です。HAIP とは併用できません。 |
| 形式 | `credential.SDJwtVC`、`credential.JwtVc`、`credential.LdpVc` | OpenID4VCI のバージョンごとに Credential Format Identifier の対応表を持ちます（`oid4vci.CredentialFormatFlavor`）。1.0 は `dc+sd-jwt`、`jwt_vc_json`、`ldp_vc`、Draft 13 は `vc+sd-jwt`、`jwt_vc_json`、`ldp_vc` です。SD-JWT VC の issuer `typ` は `dc+sd-jwt` でなければなりません。`vc+sd-jwt` は `profile.Draft13()` の下でだけ受け付けます。`ldp_vc` は Data Integrity の `eddsa-rdfc-2022` proof を使います。 |

**未実装。**
ISO mdoc（`mso_mdoc`）は mdoc / COSE / CBOR の serializer がないため、mdoc の提示を構築できません。
`decentralized_identifier` の Client Identifier Prefix は解析したうえで拒否します。
DCQL の `trusted_authorities` で評価するのは `aki` と `openid_federation` 種別で、他の種別（`etsi_tl`）の entry はどの Credential にも一致しません。

### プロファイル（Final、HAIP、Draft）

プロファイルは、プロトコルの版と、wallet がその上に適用する Option の組です（パッケージ `profile`）。`Profile.Version()` は `profile.VersionFinal`（OpenID4VCI 1.0 と OpenID4VP 1.0）、`VersionDraft13`、`VersionDraft24` のいずれかで、`Profile.Options()` が制約です。プロファイルは比較可能な値です。2 つのプロファイルは、どう構築したかにかかわらず、同じ規則を適用するときにちょうど `==` になります。

* **Final**（`profile.Final()`）は追加制約のない OpenID4VCI 1.0 と OpenID4VP 1.0 です。`profile.Profile` のゼロ値は、プロファイルを読むすべての箇所で Final です。
* **HAIP**（`profile.HAIP()`）は版ではありません。Final に `profile.HAIPOptions()` を加えたものです。HAIP 1.0 の要件を 1 つずつ `Options` のフィールドで表し、各フィールドには要件を定める HAIP の節を記しています。`profile.HAIP() == profile.Final().With(profile.HAIPOptions())` が成り立ちます。
* `Profile.With(options)` は Option を加え、連鎖できます。フラグはどちらかで on なら on になり、集合（`AllowedCredentialFormats`、`AllowedClientIDPrefixes`）は両方が許す要素だけを残します。そのため `With` が Option を弱めることはなく、`profile.Final().With(a).With(b)` は `a` と `b` の両方を適用します。組み合わせるとどの入力も通らない Option（共通の要素がない 2 つの集合や、redirect 経由の要求に署名できない Client Identifier Prefix と `RequireSignedRequestByReference` の組など）は、それらを名指す `*profile.ConflictError`（`profile.ErrOptionsConflict`）で拒否します。
* `Options.ForbidDraftProfiles`（HAIP 1.0 §1: 基盤のプロトコルは OpenID4VCI 1.0 と OpenID4VP 1.0）は、1.0 プロファイルと並ぶ Draft のプロファイルを拒否します。`Options.ForbidExperimental` は、パッケージ `experimental` のすべての設定を拒否します。どちらも `HAIPOptions()` に含まれ、ほかの Option と同じく単独でも適用できます。
* **Draft 13**（`profile.Draft13()`）と **Draft 24**（`profile.Draft24()`）は Draft のビューを有効にします。option は持ちません（`profile.ErrDraftProfile`）。
* プロファイルには Option を失わないテキスト形式があります。`String()`、`MarshalText` / `UnmarshalText`（そのため `encoding/json` は `{}` ではなく `"haip"` を書きます）、`profile.ParseProfile` です。形式は、版の名前か `haip` に、それを超える Option を `;` でつないだものです。各 Option は `Options` のフィールド名で書きます（入れ子の規則は `IssuerX5C.Require`、集合は `AllowedCredentialFormats=dc+sd-jwt,mso_mdoc`）。例: `final`、`haip`、`draft13`、`draft24`、`final;RequirePAR;RequireDPoP`、`haip;AllowedCredentialFormats=mso_mdoc`。`ParseProfile(p.String()) == p` が成り立ちます。`Options.String()` は on の Option を同じ綴りで列挙します。
* Option ごとの設定を自前で持つアプリケーションは、設定 1 つを `Options` のフィールド 1 つに対応させ、`With` でプロファイルを構築します（`profile.Final().With(profile.Options{RequirePAR: par, RequireDPoP: dpop})`）。プロセスの境界を越えるときはテキスト形式を渡し、`ParseProfile` で読みます。
* Option が原因のエラーは、その Option を名指す `*profile.OptionError` を持ちます（`errors.As(err, &optionErr)` で取り出し、`optionErr.Option` はたとえば `"RequireDPoP"`）。拒否を分類するエラーとそのコードは変わりません。Option は単独でも適用できるので、メッセージは "HAIP" ではなく Option を名指します。
* receiver と presenter の plugin は wallet の 1.0 プロファイルで構築します（`oid4vci.Oid4vciReceiver.Profile`、`oid4vp.Oid4vpPresenter.Profile`）。wallet が自ら構築する plugin にはそれが設定されます。
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

* **ローカルテストでの HTTP 許可:** wallet は、OpenID4VCI 1.0 §12.2 と OpenID4VP 1.0 のとおり、Issuer と Verifier のエンドポイントに HTTPS を要求します。
ローカルのサンプルサーバーは HTTP で動作するため、テスト用の wallet を構築するコードで明示的に HTTP を許可してください。
平文 HTTP は規格から外れるので、[`experimental`](#experimental) パッケージを通してだけ設定できます。
wallet が構築する plugin には `Config.Experimental.Transport` を、自分で構築する plugin にはその `Experimental` フィールド（`Oid4vciReceiver.Experimental`、`Oid4vpPresenter.Experimental`、Issuer の鍵の解決には `issuerkeys.Resolver.Experimental`）を使います。
環境変数で緩和することはできません。

> ⚠️ **セキュリティ警告**: 本番環境では HTTP を許可しないでください。HAIP は拒否します。

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
`Config.CredentialAcceptance` は設定しないので、発行ごとに受理ポリシーを渡す必要があります（後述の「Credential の受理」を参照）。
Credential を受領する wallet は、通常 `NewWalletWithConfig` でポリシーを設定します。

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
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/idprof"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// newWallet builds the wallet of the samples. allowHTTP accepts the plain
// http endpoints of the local sample server (not for production), and policy
// authenticates the issuer of every credential the wallet receives.
func newWallet(certPath string, allowHTTP bool, policy *acceptance.Policy) (*wallet.Wallet, error) {
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	receiverDisp, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{
		Experimental: experimental.Transport{AllowHTTP: allowHTTP},
	}))
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
		X509TrustChainRoots: certPool,
		// The local sample server speaks plain HTTP, which OpenID4VP does not
		// allow; opt in explicitly, and never in production.
		Experimental: experimental.Presenter{Transport: experimental.Transport{AllowHTTP: allowHTTP}},
	}
	presenterDisp, err := presenter.NewPresentationDispatcher(
		presenter.WithPlugin(presenter.Oid4vp, oid4vpPresenter),
	)
	if err != nil {
		return nil, err
	}

	return wallet.NewWalletWithConfig(wallet.Config{
		CredentialAcceptance: policy,
		CredStore:            credStore,
		IDProfiler:           idProf,
		Receiver:             receiverDisp,
		Serializer:           serializerDisp,
		Verifier:             verifierDisp,
		Presenter:            presenterDisp,
	})
}
```

* **保存先:** 既定の Credential ストアは、`go.etcd.io/bbolt` を使って `<ユーザー設定ディレクトリ>/vcknots/wallet/.local_credstore.db`（Linux では `~/.config/vcknots/wallet/.local_credstore.db` など）に永続化します。`Config.Storeless` はストアを持たない wallet を構築します。受領した Credential は返されるだけで保存されず、提示には Credential を値で渡します。

## 3. Wallet機能のサンプル実装

このセクションでは、`wallet/examples/server_integration_sdjwt/server_integration_sdjwt.go` と `wallet/examples/common/common.go` をもとに、最小の受領と提示のサンプルを示します。
どちらも段階的メソッドを使います。
受領のサンプルは OpenID4VCI 1.0 の、提示のサンプルは OpenID4VP 1.0 のメソッドです。
ユーザーのいる wallet に必要なその他の段階的 API は、[OpenID4VCI 1.0 の発行](#openid4vci-10-issuance)と [OpenID4VP 1.0 の提示](#openid4vp-10-presentation)で説明します。

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

OpenID4VCI 1.0 の Pre-Authorized Code の発行は 3 回の呼出しで行います。
Offer を解析し、pre-authorized code をアクセストークンと交換し、Credential を要求します。
実際の運用では Offer URI は QR コードやディープリンクから得ます。
ローカルのサンプルサーバーでは `POST /configurations/:configurationId/offer` で作成できます。

```go
import (
	"context"
	"fmt"

	"github.com/trustknots/vcknots/wallet"
)

func receiveSDJwtCredential(ctx context.Context, w *wallet.Wallet, key wallet.IKeyEntry, offerURI, txCode string) (*wallet.SavedCredential, error) {
	// openid-credential-offer://?credential_offer=...
	offer, err := wallet.ParseCredentialOfferURL(offerURI)
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

	result, err := w.RequestCredential(ctx, grant, wallet.CredentialRequest{
		HolderKeys: []wallet.IKeyEntry{key}, // each key signs one key proof
	})
	if err != nil {
		return nil, err
	}
	if result.Deferred != nil {
		return nil, fmt.Errorf("the issuer deferred the credential")
	}
	return result.Credentials[0], nil
}
```

`AuthorizePreAuthorizedIssuance` は Issuer と認可サーバーのメタデータを取得し、pre-authorized code でアクセストークンを取得します。
`PreAuthorizedIssuanceRequest.CredentialConfigurationID` は提示された configuration を選び、空の場合は最初のものを使います。
`RequestCredential` は、Issuer が Nonce Endpoint を公開していればそこから `c_nonce` を得て（§7）、holder 鍵ごとに key proof に署名し、Credential を要求し、検査してから保存します。
検査には `Config.CredentialAcceptance`（2-2 で設定します）を使います。
発行が自身のポリシーを持つ場合はそちらを使います。
`PreAuthorizedIssuanceRequest.Acceptance` は grant が `RequestCredential` まで引き継ぎ、`CredentialRequest.Acceptance` はそれより優先します。
ポリシーがまったくなければ、`AuthorizePreAuthorizedIssuance` は pre-authorized code を引き換えずに `ErrCredentialAcceptancePolicyRequired` で失敗します。
Issuer を認証していない Credential は要求も保存もしません（SD-JWT VC -19 §2.4）。
Deferred 発行、通知、Authorization Code Flow は [OpenID4VCI 1.0 の発行](#openid4vci-10-issuance)で説明します。

OpenID4VCI **Draft 13** の Issuer には、`w.Draft13()` の同じメソッドを使います。
[Draft 13](#draft-13) を参照してください。

### 3-3. Credentialの提示 (OpenID4VP)

Verifier から `openid4vp:?...` 形式のリクエスト URI（ローカルのサンプルサーバーでは `POST /request` または `POST /request-object` で取得）を受け取ったら、それを解析し、答える Credential を選び、holder が同意したら提出します。

```go
import (
	"context"
	"log"

	"github.com/trustknots/vcknots/wallet"
	sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func presentCredential(ctx context.Context, w *wallet.Wallet, key wallet.IKeyEntry, oid4vpURI string) error {
	request, err := w.ParsePresentationRequest(ctx, oid4vpURI)
	if err != nil {
		return err
	}
	selections, err := w.SelectCredentials(ctx, request)
	if err != nil {
		return err
	}
	// A wallet with a user shows selections (the credentials and the claims
	// they disclose) and submits only after the holder consents; it declines
	// with DeclinePresentation otherwise.
	submitted, err := w.SubmitPresentation(ctx, request, wallet.Presentation{
		Key:         key,
		Credentials: selections,
		// Limits SD-JWT VC disclosure to these claims.
		SerializeOptions: &sdjwtvc.SdJwtVcPresentationOptions{
			SelectedClaims: []string{"given_name", "family_name"},
		},
	})
	if err != nil {
		return err
	}
	if submitted.RedirectURI != "" {
		log.Printf("Verifier requested redirect: %s\n", submitted.RedirectURI)
	}
	return nil
}
```

`ParsePresentationRequest` は presenter の信頼ポリシーの下で要求を受け付け（[Verifier の認証](#verifier-authentication)を参照）、`*oid4vp.AdmittedRequest` の handle を返します。
`SelectCredentials` は DCQL クエリを満たす保存済み Credential を選び、それぞれが開示するクレームを示します。
`SubmitPresentation` は Credential ごとに `key` で署名した提示を作り、要求が指定したエンドポイントへ応答を送ります。
Verifier が返す `redirect_uri` には接続しません。
その URI は `SubmitResult.RedirectURI` に入り、ない場合は空文字列です。
たどるかどうかは呼出し側が決めます。
選択とは別の Credential やクレームで答える方法は [OpenID4VP 1.0 の提示](#openid4vp-10-presentation)で説明します。

* **提示オプション:** `Presentation.SerializeOptions` は形式ごとのオプション値で、`nil` なら serializer の既定値を使います。KB-JWT の audience と nonce は常に要求から取ります。SD-JWT VC では、空でない `SelectedClaims` が開示を制限し、その範囲外のクレームを要求されると失敗します。Key Binding JWT は、DCQL クエリが holder binding を要求するとき（既定）、`RequireKeyBinding` を設定したとき、`transaction_data` を提示するとき、そして HAIP では Credential が `cnf` を持つときに常に付与します。
* **Draft 24:** `ParsePresentationRequest` が解析するのは OpenID4VP 1.0 の要求だけです。Presentation Exchange の要求は `Draft24().ParsePresentationRequest` で解析し、`SelectCredentials` と `SubmitPresentation` に続けます。

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

`FetchCredentialIssuerMetadata` は Issuer の OpenID4VCI 1.0 の `.well-known/openid-credential-issuer` 文書（§12.2.2）を取得します。
たとえば、holder が Offer を受け入れる前にその内容を示すために使います。
発行のメソッドは常にメタデータを再取得し、キャッシュしたメタデータを受け取りません。

```go
import (
	"context"
	"log"
	"net/url"

	"github.com/trustknots/vcknots/wallet"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func fetchIssuerMetadata(ctx context.Context, w *wallet.Wallet) (*receiverTypes.CredentialIssuerMetadata, error) {
	// The Credential Issuer Identifier; the well-known path is inserted internally.
	issuerURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		return nil, err
	}

	metadata, err := w.FetchCredentialIssuerMetadata(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	log.Printf("Fetched metadata for issuer: %s\n", metadata.CredentialIssuer)
	return metadata, nil
}
```

receiver は、`credential_issuer` が要求した識別子と異なるメタデータを拒否します（OpenID4VCI 1.0 §12.2.4）。
署名付きメタデータを含め、wallet の 1.0 プロファイルを適用します（「署名付き Issuer メタデータ」を参照）。

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
| `Profiles` | プロトコルプロファイルです。1.0 のプロファイル 1 つ（`profile.Final()`、`profile.HAIP()`、またはそれらを `With` で強めたもの）と、必要に応じて `profile.Draft13()` と `profile.Draft24()` を並べます。空なら `wallet.DefaultProfiles()`（Final と 2 つの Draft）です。 |
| `Storeless` | Credential ストアを持ちません。このとき `CredStore` は `nil` でなければならず、ストアを必要とするメソッドは `ErrNoCredentialStore` を返します。 |
| `CredentialAcceptance` | 受領した Credential を返す、または保存する前に適用する `*acceptance.Policy` です。要求が自身のポリシー（`IssuanceRequest.Acceptance`、`PreAuthorizedIssuanceRequest.Acceptance`、`CredentialRequest.Acceptance`、`CredentialAcceptanceRequest.Acceptance`）を持つ場合はそちらを使います。どちらもなければ、`BeginIssuance`、`AuthorizeIssuance`、`AuthorizePreAuthorizedIssuance`、`RequestCredential`、`RequestDeferredCredential`、それらの `Draft13()` 版、`VerifyCredentialForAcceptance` は何も送らずに `ErrCredentialAcceptancePolicyRequired` で失敗します。 |
| `SupportedTransactionDataTypes` | wallet が構築する presenter の `transaction_data` の type です。`Presenter` と同時に設定すると拒否します。注入した plugin には `Oid4vpPresenter.SupportedTransactionDataTypes` を設定します。 |
| `DPoP` | [DPoPConfig](#DPoPConfig) です。 |
| `ClientAuth` | [ClientAuthConfig](#ClientAuthConfig) です。`ClientID` はすべての OpenID4VCI バージョンで wallet の `client_id` になります。 |
| `Issuance` | `IssuanceConfig{RedirectURI, CredentialEncryption}` で、Authorization Code Flow の `redirect_uri` と holder の `CredentialEncryptionPolicy` です。 |
| `Attestation` | `AttestationConfig{Client, ClientKey, ClientKeyFromDPoP, Key, Trust}` で、client attestation と key attestation の provider、client attestation が束縛する Client Instance Key、それらを認証する `attestation.TrustPolicy` です。`ClientKey` が nil ならフローごとに一時的な Client Instance Key を使います（[クライアント認証](#openid4vci-10-issuance)を参照）。`ClientKeyFromDPoP` は `DPoP.Key` を attest する opt-in です。 |
| `Experimental` | `experimental.Options{Transport, Hooks}` で、規格から外れる試験専用の設定です。`Transport.AllowHTTP` は wallet が構築する plugin で平文 HTTP を受け付けます（HAIP と、注入した `Receiver` / `Presenter` との併用では拒否します）。`Hooks{KeyProof, PresentationExchangeResponse}` は Draft 13 の key proof と Draft 24 の応答を構築後に書き換えます（Draft のプロファイルが有効でなければ拒否するので、HAIP では常に拒否します）。[experimental](#experimental) を参照してください。 |

### CredentialOffer {#CredentialOffer}

Credential Offer です。
Issuer の URL（`CredentialIssuer`）、configuration ID（`CredentialConfigurationIDs`）、grant（`Grants`）を持ちます。
`CredentialOfferGrant` は `PreAuthorizedCode`、`TxCode`、`IssuerState`、`AuthorizationServer` のヒントを持ちます。

### SavedCredential {#SavedCredential}

受領または保存された Credential です。
`Credential`（解析結果）、`Entry`（保存エントリ: ID、生のバイト列、MIME タイプ、受領日時）、`Verification`（`*acceptance.Verification`、保存前に認証した内容。ストアから読み込んだ Credential では `nil`）を持ちます。

### GetCredentialEntriesRequest {#GetCredentialEntriesRequest}

`GetCredentialEntries` の検索条件です（`Offset`、`Limit`、`Filter`）。

### SdJwtVcPresentationOptions {#SdJwtVcPresentationOptions}

SD-JWT VC の提示オプションです（パッケージ `serializer/plugins/sdjwtvc`）。
`SelectedClaims`、`RequireKeyBinding`、`LimitDisclosureToSelectedClaims`、`RequireRootClaimMatch` と、wallet が要求から埋める `Audience`、`Nonce`、`TransactionData`、`TransactionDataHashesAlg` を持ちます。

### DIDCreateOptions {#DIDCreateOptions}

`GenerateDID` のオプションです。
DID の種類（`TypeID`、例 `"did:key"`）と公開鍵（`PublicKey`）を指定します。

### DPoPConfig {#DPoPConfig}

`Key` は wallet の DPoP 鍵です。
OpenID4VCI 1.0 のメソッドは、`Key` が設定されていれば常に DPoP proof を送り、HAIP では `Key` が必須です（`ErrDPoPKeyRequired`）。
`Enabled` は `Key` が `nil` のときにインメモリ鍵を生成し、`Draft13()` の token request で DPoP を強制します。
`Draft13()` の token request は、`Enabled` がなければ認可サーバーが広告するときだけ DPoP を使います。

### ClientAuthConfig {#ClientAuthConfig}

token エンドポイントでのクライアント認証です。
`Method`（`""` は認証なし、または `receiverTypes.PrivateKeyJwt`）、`ClientID`、`Key`、`AssertionAudience`、`SigningAlg`（ES256、ES384、ES512）を持ちます。
`private_key_jwt` では、認可サーバーがその方式と署名アルゴリズムの両方を広告していなければならず、そうでなければ token リクエストを送りません（`client_authentication_unavailable`）。

## 6. Walletのメソッド

`*Wallet` のメソッドは 23 個です。

| 領域 | メソッド |
| --- | --- |
| ストレージと ID | `GetCredentialEntries`、`GetCredentialEntry`、`GenerateDID` |
| Credential の検査 | `VerifyCredentialForAcceptance`、`StatusListChecker` |
| OpenID4VCI 1.0 | `ResolveCredentialOffer`、`FetchCredentialIssuerMetadata`、`BeginIssuance`、`AuthorizeIssuance`、`AuthorizePreAuthorizedIssuance`、`RequestCredential`、`RequestDeferredCredential`、`NotifyIssuer` |
| OpenID4VP 1.0 | `ParsePresentationRequest`、`ParsePresentationRequestObject`、`ReadmitPresentationRequest`、`AdmitPresentationRequestUnderVersion`、`ParseDCAPIRequest`、`SelectCredentials`、`SubmitPresentation`、`DeclinePresentation` |
| Draft ビュー | `Draft13()`（`BeginIssuance`、`AuthorizeIssuance`、`AuthorizePreAuthorizedIssuance`、`RequestCredential`、`RequestDeferredCredential`、`NotifyIssuer`）、`Draft24()`（`ParsePresentationRequest`、`ParsePresentationRequestObject`、`ReadmitPresentationRequest`） |

フロー全体を 1 回の呼出しで実行するメソッドはありません。
ユーザーのいる wallet は段階の間で holder の同意を得る必要があり、同意の要らない呼出し側は、サンプルの `wallet/examples/common.PresentAll` のように段階を自分で実行します。
`context.Context` を受け取るメソッドは、その context がキャンセルされると停止します。
メソッドが返すエラーにはすべてコードがあります（[エラーコード](#error-codes)を参照）。

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

Credential Issuer Identifier の OpenID4VCI 1.0 の Credential Issuer Metadata を、wallet の 1.0 プロファイルの下で取得します（4 章を参照）。

```go
func (w *Wallet) FetchCredentialIssuerMetadata(ctx context.Context, issuer *url.URL) (*receiverTypes.CredentialIssuerMetadata, error)
```

### GenerateDID

公開鍵から DID を生成します。

```go
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error)
```

### VerifyCredentialForAcceptance

発行時に保存前に行う検査を、`req.Acceptance`、なければ `Config.CredentialAcceptance` で生の Credential に適用します。何も保存しません。
storeless の wallet で受け取って後で保存する呼び出し側や、保持している Credential を検査し直す呼び出し側のための 2 段目です。
`CredentialIssuer` は発行の Credential Issuer Identifier です（DID の Issuer はこの origin と束縛します）。
`Version` はプロファイルを選びます。ゼロ値の `profile.VersionFinal` は wallet の 1.0 プロファイルを、`profile.VersionDraft13` は `profile.Draft13()` を適用します（SD-JWT VC の `typ` `vc+sd-jwt` を受け付けます）。
`CredentialConfiguration` を設定すると、それは Credential を発行した Configuration です。`cryptographic_binding_methods_supported` を列挙していれば、`RequestCredential` と同じく、Credential は `HolderKey` と一致する `cnf.jwk` を持たなければなりません（OpenID4VCI 1.0 §12.2.4、HAIP 1.0 §6.1）。

```go
type CredentialAcceptanceRequest struct {
	Raw              []byte
	Flavor           credential.SupportedSerializationFlavor
	HolderKey        *jose.JSONWebKey
	CredentialIssuer string
	Version          profile.Version
	Acceptance       *acceptance.Policy
	// CredentialConfiguration, when it lists cryptographic_binding_methods_supported,
	// requires a cnf.jwk that HolderKey matches.
	CredentialConfiguration *receiverTypes.CredentialConfiguration
}

func (w *Wallet) VerifyCredentialForAcceptance(ctx context.Context, req CredentialAcceptanceRequest) (*credential.Credential, *acceptance.Verification, error)
```

受理ポリシーを通さずに、解析済みの Credential の署名だけを検査するときは、`verifier.VerificationDispatcher` の `Verify(proof, key)` を使います。
ディスパッチャが登録したアルゴリズムをすべて受け付けるので、アルゴリズムのポリシーは呼出し側が適用します。

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

状態の型（`IssuanceAuthorization`、`IssuanceGrant`、`DeferredIssuance`、`IssuanceNotification`）は JSON にシリアライズできるので、段階を別プロセスで実行できます。
状態が持つのは識別子と秘密だけです。
各段階は Issuer と認可サーバーのメタデータを再取得し、状態がまだ wallet に合っているか（同じ `ClientAuth.ClientID`、`Issuance.RedirectURI`、DPoP 鍵であり、Issuer がまだその認可サーバーに委任しているか）を確認して、合わなければ `ErrIssuanceStateMismatch` で拒否します。
各状態はフローのプロファイルを `Profile`（JSON の `"profile"`、`profile.Profile` のテキスト形式）に記録します。
`Profile` の版（`Profile.Version()`）が別の OpenID4VCI バージョンである状態は `ErrIssuanceVersionMismatch` で拒否します。
同じ版で wallet が別のプロファイルで動く段階は、何も送る前にその状態を拒否します（`ErrIssuanceProfileMismatch`）。そのため、フローが開始時と異なる Option で続くことはありません。
段階を別プロセスで実行する呼出し側は、各段階の wallet を状態の `Profile` で構築します。

**状態の JSON は bearer secret です。**
PKCE の `code_verifier`、フローの一時的な Client Instance Key、アクセストークン、または応答復号用の一時鍵を含みます。
サーバー側か暗号化して保管し、ログに出さないでください。

**メタデータの取得位置。**
1.0 の発行は、Credential Issuer Metadata を OpenID4VCI 1.0 §12.2.2 の位置（識別子のパスの前に well-known パスを挿入した位置）からだけ取得します。
Draft 13 の発行は Draft 13 §11.2.2 の位置（識別子の末尾に well-known パスを付けた位置）からだけ取得します。
404 はそのまま報告し、別の位置や OpenID Federation の Entity は試しません。

**Credential の形式。**
Credential Configuration の `format` が発行の OpenID4VCI バージョンの対応表になければ、token request の前に `oid4vci.ErrCredentialFormatUnsupported` で拒否します。
識別子は完全一致で比較します。
もう一方のバージョンの SD-JWT VC の識別子、`jwt_vc` のような Draft 13 より前の名前、未知の値を、別の形式として読むことはありません。

`BeginIssuance` または `AuthorizePreAuthorizedIssuance` から `RequestDeferredCredential` までの各段階は受理ポリシーを要求し、なければ何も送りません（`ErrCredentialAcceptancePolicyRequired`）。
そのため、wallet が拒否する Credential のために認可を得たり、pre-authorized code を引き換えたりすることはありません。
ポリシーは `Config.CredentialAcceptance` です。
発行が自身のポリシーを持つ場合はそちらを使います。
`IssuanceRequest` または `PreAuthorizedIssuanceRequest` の `Acceptance` は、`IssuanceAuthorization.Acceptance` と `IssuanceGrant.Acceptance` が `RequestCredential` まで引き継ぎ、そこでは `CredentialRequest.Acceptance` が優先し、`DeferredIssuance.Acceptance` がさらに引き継ぎます。
ポリシーは関数や信頼の材料を持つので、JSON には含まれません。
各状態は、発行ごとのポリシーがあったことを、シリアライズされる `AcceptanceOverridden` に記録します。
読み戻した後に `Acceptance`（grant では `CredentialRequest.Acceptance` でも構いません）を設定し直さなければ、`Config.CredentialAcceptance` に置き換えずに `ErrCredentialAcceptancePolicyRequired` で失敗します。
HAIP では、各段階が `Config.DPoP.Key` を要求し、PAR または token エンドポイントを呼ぶ段階（`BeginIssuance`、`AuthorizeIssuance`、`AuthorizePreAuthorizedIssuance`）はクライアント認証の手段（`private_key_jwt` または `Config.Attestation.Client`、HAIP §4.4.1）も要求します。

### Authorization Code Flow

`BeginIssuance` はメタデータを解決し、Credential Configuration を profile と `Config.Issuance.CredentialEncryption` に照らして確認し、サーバーが RFC 9126 PAR に対応していれば認可リクエストを push して（HAIP では必須。サーバーが `require_pushed_authorization_requests` を示す場合も必須）、holder のブラウザで開く URL を返します。
PAR の応答は `request_uri` と正の `expires_in` を持たなければなりません（RFC 9126 §2.2、`receiverTypes.ErrPARResponseInvalid`）。push に失敗したとき、パラメータを URL に載せて送る方式に切り替えることはありません。
認可エンドポイントは `https` でなければなりません（`http` は experimental の transport のときだけで、HAIP では使えません）。
`grants` の無い Offer や空の `grants` の Offer は、認可サーバーの `grant_types_supported` が `authorization_code` を含むか、省略されているときに開始します（OpenID4VCI 1.0 §4.1.1。それ以外は `ErrAuthorizationCodeGrantUnsupported`）。
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
HAIP では `Config.ClientAuth.ClientID` の設定が必須です。
Client Attestation を使わないとき、設定した `Config.ClientAuth.Method`（既定は `none`）が認可サーバーの `token_endpoint_auth_methods_supported` に含まれている必要があります。
この一覧がなければ RFC 8414 §2 により `client_secret_basic` とみなされ、wallet はこの方式を実装していないので、送信前に `client_authentication_unavailable` で拒否します。
ただし、サーバーが `pre-authorized_grant_anonymous_access_supported: true` を宣言していれば、匿名の要求（クライアント認証なし、`client_id` なし）を送ります。§6.1 はこの grant でのクライアント認証を OPTIONAL とし、§12.3 はこのパラメータで `client_id` のない要求を受け付けると宣言させるからです。
`none` のとき、`pre-authorized_grant_anonymous_access_supported` は `client_id` を送るかどうかだけを決めます。
`true` なら、`client_id` を設定していても token request に含めません。
それ以外のとき（既定値は `false`、§12.3）は `Config.ClientAuth.ClientID` を送り、設定がなければ `client_authentication_unavailable` で拒否します。
`private_key_jwt` と Client Attestation の要求は常に `client_id` を含みます。

### Credential の要求、Deferred 発行、通知

`RequestCredential` は holder 鍵ごとに key proof を 1 つ送り（複数なら batch 要求になります）、必要に応じて key attestation を付け、`Config.Issuance.CredentialEncryption` に従ってリクエストと応答を暗号化します。
Credential は `CredentialRequest.Acceptance`、なければ grant が発行の始めから引き継いだポリシー、それもなければ `Config.CredentialAcceptance` で検査し、storeless でなければ保存します。
ポリシーが必要とする発行の文脈（Credential Issuer Identifier と形式）はライブラリが渡すので、呼び出し側は Credential を自分で検証し直さずに、発行ごとの受理を構成できます。
`IssuanceResult` は `Credentials` か保留中の `Deferred` トランザクションのどちらかを持ち、Issuer が通知を求めた場合は `Notification` も持ちます。
Token Response が `credential_identifiers`（§6.2）を示した場合、`IssuanceGrant.CredentialIdentifiers` はそのすべてを保持し、`CredentialRequest.CredentialIdentifier` がリクエストで指定する Credential Dataset を選びます（既定は先頭）。holder が求める dataset ごとに `RequestCredential` を呼びます。
`credentials` 配列の要素は、ほかのメンバーがあっても `credential` メンバーを読みます（§8.3）。
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

`DeferredIssuance.Interval` は Issuer が求めた間隔で、短くすることはありません。どれだけ待つかは呼出し側が決めます。
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
`CredentialEncryptionDisabled` は暗号化をしません。`encryption_required: false` で暗号化を提供する Issuer にも暗号化せず、暗号化を要求する Issuer は拒否します（`ErrCredentialEncryptionDisallowed`）。どちらか一方を無効にすると、両方が無効になります。
応答用の鍵は暗号化されたリクエストの中でしか運ばれないため、応答の暗号化を必須にするとリクエストの暗号化も必須になります。
矛盾は `BeginIssuance` または `AuthorizePreAuthorizedIssuance` で拒否します。
応答の復号鍵は一時鍵で、`DeferredIssuance` に含まれて運ばれます。
暗号化を要求した後の平文の応答は拒否します。

### クライアント認証、DPoP、attestation

* **`private_key_jwt`:** `Config.ClientAuth` に `Method: receiverTypes.PrivateKeyJwt`、`ClientID`、`Key` を設定します。パッケージ `clientconfig` は JSON の登録ファイルからこれを読み込みます。
* **Attestation-Based Client Authentication:** `Config.Attestation.Client`（`attestation.ClientProvider`）が、選択した認可サーバー向けに Client Instance Key の Wallet Attestation を提供し、PoP はその鍵で署名します。
  * 既定では、フローごとに一時的な P-256 の Client Instance Key を使います。draft-ietf-oauth-attestation-based-client-auth §11.1 が、認可サーバーをまたいだ名寄せを避けるために推奨するためです。Authorization Code Flow は Pushed Authorization Request の鍵を `IssuanceAuthorization.ClientInstanceKey` に保持し、token エンドポイントでも同じ鍵を使います（§10.4）。
  * `Config.Attestation.ClientKey` は、設定した 1 本の鍵をすべての認可サーバーで使います。`Config.Attestation.ClientKeyFromDPoP` は `Config.DPoP.Key` を attest する opt-in です。両者は併用できません。
  * PoP は最新の Challenge を持ちます。その要求のために `challenge_endpoint` から取得した Challenge があればそれを、なければ同じサーバーの同じ鍵への直近の応答の `OAuth-Client-Attestation-Challenge` ヘッダーを使います。新しい Challenge を伴う `use_attestation_challenge` エラーには、その Challenge で 1 回だけ再試行します。
* **Key attestation:** `Config.Attestation.Key`（`attestation.KeyProvider`）です。
* **DPoP:** proof は `Config.DPoP.Key` で署名し、DPoP に束縛された grant は同じ鍵で提示しなければなりません（`ErrDPoPKeyMismatch`）。サーバーが求めた場合は `use_dpop_nonce` による再試行を 1 回行います。receiver は、サーバーが与える DPoP nonce を origin、役割（認可サーバーか Credential Issuer か、RFC 9449 §9）、DPoP 鍵の組ごとに保持するので、nonce をもう一方の役割や別の鍵で送ることはありません。Nonce Response（§7.2）の DPoP-Nonce は、Credential Issuer に最初に要求した鍵のものになります。receiver plugin は proof を `types.DPoPProver`、attestation のヘッダーを `types.ClientAttestationProver` として受け取り、どちらも鍵の RFC 7638 thumbprint を持ちます。

ライブラリが attester の秘密鍵を保持することはありません。
attestation は送信前に `Config.Attestation.Trust`（`attestation.TrustPolicy`）で認証します。
`x5c` を持つ attestation はその leaf 鍵で検証し、`TrustAnchors` か `RootCAs` があればチェーンも検証します。
`x5c` を持たない attestation には `ResolveKey` が必要です。
パッケージ `attestation` の `StaticClientAttester` と `StaticKeyAttester` は、テストと単一運用者の構成のために、ローカルの鍵で自己発行します。
これらの鍵は wallet が自ら解決します。
HAIP では、attestation は自己署名でない `x5c` leaf を持ち、トラストアンカーを含んではなりません。
さらにチェーンは `TrustAnchors` か `RootCAs` に届かなければなりません。どちらもなければ、`x5c` を持つ attestation を署名だけで検証せずに拒否します。
拒否された attestation は `attestation.ErrClientAttestationInvalid` または `attestation.ErrKeyAttestationInvalid` になります。

### 署名付き Issuer メタデータ

`oid4vci.Oid4vciReceiver.IssuerMetadataSigning` は、OpenID4VCI 1.0 §12.2.3 の署名付き Credential Issuer Metadata を設定します。
`Request` は署名付きメタデータを求める `Accept` ヘッダーを送り、トラスト情報がなければ効果がありません。
HAIP（`Options.RequestSignedIssuerMetadata`）では、`IssuerMetadataSigning` の設定にかかわらず `Request` は有効です。
`Require` は署名のない文書を拒否します。
署名者は `x5c` ヘッダーから `TrustAnchors` または `RootCAs` に照らして認証し、`sub` と `credential_issuer` はどちらも要求した識別子でなければなりません。
`RequireIssuerDNSBinding` と `ExpectedLeafDNSName` は leaf 証明書の DNS 束縛を加えます。
このポリシーは再取得のたびに適用されます。

Draft 13（§11.2.3）では、同じトラスト情報で JSON 文書の `signed_metadata` メンバーを検証します。
`iss`、`sub`（要求した識別子）、`iat` が必須で、`exp` があれば確認し、`typ` は求めません。
検証した claim は JSON の値より優先するので、Draft 13 の各段階は署名された endpoint と `authorization_servers` を使います。
検証できない `signed_metadata` は取得を失敗させます。トラストアンカーが無ければこのメンバーは無視し、`Require` はこれを必須にします。
`SignedMetadata` は検証した署名があるときだけ設定します。

署名付き文書の拒否はすべて `errors.Is(err, ErrIssuerMetadataSignatureInvalid)` を満たし、`ErrIssuerMetadataSubjectMismatch`、`ErrIssuerMetadataLeafDNSMismatch`、`ErrIssuerMetadataExpired` はこれをラップします。
`ErrIssuerMetadataSignatureRequired` は `Require` の結果です。
`CredentialIssuerMetadata.MetadataSignature` は受け入れた署名者を記録し、`RawDocument` は受け入れた文書を保持します。

### Draft 13

`w.Draft13()` は、同じ段階的メソッドと状態の型で OpenID4VCI Draft 13 を実行します。
状態は `Profile` に `profile.Draft13()` を持ちます。
Credential Offer が必須で、`c_nonce` は Token Response と Credential Response から得て、key proof は 1 つだけ送り、key attestation と Credential の暗号化はありません。
`authorization_details` で要求したあとの `credential_identifiers` は任意です（無ければ形式でリクエストします）。
key proof は、`cryptographic_binding_methods_supported` のうち wallet が作れる最初の方式（`jwk` か `did:key`）で鍵を示します（どちらも無ければ `ErrCryptographicBindingMethodUnsupported`）。
アクセストークンは Bearer か DPoP でなければならず、`interval` の無い `issuance_pending` は 5 秒待つものとします（§9.3）。
Credential Issuer Metadata は Draft 13 §11.2.2 の位置からだけ取得します。
`Config.Experimental.Hooks.KeyProof` はテストのために key proof を書き換えます。

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
wallet を必要とせず、`acceptance.NewAcceptor(profile, serializer, verifier)`（`profile` は Credential を発行したプロファイル）が返す `Acceptor` の `Verify(ctx, raw, policy, options)` が `acceptance.Policy` を適用します。
`options.CredentialIssuer` は発行の Credential Issuer Identifier です。
wallet は Credential を返す、または保存する前に、要求のポリシーか `Config.CredentialAcceptance` で同じ検査を実行します。

検査の内容は次のとおりです。

* **解析とヘッダー:** Credential が解析でき、issuer JWT が `Policy.SigningAlgorithms`（既定は `acceptance.DefaultSigningAlgorithms()`、ES256）のアルゴリズムを持つこと。SD-JWT VC では `typ` が `dc+sd-jwt`（SD-JWT VC -19 §2.2.1。`vc+sd-jwt` は `profile.Draft13()` の下でだけ）で、`vct` を持つこと（§2.2.2.3）。
* **Issuer の鍵:** 方式はポリシーではなく Credential で決まります（SD-JWT VC -19 §2.5、§7.3）。
  ポリシーは方式を許すだけです。
  許していない方式にあたる Credential は拒否し、代わりに別の方式を試すことはしません。
  * `x5c` ヘッダがあれば、そのチェーンだけで `IssuerX509` に対して認証します（アンカー、CRL による失効確認、任意の EKU）。信頼できないチェーンは拒否します。`iss` の有無にかかわらず、Issuer は leaf 証明書の subject です（SD-JWT VC -19 §2.5）。`x5c` と並ぶ `iss` は `https` の URL でなければならず、その host を leaf が `dNSName`（完全一致、ワイルドカードは不可）か、同じ scheme の `uniformResourceIdentifier` で名指ししていなければなりません。そうでなければ `ErrIssuerDNSBindingFailed` で拒否します。DID の `iss` と `x5c` の組み合わせは拒否します。DID の Issuer は DID document で認証するので、その Credential は `x5c` を持ちません。その他の `iss` も拒否します。例外は `IssuerX509.Experimental.AllowHTTP` の下の `http` の `iss` で、同じ規則で束縛します（ローカルのテスト用 Issuer のためのもので、`ForbidExperimental` を持つプロファイルは拒否します）。
  * `x5c` がなく `iss` が `https` なら、`IssuerKeys` による JWT VC Issuer Metadata（SD-JWT VC -19 §4、SD-JWT VC だけ）か、`Federation`（Entity Identifier が `iss` である OpenID Federation の Trust Chain から導いた `openid_credential_issuer` metadata の鍵。`acceptance.NewFederationIssuerKeys`）で認証します。
  * `x5c` がなく `iss` が DID なら、`IssuerKeys` で解決し、Credential Issuer の origin が DIF Well Known DID Configuration でその DID を結び付けている場合だけ受け入れます（OpenID4VCI 1.0 §14.4）。
  * それ以外の `iss`、または `iss` がなければ拒否します。
* **holder binding:** `cnf.jwk` は Credential を要求した holder 鍵と一致しなければなりません。`RequireHolderBinding` は `cnf` のない Credential も拒否します。
* **有効性:** 署名、`exp` / `nbf`（`ClockSkew` を考慮）、SD-JWT の disclosure の整合性、wallet が実装する `_sd_alg`（RFC 9901 §4.1.1、§7.1）、`iss`、`nbf`、`exp`、`cnf`、`vct`、`vct#integrity`、`aka_vcts`、`status` の Disclosure がないこと（SD-JWT VC -19 §2.2.2.3）、設定されていれば `ExpectedSDJWTVCType`。
* **`ldp_vc`:** `eddsa-rdfc-2022` の Data Integrity proof を、上と同じ規則で確立した credential の `issuer` の鍵（DID は DID Configuration、`https` の Issuer は `Federation`）と、`Policy.DataIntegrityContexts` に固定した JSON-LD context で検証します。`verificationMethod` は `issuer` に属する必要があり、有効期間は `validFrom` / `validUntil` です。発行では holder との束縛を `did:key` または `did:jwk` の `credentialSubject.id` で判定します。`IssuerX509` は適用されません。

`IssuerKeys` は `*issuerkeys.Resolver` です。
その `Mechanisms` で JWT VC Issuer Metadata（と `jwks_uri`）、DID の各 method、DID Configuration による束縛を有効にします。
`issuerkeys.Request` は acceptor が自分で埋めます。
平文 HTTP で取得できるのは `Resolver.Experimental`（`experimental.Transport`）を設定したときだけです。SD-JWT VC -19 §3 はすべての取得に HTTPS を求めており、`ForbidExperimental` を持つプロファイル（HAIP）は、これを設定した resolver を持つポリシーを拒否します。

`acceptance.Verification`（`SavedCredential.Verification` も同じ）は、Issuer をどう認証したかを記録します。
`Issuer`（認証した主体。`x5c` では leaf 証明書の subject、その他の方式では `iss`）、`ClaimedIssuer`（Credential が持つ `iss`。`x5c` では leaf を束縛した相手であり、認証した主体そのものではありません）、`Mechanism`（`issuerkeys.MechanismX5CTrustedChain`、`MechanismJWTVCIssuerMetadata`、`MechanismDIDConfigurationBinding`、`MechanismOpenIDFederation`）、Issuer の鍵、証明書のフィンガープリントと `IssuerCertificateSubject`、`IssuerDNSBound`、`DID`、`FederationTrustAnchor`、失効確認の件数、holder binding の結果です。
失敗はパッケージ `acceptance` のセンチネル（`ErrIssuerKeyUnresolved`、`ErrIssuerSignatureInvalid`、`ErrHolderBindingMismatch` など）をラップします。
鍵の解決に失敗した場合は、診断を持つ `*issuerkeys.UnresolvedError` か `*issuerkeys.DIDOnlyTrustError` も含みます。
信頼できない、または失効したチェーンは、パッケージ `common/x509` の `*x509.SigningChainError` または `*x509.CRLCheckError` になります。

### fail-closed の既定値

* ポリシーがなければ、認可を得ず、Credential を要求も保存もしません（`ErrCredentialAcceptancePolicyRequired`）。
* Issuer を認証せずに Credential を受け入れるポリシーはありません。
* HAIP では SD-JWT VC に `IssuerX509` が必要です（HAIP §6.1.1）。`x5c` を持たなければならず（`ErrIssuerX5CRequired`）、トラストアンカーを含んではならず（`ErrIssuerX5CTrustAnchor`）、署名証明書は自己署名であってはなりません（`ErrIssuerCertificateSelfSigned`）。
* `AllowUnadvertisedRevocation` は、失効確認の手段を何も示さない（CRL 配布点も OCSP もない）証明書を信頼経路に残し、別に数えて報告します。OCSP は参照しないので、OCSP だけを示す証明書は、この設定にかかわらず拒否します（`x509.CRLErrorUnsupported`）。受け入れると、CA が公開している失効確認を黙って飛ばすことになるためです。

## OpenID4VP 1.0 の提示 {#openid4vp-10-presentation}

### 受け付けた要求

提示要求は一度だけ解析して受け付け、その解析が返したハンドルを通じて応答します。
`*oid4vp.AdmittedRequest` は、どの presenter が要求を受け付けたかと、応答の送り先を記録します。
エンドポイントを呼出し側から受け取ることはなく、ハンドルに応答できるのはそれを受け付けた presenter だけです（`oid4vp.ErrRequestNotAdmittedHere`）。

| メソッド | 目的 |
| --- | --- |
| `ParsePresentationRequest(ctx, uri)` | Authorization Request URI を解析して受け付けます。`request_uri` はライブラリ自身が取得します。 |
| `ParsePresentationRequestObject(ctx, requestObject, src)` | 呼出し側が既に持つ Request Object を、値で渡されたものとして認証します。HAIP は拒否します（`ErrRequestURIRequired`）。 |
| `ReadmitPresentationRequest(ctx, sealed, key)` | `h.Seal(key)` が返した封をした受理から、要求を再び受理します（[解析と提示を分けるとき](#parsing-now-and-presenting-later)を参照）。 |
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

### 解析と提示を分けるとき {#parsing-now-and-presenting-later}

ハンドルはシリアライズできず、要求に応答できるのはそれを受理した presenter だけです。
同意画面と提示を別の呼出しで行い、その間にメモリ上の状態を持たない wallet は、次の 2 つのどちらかで受理を引き継ぎます。

**封をした受理。**
`h.Seal(key)` は `presenterTypes.SealedAdmission` を返します。
最初の受理で観測した事実の記録を、呼出し側が持つ鍵で HMAC-SHA256 によって封をしたものです。
記録には、ライブラリが取得したままの Request Object、取得元の `request_uri`、参照渡しで届いたこと、ライブラリが送った `wallet_nonce`、外側の `client_id`、Request Object を認証した時刻、受理したときのプロファイルのテキスト形式（`profile.Profile.String`、すべての option を名指します）、Draft 24 の要求では `presentation_definition_uri` から取得した Presentation Definition を含みます。
`w.ReadmitPresentationRequest(ctx, sealed, key)`（Draft 24 の要求には `w.Draft24().ReadmitPresentationRequest`）は、同じ鍵で封が検証でき、記録が wallet のプロファイル（テキスト形式で比べます）とメソッドのプロトコルの版を名指し、`MaxReadmitAge` より新しいときだけ記録を受け付けます。
そのうえで、記録した `request_uri` に `RequestURIPolicy` を適用し、Request Object を改めて認証します。
署名、Client Identifier Prefix が選ぶ client の認証、`wallet_nonce` の echo、プロファイルのすべての option を、参照渡しで届いた Request Object として検証します。
`request_uri` は取得し直しません。
結果は通常のハンドルで、`SubmitPresentation` か `DeclinePresentation` で応答でき、もう一度封をすることもできます（同じ記録になります）。

HAIP の wallet が後の呼出しで応答する方法はこれです。
HAIP（`Options.RequireSignedRequestByReference`、§5.1）は値で渡された Request Object を拒否しますが、封をした受理は値渡しではありません。
ライブラリが受け付ける記録を作れるのは鍵を持つ者だけだからです。
wire 上の挙動は変わりません。

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

// admit parses the request for the consent screen and seals the admission;
// the caller stores sealed with its pending presentation.
func admit(ctx context.Context, w *wallet.Wallet, uri string, key []byte) (presenterTypes.SealedAdmission, error) {
	request, err := w.ParsePresentationRequest(ctx, uri)
	if err != nil {
		return "", err
	}
	return request.Seal(key)
}

// answer re-admits the sealed request after the Holder's consent and sends
// the presentation, from a wallet built for this call.
func answer(ctx context.Context, w *wallet.Wallet, sealed presenterTypes.SealedAdmission, key []byte,
	p wallet.Presentation) (*presenterTypes.SubmitResult, error) {
	request, err := w.ReadmitPresentationRequest(ctx, sealed, key)
	if err != nil {
		return nil, err
	}
	return w.SubmitPresentation(ctx, request, p)
}
```

規則は次のとおりです。

* **鍵。** `oid4vp.MinSealKeyBytes`（32）バイト以上の乱数で、wallet の運用者だけが知るものにします。短い鍵は `oid4vp.ErrSealKeyTooShort` です。ライブラリは鍵を保存しません。鍵を入れ替えると、古い鍵で封をした受理は使えなくなります。
* **封ができるもの。** ライブラリが `request_uri` から Request Object を取得した要求（`RequestObjectVerification.Delivery == "reference"`）だけです。値で渡された Request Object、プレーンなパラメータ、DC API の要求は `oid4vp.ErrAdmissionNotSealable` です。引き継ぐべき届き方の事実がないからです。
* **拒否。** 形式が壊れた記録、`v3` 以外の版、正規の padding なし base64url でない記録やタグ、改ざんされた記録やタグ、別の鍵、別のプロファイル（`profile.Final().With(profile.HAIPOptions())` は `profile.Final()` とは別です）、別のプロトコルの版の記録、`Oid4vpPresenter.MaxReadmitAge`（既定は `oid4vp.DefaultMaxReadmitAge` の 15 分）より古い記録、presenter の時計より後に受理したことになっている記録は `oid4vp.ErrSealedAdmissionInvalid`（コード `sealed_admission_invalid`）です。何かを認証したり取得したりする前に判定します。`RequestURIPolicy` が拒否する `request_uri` は、取得の前と同じく `ErrRequestURINotAssociated` です。記録した Presentation Definition の URI を、改めて認証した Request Object が名指さない場合も `ErrSealedAdmissionInvalid` です。
* **時計。** 再受理では、Request Object の `iat`、`exp`、`nbf` を最初の受理の時刻で判定します。そのため、同意が `exp` を過ぎても応答は拒否されません。その期間の上限は `MaxReadmitAge` で、より短い上限を設けたい wallet は `RequestObjectVerification.ExpiresAt` で `exp` を読めます。それ以外はすべて現在の時計で判定します。証明書チェーンとその有効期間、失効（失効リストは改めて取得します）、Verifier Attestation、OpenID Federation の Trust Chain です。最初の受理の後に期限切れや失効となった証明書は、再受理を拒否します。
* **再利用。** ライブラリは状態を持たないので、同じ封は `MaxReadmitAge` まで何度でも再受理できます。封と鍵を持つ者は、同じ要求に何度でも応答できます。要求ごとに一度だけ応答する wallet は `Oid4vpPresenter.ConsumeSealedAdmission(ctx, sealID, notAfter)` を設定します。再受理が成功すると、最後に封の識別子（タグ）と、どのみち再受理できなくなる時刻を渡して呼び出します。hook は識別子を不可分に記録し、既に見た識別子にはエラーを返します。そのとき再受理は `oid4vp.ErrSealedAdmissionConsumed`（コード `sealed_admission_consumed`）で拒否されます。失敗した再受理は封を消費しません。再受理したハンドルにもう一度封をすると同じ封になるので、識別子も同じです。wallet が構築する presenter には hook がありません。設定するには `Config.Presenter` で `Oid4vpPresenter` を注入します。
* **形式。** `v3.` + base64url（JSON の記録）+ `.` + base64url（HMAC-SHA256 のタグ）で、どちらも正規の padding なしの表記です。タグは版を名指すラベルと記録を覆います。記録は、持っている者なら誰でも読めます。封が守るのは完全性であって機密性ではないので、Request Object を置いてよい場所に保管してください。

**保持した Request Object。**
プロファイルが値渡しの Request Object を認める場合（HAIP 以外）は、代わりに Request Object（`h.RequestObject()`）を保持しておき、もう一度解析することもできます。
2 回目の解析では Request Object を、`exp` も含めて現在の時計で再び認証します。

```go
import (
	"context"

	"github.com/trustknots/vcknots/wallet"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
)

// presentLater answers a request admitted earlier from its kept Request Object.
func presentLater(ctx context.Context, w *wallet.Wallet, requestObject, clientID string,
	p wallet.Presentation) (*presenterTypes.SubmitResult, error) {
	request, err := w.ParsePresentationRequestObject(ctx, requestObject, presenterTypes.RequestObjectSource{ClientID: clientID})
	if err != nil {
		return nil, err
	}
	return w.SubmitPresentation(ctx, request, p)
}
```

プレーンなパラメータの要求には Request Object がない（`RequestObject()` が空）ので、その URI をもう一度解析します。
`RequestObjectSource` が持つのは外側の `client_id` だけです。
Request Object がどう届いたかはライブラリが観測するもので、呼出し側が申告するものではありません。
`RequestObjectVerification.Delivery` が `"reference"` になるのは、ライブラリ自身が `request_uri` を取得したとき（またはその取得の封をした受理を再受理したとき）だけで、`WalletNonce` もその POST でライブラリが送った `wallet_nonce` だけを記録します。
値で渡された Request Object は、常に値で届いたものとして扱います。
そのため HAIP では、`ParsePresentationRequestObject` と `request` パラメータを、通信の前に `ErrRequestURIRequired` で拒否します。

### Verifier の認証 {#verifier-authentication}

`oid4vp.Oid4vpPresenter` は Client Identifier Prefix に応じて Verifier を認証します。

| Prefix | 認証 |
| --- | --- |
| `x509_san_dns`、`x509_hash` | 署名付き Request Object が必須です。`x5c` チェーンは `RequestObjectValidation.TrustAnchors` / `RootCAs`（または `X509TrustChainRoots`）に届かなければならず、CRL で失効を確認します。`x509_san_dns` は DNS SAN と応答エンドポイントを、`x509_hash` は leaf 証明書のハッシュを束縛します。HAIP は `x509_hash` を要求します。 |
| `redirect_uri` | 署名なしのみです。応答エンドポイントを識別子に束縛しますが、誰も認証しません。 |
| なし（pre-registered） | client は `PreRegisteredClients` にあるか、`ResolvePreRegisteredClient` で見つからなければなりません（`oid4vp.ErrPreRegisteredClientUnknown`）。登録された `Metadata` が要求のメタデータに代わり、その `Metadata.RedirectURIs` だけが応答エンドポイントとして受け入れられます。これがない登録はどの要求も受け入れません。署名付き Request Object は登録された `JWKS` で検証し、`RequireSignedRequestObject` は署名なしの要求を拒否します。 |
| `verifier_attestation` | 署名付き Request Object が必須です。Verifier Attestation JWT は `RequestObjectValidation.VerifierAttestationIssuers` のいずれかが発行したものでなければならず、Request Object はその `cnf` 鍵で署名されていなければなりません。 |
| `openid_federation` | 署名付き Request Object が必須です（OpenID Federation 1.0 §12.1.1）。`RequestObjectValidation.Federation.TrustAnchors` への Trust Chain で認証し、Request Object は、導出した `openid_credential_verifier` メタデータが `jwks`、`signed_jwks_uri`（Verifier の Federation Entity Key で署名されたもの）、`jwks_uri` で公開する鍵で検証します。Federation Entity Key そのものでは検証しません（§12.1.1.1.2、§5.2.1。`federation.ErrVerifierKeysUnavailable`）。 |
| `decentralized_identifier` | 拒否します。 |
| `origin` | 拒否します（`ErrClientIDPrefixReserved`）。 |

署名を要求する prefix の要求がプレーンなパラメータで届いた場合は、`ErrRequestObjectSignatureRequired` で拒否します。
解析済み要求の `RequestObjectVerification` は、認証した内容（証明書のフィンガープリントと `Certificate` の要約、失効確認の件数、echo された `WalletNonce`、`Delivery`、`ExpiresAt`、`VerifierAttestation` または `Federation` の証跡）を記録します。
要求のパラメータからこの値を設定することはできません。

`client_metadata.jwks` のすべての要素は、他の要素と重ならない `kid` を持たなければなりません（OpenID4VP 1.0 §5.1。`ErrClientMetadataJWKKeyIDMissing`、`ErrClientMetadataJWKKeyIDDuplicate`）。
`RequestObjectValidationOptions.RequestURIPolicy(clientID, requestURI)` を使うと、trust framework の中の wallet は `request_uri` を `client_id` に結び付けられます。
これは取得の前に呼ばれ（封をした受理の再受理では、記録した `request_uri` に対して呼ばれ）、拒否は `ErrRequestURINotAssociated` になります。
`oid4vp.RequestURISameHost` はそのようなポリシーの 1 つです。
`https` を求め、`x509_san_dns`、`redirect_uri`、`openid_federation` の Client Identifier が名指す host と一致させます。
host を名指さない prefix は受け入れます。

`client_metadata` のうち、要求の版が使うメンバ（1.0 では `jwks`、`encrypted_response_enc_values_supported`、`vp_formats_supported`、Draft 24 では `jwks`、`vp_formats`、JARM のメンバ）は正しい形でなければなりません。
それ以外のメンバは、型が合うときだけ保持し、要求を拒否する理由にはしません（OpenID4VP 1.0 §5.1「Other metadata parameters MUST be ignored」）。
もう一方の版の形式のメンバは読まず、`openid_federation` の要求の `client_metadata` は読みません（§5.9.3）。
Issuer 署名の JWT または KB-JWT のアルゴリズムが、Verifier の `sd-jwt_alg_values` / `kb-jwt_alg_values` にない提示は、送る前に `ErrVPFormatAlgUnsupported` で失敗します。

`redirect_uri` を持つ `direct_post` / `direct_post.jwt` の要求は `invalid_request` です（`ErrRedirectURIWithDirectPost`、§8.2）。
`redirect_uri` の Client Identifier によって `response_uri` を省略した要求も同じです。

`RequestObjectValidationOptions` は Relying Party 側のポリシーで、`TrustAnchors` または `RootCAs`、`CRL`、`AllowUnadvertisedRevocation`、`CertificateKeyUsages`、`WalletAudience`、`SigningAlgorithms`（既定は ES256 と RS256）、`RequireExpiry`、`MaxAge`（ゼロはどのプロファイルでも無制限です）、`Now`、`ClockSkew` を持ちます。
`iat` が未来の Request Object は拒否するので、受け入れる Verifier の時計のずれに合わせて `ClockSkew` を設定してください。
`X509TrustChainRoots` だけを使う場合は、失効情報を公開していない証明書も受け入れます。ただし、OCSP だけを示す証明書は拒否します。
`RequestObjectValidation` のアンカーと併用はできません。

`Oid4vpPresenter.Experimental`（`experimental.Presenter`）は、どの仕様も認めない緩和を持ちます。
ローカルの Verifier や実験のためだけのものです。
`Transport.AllowHTTP` は平文 HTTP の Verifier エンドポイントを受け入れます。
`InsecureSkipX509Verify` は Draft 24 の `x509_san_dns` の Request Object を束縛と署名だけで確かめ、`RequestObjectVerification` なしで受け付けます。これを設定している間、OpenID4VP 1.0 の経路はすべての署名付き Request Object を拒否します。
`AcceptClientMetadataJWKsWithoutKeyID` は `kid` の規則を緩めます。
ゼロ値は何も緩めません。HAIP の presenter は、どの入口でもこれらのいずれも拒否します。

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
各 entry は、Holder が割り当てた提示 Credential に束縛されます（§5.1「the Wallet MUST use only one of the referenced Credentials」）。
`CredentialSelection.TransactionData` は、その Credential で承認する entry の index を列挙します。
割り当てがある場合、すべての entry を割り当てなければならず、1 つの entry を割り当てる Credential は、その `credential_ids` のうち同じ 1 つの query に答えるものでなければなりません。
同じ query の複数の Credential に載せるのは、割り当てがそれぞれを名指すときだけです（`ErrTransactionDataAssignmentInvalid`）。
割り当てがない場合、entry は `credential_ids` のうち最初に提示される query に載ります。
その query に答える Credential が複数ある（`multiple: true`）ときは、すべてに載せずに `ErrTransactionDataAssignmentRequired` で失敗します。
ハッシュアルゴリズムは entry の `transaction_data_hashes_alg` から決まります（既定は `sha-256`）。
Draft 24 の要求も同じ規則に従います。
`credential_ids` は input descriptor を指し、それぞれ SD-JWT VC（`vc+sd-jwt`）を受け付けなければなりません。

### 応答モードと暗号化

リクエスト URI と Request Object は `direct_post` か `direct_post.jwt` を使い、DC API の要求は `dc_api` か `dc_api.jwt` を使います。
それぞれの経路は他方のモードを拒否します。
HAIP は `direct_post.jwt` を、DC API では `dc_api.jwt` を要求します。
`direct_post.jwt` と `dc_api.jwt` には `client_metadata.jwks` の暗号化鍵が必要です（`ErrResponseEncryptionKeyMissing`）。
鍵は `alg` を持たなければならず、それが JWE の `alg` になります（OpenID4VP 1.0 §8.3）。
`authorization_encrypted_response_alg` がその代わりになることはありません。
応答は ECDH-ES 系の JWE で、`enc` は `encrypted_response_enc_values_supported` から wallet の優先順（A256GCM が先。一覧がなければ A128GCM）で選びます。
HAIP では鍵が P-256 の ECDH-ES でなければならず、Verifier は A128GCM と A256GCM の両方を列挙していなければなりません（`ErrResponseEncryptionEncMissing`）。
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
受け付けた要求は、それを `Request().Origin` として持ちます。
署名なしの要求には Client Identifier がありません。
その `client_id` と `expected_origins` は無視し、`ClientID` は空のままです（Appendix A.2）。
署名付きの要求は、`x509_san_dns` または `x509_hash` の Client Identifier の `x5c` チェーンで認証します。
`expected_origins` は origin を完全一致で含まなければなりません。
`aud` はなくてもよく、ある場合は wallet を指していなければなりません。
multi-signed の要求では、すべての署名が `oauth-authz-req+jwt` で型付けされていなければなりません。
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
定義は値で渡されても、`presentation_definition_uri` で参照されてもかまいません。
参照はライブラリが要求の認証後に取得し（§5.5、パラメータなしの `GET`、`https`、リダイレクトなし、失敗は `invalid_presentation_definition_uri` / `_reference`）、`PresentationDefinition` と `RawPresentationDefinition` に報告します。
封をした受理は、取得した定義を再受理へ運びます。
`w.Draft24().ReadmitPresentationRequest` は、Draft 24 の要求の封をした受理を再び受理します。
ハンドルには `SubmitPresentation`（`vp_token` と `presentation_submission`）と `DeclinePresentation` で応答します。
`SelectCredentials` は input descriptor ごとに最も新しい Credential を選び、`QueryIDs` は input descriptor の id を指定します。
SD-JWT VC では key binding が常に必須で、nil でない `DisclosedClaims` が開示を制限します。
`limit_disclosure` が `required` の input descriptor は、提示をその `fields` が名指すクレームに限ります。
各 field は、その `path` のうち Credential で最初に解決できたものです。
クレーム名ではなく JSONPath 全体（`$.a.b`、`['a']`、`[0]`、`[*]`）で照合します。
このとき `DisclosedClaims` は、field が必要とする disclosure をすべて含む場合に限り、その field を残します。
選択的に開示できない Credential、どの field も必要としない disclosure、1 つの位置を指さない path（再帰下降やフィルタ）、どの field も覆わない平文のメンバーを持つ親の disclosure は、何かを送る前に `ErrLimitDisclosureUnsatisfiable` で失敗します。
disclosure は一部だけを開示できないためです。
input descriptor の `format` のアルゴリズムの列挙は `vp_formats` と同じく適用します。
ただし `vp_formats` にない形式は無視します（§5.4）。
`Config.Experimental.Hooks.PresentationExchangeResponse` はテストのために応答を書き換えます。

**プロトコルの版。**
2 つの版は要求の構文が同じなので、入口は、片方の版だけの規則より前に、クエリ言語で版を決めます（`oid4vp.VersionMismatchError`、コード `oid4vp_version_mismatch`）。
`dcql_query` がなく `presentation_definition` または `presentation_definition_uri` を持つ要求が OpenID4VP 1.0 の入口に届くと、Draft 24 を名指して拒否します。
外側が `response_mode=direct_post.jwt` で、署名付きの `request_uri` の中身が PE の場合も同じです。
`dcql_query` の要求が Draft 24 の入口に届くと、1.0 を名指して拒否します。
ライブラリは Draft 24 の DCQL の応答（§8.1）を実装していません。
`w.AdmitPresentationRequestUnderVersion(ctx, err)` は、拒否した要求を、エラーが名指す版で受理します。
`request_uri` は取得し直さず、送った `wallet_nonce` とともに参照渡しで届いた Request Object として認証します。
PE のパラメータも持つ 1.0 の要求は、それを無視します（§5）。
クエリ言語を 2 つ以上持つ Draft 24 の要求は `invalid_request` です。

Draft 24 の入口は、1.0 ではなく Draft 24 の規則を適用します。

* **Client Identifier Scheme**（Draft 24 §5.10.4）: `redirect_uri`（署名なしのみ。Response URI は Client Identifier と一致しなければならず、省略時は Client Identifier になります）、`https` の OpenID Federation の Entity Identifier、`verifier_attestation`、`x509_san_dns`、コロンのない pre-registered client を受け付けます。pre-registered client は `PreRegisteredClients` / `ResolvePreRegisteredClient` で解決し、登録されたメタデータを `client_metadata` より優先します（§5.1）。`did` と `x509_san_uri` は未対応として拒否し（`ErrRequestObjectClientAuthUnsupported`）、`web-origin` は DC API 専用として拒否します（`ErrClientIDPrefixReserved`）。1.0 の prefix である `x509_hash`、`decentralized_identifier`、`openid_federation`、`origin` は Draft 24 の scheme ではありません。Request Object を `client_metadata` の鍵で検証することはなく、Draft 22 より前の `client_id_scheme` パラメータは無視します。
* **`request_uri`**: POST では毎回新しい `wallet_nonce` を送り、Request Object はそれを echo しなければなりません。`WalletMetadata` があればそれも送ります（§5.11）。`request_uri_method` は大文字と小文字を区別します。`OmitWalletNonce` を設定すると POST に `wallet_nonce` を含めず、echo も検査しません。echo が求められるのは Wallet が送った場合だけだからです。
* **応答**: 応答するのは `direct_post` と `direct_post.jwt` だけです。`direct_post.jwt` は暗号化した JARM の応答です（§8.3）。`vp_token` は、1 つのコンパクトな提示なら文字列、配列や `ldp_vp` のオブジェクトなら JSON のまま埋め込みます（§8.1）。JWE の `alg` は `authorization_encrypted_response_alg`（必須）、`enc` は `authorization_encrypted_response_enc`（なければ A128CBC-HS256）で、鍵は `use` が `enc` かなしで、`alg` があればそれが一致する `client_metadata.jwks` の鍵です。`client_metadata.jwks` に `kid` は要らず、HAIP は適用しません。

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

`NewWalletWithConfig` は構成を `Config.Profiles` に照らして確認します。

* `Config.Profiles` は 1.0 のプロファイルをちょうど 1 つ、Draft のプロファイルをそれぞれ高々 1 つ含みます（`ErrInvalidArgument`）。`Options.ForbidDraftProfiles` を持つ 1.0 プロファイル（HAIP）は、Draft のプロファイルと併用できません（`ErrProfileForbidsDraft`）。
* `profile.Carrier` を実装する receiver / presenter の plugin は、option を含めて wallet の 1.0 プロファイルを報告しなければなりません（`ErrProfileMismatch`）。Draft のプロファイルを報告する plugin は拒否します（`profile.ErrDraftProfile`）。1.0 プロファイルが option を持つとき（HAIP、または `With` で強めた Final）は `profile.Carrier` を実装しない plugin を拒否し（`ErrProfilePluginUnsupported`）、素の Final では受け入れます。
* `Draft13()` のメソッドは `profile.Draft13()` が、`Draft24()` のメソッドと Draft 24 の handle は `profile.Draft24()` が有効でなければ `ErrProfileForbidsDraft` を返します。`Experimental.Hooks` は Draft のプロファイルが 1 つも有効でなければ拒否します。
* `Experimental.Transport` と `Experimental.Hooks` は `ForbidExperimental` を持つプロファイル（HAIP）で拒否し、`Experimental.Transport` は wallet が再構成しない注入された `Receiver` / `Presenter` との併用でも拒否します（`ErrInvalidArgument`）。
  プロファイルが禁じる `Experimental` を自身に持つ注入された `oid4vci.Oid4vciReceiver` も拒否し（`Oid4vciReceiver.ValidateProfile`）、そのような receiver はどの交換でも何も送りません。
* DPoP 鍵のない `Attestation.ClientKeyFromDPoP` と、`Attestation.ClientKey` と併用した `Attestation.ClientKeyFromDPoP` は拒否します（`ErrInvalidArgument`）。
* `Storeless` と `CredStore` の併用、`SupportedTransactionDataTypes` と `Presenter` の併用、`*oid4vp.Oid4vpPresenter` 以外の `Presenter` plugin は拒否します（`ErrInvalidArgument`）。

receiver と presenter はここで一度だけ確認します。
wallet には、後からそれらを差し替えるメソッドはありません。
plugin のフィールドは登録後に変更してはなりません。
HAIP はさらに、それぞれ `profile.Options` のフィールドを通じて、PAR、DPoP に束縛されたアクセストークン、クライアント認証の手段、すべての Credential Configuration の `scope`、key attestation が必要なときの Nonce Endpoint、`x509_hash`、`request_uri` で配送される署名付き要求、暗号化された応答モード、SD-JWT VC の issuer `x5c`、`cnf` を持つすべての SD-JWT VC への Key Binding JWT などを要求します。
`Experimental.Transport`（wallet、receiver、Issuer の鍵の resolver、Status List の checker）と、presenter のゼロ値でない `Experimental` は、すべての入口で拒否します。

`w.StatusListChecker(base)` は、`base` の `Profile` が wallet の 1.0 プロファイルであることを確かめてから `statuslist.Checker` の複製を返します（違えば `ErrProfileMismatch`）。
checker は自身のプロファイルの Option を適用します。HAIP 1.0 §6.1 なら、token の鍵を `x5c` に含める、トラストアンカーを含めない、自己署名の leaf を使わない、です。そのため HAIP の wallet でゼロ値（Final）のプロファイルのままの checker は、弱い規則で動かさずに拒否します。
鍵の hook `issuerkeys.Resolver.StatusListKeyFunc` は、設定したアンカーに届く token の `x5c` チェーンの leaf を受け入れます。draft-ietf-oauth-status-list-21 §11.3 は、Status List Token の署名者と Credential の Issuer との束縛を義務づけていないからです。
`profile.Options.RequireStatusListSignerBinding` はどのプロファイルでも既定で無効で、有効にすると、leaf が Credential の Issuer 証明書（`X5CTrust.IssuerCertificate`）と同じ鍵か subject を持つこと、同じ CA が発行したこと、または `iss` のホストを名指すことも求めます。
Extended Key Usage は `X5CTrust.KeyUsages` を設定したときだけ要求します。
`ForbidExperimental` の下では、`Experimental` を設定した checker を拒否します（`statuslist.ErrStatusListInsecureTransportForbidden`）。
ライブラリが既定で作る HTTP client（receiver、presenter、Federation の resolver、Issuer の鍵の resolver、Status List の checker、CRL の取得）は、すべて TLS 1.2 以上で接続します（HAIP 1.0 §4 が適用する FAPI 2.0 Security Profile §5.2.1、BCP 195）。
呼出し側が注入した client は、その TLS 設定のままです。

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
		return "configure Config.CredentialAcceptance or the Acceptance of the issuance request"
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

observer に渡すリクエストでは、秘密を `observe.Redacted` に置き換えています。
対象は、`Authorization` の scheme より後ろの値、`DPoP`、`OAuth-Client-Attestation`、`OAuth-Client-Attestation-PoP` の各ヘッダー、form body の `pre-authorized_code`、`tx_code`、`code`、`code_verifier`、`client_assertion`、`refresh_token` です。
送信するリクエストは変わりません。
秘密を見る必要がある observer には、opt-in の `observe.UnredactedTransport` を使います。その observer は bearer secret を扱うことになります。

## 試験用の設定 {#experimental}

パッケージ `experimental` は、OpenID4VC の規格から外れる設定をすべて持ちます。
相手側を試験するためのもので、本番環境向けではありません。
規格から外れる設定は、このパッケージの型を `Experimental` という名前のフィールドに渡すことでだけ設定できるので、規則を緩めるコードは必ずこのパッケージを import します。

| 設定 | 渡す場所 | 効果 |
| --- | --- | --- |
| `experimental.Transport{AllowHTTP}` | `Config.Experimental.Transport`（wallet が構築する plugin）、`oid4vci.Oid4vciReceiver.Experimental`、`issuerkeys.Resolver.Experimental`、`statuslist.Checker.Experimental`、`acceptance.IssuerX509TrustOptions.Experimental` | ローカルのテスト用 Issuer のために、平文 HTTP のエンドポイント、識別子、メタデータ、Status List のエンドポイントを受け付け、`http` の `iss` を host で `x5c` の leaf に束縛します。wallet が構築する presenter にも設定します。client assertion を平文 HTTP で送るのは、引き続き loopback ホストに対してだけです。 |
| `experimental.Presenter{Transport, InsecureSkipX509Verify, AcceptClientMetadataJWKsWithoutKeyID}` | `oid4vp.Oid4vpPresenter.Experimental` | 平文 HTTP の Verifier エンドポイント、チェーンを検証しない Draft 24 の `x509_san_dns` の Request Object、1.0 の経路での `kid` が一意でない `client_metadata.jwks`（OpenID4VP 1.0 §5.1）を受け付けます。 |
| `experimental.Hooks{KeyProof, PresentationExchangeResponse}` | `Config.Experimental.Hooks` | Draft 13 の key proof（`ProofTransform`、`ProofJWTContent`）と Draft 24 の応答（`Draft24ResponseTransform`）を構築後に書き換えます。 |

どの型もゼロ値が規格どおりの挙動です。
環境変数からは何も読みません。
規格外の設定を禁じるプロファイルは、無視せずに拒否します。HAIP は、どこに渡した `Transport` も、ゼロ値でない `Presenter` も拒否します。`Presenter` は presenter のすべての入口（OpenID4VP 1.0、Digital Credentials API、Draft 24、再受理）で、ネットワークに触れる前に拒否します（Status List の checker は `statuslist.ErrStatusListInsecureTransportForbidden`、ほかは不正な入力または `invalid_request` のエラーです）。`Hooks` も拒否します。`Hooks` にはもともと Draft のプロファイルが必要です。

## 環境変数

環境変数は `wallet/env/env.go` で定義されています。

| 変数 | 既定値 | 説明 |
| :---- | :---- | :---- |
| `VCKNOTS_WALLET_DEBUG` | `false`（未設定 / 空） | デバッグログのみを有効化します。HTTPS の要件は緩和しません。 |

テストコードからは `env.SetDebugMode(true)` で設定できます。
平文 HTTP を許可する環境変数はありません。[`experimental.Transport`](#experimental) を使ってください。

## 以前の wallet API からの変更点

このセクションは、upstream の `main`（`51149d9`）の wallet API に存在する識別子に加えた変更と、そのメソッドの挙動の変更を挙げます。
この版で追加した識別子は、ここまでのセクションで説明しています。
upstream の `main` のエクスポートされたシグネチャは、下に挙げる削除または変更した `Wallet` のメソッドと型、削除した `env` の識別子を除いて変わっていません。

**パッケージ `wallet`**

* `Config` は `==` で比較できなくなりました。
* `Config` に新しいフィールド `Profiles`、`Storeless`、`CredentialAcceptance`、`SupportedTransactionDataTypes`、`Issuance`、`Attestation`、`Experimental` があります。`CredentialOfferGrant` に `IssuerState` と `AuthorizationServer` が、`SavedCredential` に `Verification` があります。
* `NewWalletWithConfig` は、不正な `Profiles`、wallet と異なる profile の plugin、プロファイルが option を持つときの `profile.Carrier` を実装しない plugin、Draft のプロファイルがないときの `Experimental.Hooks` を拒否します。`CredStore` を伴う `Storeless`、注入した `Presenter` を伴う `SupportedTransactionDataTypes`、`*oid4vp.Oid4vpPresenter` 以外の presenter plugin も拒否します。エラーにはコードがあります。
* `SetReceiver` を削除しました。`Config.Receiver` を設定してください。`NewWalletWithConfig` がその plugin を wallet のプロファイルと照合し、一致しなければ構築時に拒否します。
* `VerifyCredential` を削除しました。保存前の発行と同じ検査は `VerifyCredentialForAcceptance` です。署名だけの検査は `verifier.VerificationDispatcher` の `Verify` で、登録されたアルゴリズムをすべて受け付けるので、アルゴリズムのポリシーは呼出し側が適用します。
* `ReceiveCredential` と `ReceiveCredentialRequest` を削除しました。発行は `AuthorizePreAuthorizedIssuance`（または `BeginIssuance` と `AuthorizeIssuance`）の後に `RequestCredential` を呼びます。OpenID4VCI 1.0 の Issuer には `Wallet` の、Draft 13 の Issuer には `Draft13()` のメソッドを使います。upstream のメソッドは解析しただけの Credential を保存していました。いまはすべての発行が token request の前に受理ポリシーを必要とし、ポリシーが拒否する Credential は保存しません。Draft 13 の Issuer では key proof に Token Response の `c_nonce` を入れ、`nonce_endpoint` は呼びません。Draft 13 の token request は、OpenID4VCI 1.0 の `token_endpoint_auth_methods_supported` による交渉ではなく、Draft 13 §6.1 に従います。`Config.ClientAuth.ClientID` があれば常に送り、匿名の token request（`client_id` なし）には `pre-authorized_grant_anonymous_access_supported: true` が必要です（値がなければ `false` です）。設定した方式を黙って落とすことはありません。`private_key_jwt` はサーバーが広告しているときだけ使い、`none` はサーバーが `none` を含む一覧を公開しているか、`token_endpoint_auth_methods_supported` を公開していないか、匿名アクセスを宣言しているときだけ使います。それ以外の組合せは、送信前に `client_authentication_unavailable` で拒否します。Draft 13 の Authorization Code Flow とその PAR の要求も同じ規則に従います。Offer の Issuer は、receiver plugin が許す場合（`HTTPSchemePolicy`）に限り平文 HTTP を使えます。
* `pre-authorized_grant_anonymous_access_supported: true` を宣言し、`token_endpoint_auth_methods_supported` を省略した認可サーバーへの pre-authorized_code の token request は、`client_authentication_unavailable` で拒否せず、匿名（クライアント認証なし、`client_id` なし）で送ります（OpenID4VCI 1.0 §6.1、§12.3）。方式の一覧を公開しているサーバーでは、従来どおりその一覧で決めます。
* `PresentCredential`、`PresentCredentialWithOptions`、`PresentCredentialOptions`、`RedirectHandler` を削除しました。提示は `ParsePresentationRequest`、`SelectCredentials`、`SubmitPresentation` で行い、後の 2 つの間で holder の同意を得ます。Verifier のリダイレクト URI は `SubmitResult.RedirectURI` に入り、ライブラリはたどりません。保存済み Credential は最新のものではなく DCQL クエリで選び、答える query ごとに提示を作り、query の要求どおりに Key Binding JWT を付けます。要求は [Verifier の認証](#verifier-authentication)の規則で受け付けます。
* `FetchCredentialIssuerMetadata` は `context.Context` と Credential Issuer Identifier を受け取ります。OpenID4VCI 以外を選べなかった `receivingType` 引数を削除しました。メタデータは wallet の 1.0 プロファイルの下で OpenID4VCI 1.0 §12.2.2 の位置から読みます。
* `GetCredentialEntries` と `GetCredentialEntry` は、storeless の wallet で `ErrNoCredentialStore` を返します。
* `Wallet` のメソッドが返すエラーにはすべてコードがあります（`wallet.ErrorCode`）。

**plugin とサブパッケージ**

* `oid4vp.Oid4vpPresenter` は `==` で比較できなくなりました。`oid4vci.Oid4vciReceiver` と `oid4vp.Oid4vpPresenter` には新しいフィールド（`HTTPClient`、receiver の `Experimental`、`Profile` など）とメソッドがあります。`receiver.WithDefaultConfig`、`presenter.WithDefaultConfig`、`NewWallet` が構築する plugin は HTTPS を要求し、環境変数でこれを変えることはできません。
* `oid4vci.OID4VCICredentialFormatToSerializationFlavor` を削除しました。発行のプロファイルを渡して `oid4vci.CredentialFormatFlavor` を使います。Draft 13 の発行（`Draft13()`）は、Issuer のメタデータを Draft 13 §11.2.2 の位置から読み、形式を `CredentialFormatFlavor(profile.Draft13(), …)` の Draft 13 の表（`jwt_vc_json`、`ldp_vc`、`vc+sd-jwt`）で対応付けます。`dc+sd-jwt` は `oid4vci.ErrCredentialFormatUnsupported` で拒否します。upstream の `ReceiveCredential` は未知の形式を JWT VC として保存していましたが、いまは拒否します。
* receiver plugin は HTTP のリダイレクトをすべて拒否し（`ErrHTTPRedirectNotAllowed`）、応答ボディの大きさを制限し、`credential_issuer` が要求した識別子と異なる Credential Issuer Metadata と、`issuer` が要求したものと異なる認可サーバーメタデータを拒否します。
* `Oid4vpPresenter.ParsePresentationRequest` は [Verifier の認証](#verifier-authentication)のとおりに Verifier を認証します。署名付き Request Object は prefix ごとの仕組みで検証し、`client_metadata` の鍵では検証しません。`x509_*` の prefix は署名付き Request Object を要求し、コロンのない `client_id` は登録が必要な pre-registered client として扱い、`iat` が未来のものは拒否します。`X509TrustChainRoots` は失効情報のない証明書を引き続き受け入れます。
* `Oid4vpPresenter.AllowHTTP` と `InsecureSkipX509Verify` を削除しました。`Oid4vpPresenter.Experimental`（`experimental.Presenter`）で明示的に設定します。`NewWallet` と `presenter.WithDefaultConfig` が構築する presenter は `VCKNOTS_WALLET_HTTP_ALLOWED` を読まなくなりました。`Oid4vpPresenter.RequireClientMetadataJWKKeyIDs` を削除しました。OpenID4VP 1.0 の入口は、`Experimental.AcceptClientMetadataJWKsWithoutKeyID` を設定しない限り、重複のない `kid` を常に要求します。`requestBuilder.WithHTTPAllowed` を削除しました。
* `issuerkeys.Resolver.AllowHTTP` と `statuslist.Checker.AllowHTTP` を `Experimental experimental.Transport` に置き換えました。プロファイルが `ForbidExperimental` を持つ `statuslist.Checker` は、`Experimental` を無視せず `statuslist.ErrStatusListInsecureTransportForbidden` で拒否し、その規則を `KeyRequest.ForbidExperimental` で鍵の hook に渡します。`Resolver.StatusListKeys` はそれを resolver 自身の `Experimental` に適用します。
* `presenterTypes.RequestObjectSource.DeliveredByReference`、`RequestObjectSource.WalletNonce`、`oid4vp.RequestObjectVerification.DeliveryAttested` を削除しました。ライブラリは自ら観測した配送と自ら送った `wallet_nonce` を記録し、HAIP は値で渡された Request Object を拒否します。
* `oid4vp.FederationTrustOptions.AllowUnsignedRequests` を削除しました。署名なしの `openid_federation` の要求は常に拒否します。federation の Request Object は、Federation Entity Key ではなく `openid_credential_verifier` メタデータの鍵で検証します。
* `oid4vp.OID4VPClientIDPrefixWebOrigin` を削除しました。署名なしの DC API の要求は `ClientID` が空のままで、platform の Origin は `CredentialPresentationRequest.Origin` が持ちます。OpenID4VP 1.0 は JWK の `alg` を常に要求するので、`profile.ResponseEncryptionRules.RequireJWKAlg` を削除しました。
* presenter は解析に失敗しても、エラー応答を送らなくなりました。求める場合は `SendParseErrorResponses` または `AuthorizationRequestError.SendErrorResponse` が送ります。`request_uri` の取得と応答の POST（`Present`）はリダイレクトに従わず、`Present` への 2xx 以外の応答は `*oid4vp.VerifierResponseError` になります。
* `NewRequestBuilder` は `profile.Final()` の下で OpenID4VP 1.0 の要求を構築します。`WithProfile` で別の 1.0 プロファイルを選べます。
* SD-JWT VC の serializer は、文字列でない `_sd_alg` や実装していないハッシュを名指す `_sd_alg` を拒否します。以前は `sha-256` として扱っていました（RFC 9901 §4.1.1、§7.1）。また、`iss`、`nbf`、`exp`、`cnf`、`vct`、`vct#integrity`、`aka_vcts`、`status` とその sub-claim の Disclosure を拒否します（`serializerTypes.ErrRegisteredClaimDisclosed`、SD-JWT VC -19 §2.2.2.3）。
* `receiver.ReceivingDispatcher` と `presenter.PresentationDispatcher` に新しいメソッド（`Plugins`、transport と解析のアクセサ）があります。`sdjwtvc.SdJwtVcPresentationOptions` に `LimitDisclosureToSelectedClaims` と `RequireRootClaimMatch` が、`presenterTypes.PresentationRequest` に `ResponseMode` があります。`receiver/types` のメタデータの型に新しいフィールドがあります。
* `env.IsHTTPAllowed`、`env.SetHTTPAllowed`、`env.HTTP_ALLOWED` を削除し、`VCKNOTS_WALLET_HTTP_ALLOWED` は読まなくなりました。ローカルテストでの平文 HTTP には [`experimental.Transport`](#experimental) を使います。
* コンポーネントのパッケージ（`keystore`、`credstore`、`presenter/types`、`common` など）のセンチネルエラーはコードを持ちます。`errors.Is` は引き続き一致します。
* `receiverTypes.SignatureAlgorithm` は、JWA 名の無い COSE アルゴリズム識別子を失敗させず、10 進の文字列として保持します。未知の `credential_signing_alg_values_supported` の値で Credential Issuer Metadata 全体が読めなくなることはありません。

## 7. 注意事項

1. **モック鍵は本番環境で使用禁止 (CRITICAL):**
    - このチュートリアルのインメモリの鍵（および `wallet/examples/common/` の `MockKeyEntry`）は、秘密鍵を Go のヒープ上に平文で保持します。テストとデモンストレーションにだけ使ってください。
    - 本番環境では、`Sign` を OS のキーストア（iOS Secure Enclave、Android Keystore）や HSM に委譲し、秘密鍵がアプリケーションのメモリにロードされない形で `IKeyEntry` を実装してください。

2. **GOPRIVATE の設定:**
    - `go mod download` または `go build` が失敗する場合、最も可能性が高い原因は GOPRIVATE 環境変数の設定漏れです。

3. **永続化ストレージ (bbolt):**
    - `credstore.WithDefaultConfig()` は `<ユーザー設定ディレクトリ>/vcknots/wallet/.local_credstore.db` に Credential を永続化します。プロセスがこのディレクトリを作成し、書き込めるようにしてください。

4. **HTTPS の強制:**
    - wallet は Issuer と Verifier のエンドポイントに HTTPS を要求します。Issuer への [`experimental.Transport`](#experimental)、Verifier への `experimental.Presenter` による緩和は、ローカル開発に限ってください。

5. **OpenID4VP `client_id` の厳格な検証:**
    - wallet は `client_id` を厳格に検証します。重複した prefix（例: `x509_san_dns:x509_san_dns:...`）、不正な形式、wallet 専用の prefix は拒否します。
    - `x509_san_dns` では、Request Object の `x5c` ヘッダーから証明書を取り出し、その DNS Subject Alternative Name のいずれかが `client_id` の値と一致しなければなりません。

6. **`experimental.Presenter.InsecureSkipX509Verify`:**
    - Draft 24 の入口で証明書チェーンの検証を省略し、束縛と署名だけを確認します。これを設定している間、OpenID4VP 1.0 の経路は署名付き Request Object を拒否し、HAIP はこの設定を拒否します。
    - ⚠️ コンフォーマンステストかローカル開発でのみ使ってください。

## 8. トラブルシューティング

* **Q: `go mod download` が `package ... is private` または `404 Not Found` で失敗する。**
  * **A:** GOPRIVATE 環境変数が設定されていません。「1. 前提条件」を参照してください（または mise を使用してください）。

* **Q: 受領または提示が `connection refused` または `timeout` で失敗する。**
  * **A:** Issuer/Verifier サーバーが起動していません。`pnpm -F @trustknots/server start` で起動し、http://localhost:8080 が応答することを確認してください。

* **Q: 受領が `credential issuer must use https scheme` で失敗する。**
  * **A:** wallet は HTTPS を要求します。HTTP のローカルサンプルサーバーに対しては、`Config.Experimental.Transport.AllowHTTP` を設定するか、自分で構築する receiver、presenter、Issuer の鍵の resolver の `Experimental` フィールドを設定してください（[experimental](#experimental) を参照）。

* **Q: 受領が `issuer_metadata_fetch_failed` で失敗する。**
  * **A:** `curl http://localhost:8080/.well-known/openid-credential-issuer` を実行して JSON メタデータが返ること、その `credential_issuer` が Offer の識別子と一致することを確認してください。識別子がパスを持つとき、1.0 の発行は `/.well-known/openid-credential-issuer/<パス>` を、Draft 13 の発行は `<パス>/.well-known/openid-credential-issuer` を読み、ほかの位置は試しません。

* **Q: Pre-Authorized Code の発行が `client_authentication_unavailable` で失敗する。**
  * **A:** token request に使えるクライアント認証が見つかりません。理由はエラーメッセージに出ます。認可サーバーのメタデータが匿名アクセスを宣言せずに `token_endpoint_auth_methods_supported` を省略しているか、設定した方式（既定は `none`）を含んでいないか、`none` を含んでいても `pre-authorized_grant_anonymous_access_supported` を `true` にしておらず（既定値は `false`）、wallet に `client_id` がありません。サーバーが示す方式を `Config.ClientAuth` に設定するか、`Config.ClientAuth.ClientID` を設定するか、サーバー側で匿名アクセスを宣言してください。

* **Q: 発行が `credential_acceptance_policy_required` で失敗する。**
  * **A:** `Config.CredentialAcceptance` か、発行を始める `IssuanceRequest` または `PreAuthorizedIssuanceRequest` の `Acceptance` を設定してください。JSON から読み戻した状態は、`AcceptanceOverridden` が true なら `Acceptance` を設定し直す必要があります。ポリシーは Issuer を認証できる方式を許していなければなりません。`x5c` を持つ Credential には `IssuerX509`、JWT VC Issuer Metadata や DID Configuration で束縛された DID には `IssuerKeys`、OpenID Federation の Entity には `Federation` です。テスト用の Issuer も同じ方法で認証します（たとえばテスト用 CA を `IssuerX509` に入れます）。

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
