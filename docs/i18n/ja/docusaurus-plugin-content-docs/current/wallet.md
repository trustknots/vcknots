---
sidebar_position: 5
---

# Wallet機能のセットアップと使用方法

このチュートリアルは、VCKnots の wallet ライブラリ（Go ライブラリ）のセットアップ、Credential の受領と提示のサンプル実装、本番環境での利用に向けた考慮事項を説明します。

wallet は OpenID for Verifiable Credentials の各仕様を実装しています。

* **Credential の受領（OID4VCI）:** Credential Offer と pre-authorized code フローを使って、Issuer から Credential を受け取ります。
* **Credential の提示（OID4VP）:** `openid4vp://` 形式の Authorization Request に応答し、Verifiable Presentation を Verifier に送信します。

受領と提示のどちらも **JWT-VC**（`application/vc+jwt`）と **SD-JWT VC**（`application/dc+sd-jwt`）に対応しています。
SD-JWT VC では選択的開示と Key Binding JWT も利用できます。

## 1. 前提条件

* **対応している仕様:**
    - 受領: [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)（Pre-Authorized Code フロー）
    - 提示: [OpenID for Verifiable Presentations - draft 24](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html)（クロスデバイスフロー、`response_mode=direct_post`）
    - 各機能の実装範囲の詳細は [VC Knots Coverage](./support-matrix.md) を参照してください。

### 1-1. Go環境の要件

* **Goのバージョン:** vcknots/wallet ライブラリは、`wallet/mise.toml` に固定されたバージョンの Go（現在は Go 1.26.5）を要求します。
* **開発環境管理 (mise):**
    - 開発環境の管理には [mise](https://mise.jdx.dev/) の使用を推奨します。
    - `wallet` ディレクトリで `mise install` を実行すると、必要な Go バージョンがインストールされ、環境変数も設定されます。

```bash
# macOS
brew install mise

# curl経由でのインストール
curl https://mise.jdx.dev/install.sh | sh

# (vcknotsリポジトリのルートから)
cd wallet
mise install
```

* **GOPRIVATE 環境変数:**
    - mise を使用しない場合は、以下の環境変数を手動で設定してください。設定しないと `go mod download` が失敗します。

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 1-2. サンプル実行環境の要件 (Issuer/Verifierサーバー)

このチュートリアルのサンプルコード（Credential の受領と提示）は、対話する相手（Issuer と Verifier）が存在することを前提としています。
このリポジトリの Node.js ベースのサンプルサーバー（`server/`）が両方の役割を提供します。

wallet のサンプルコードを実行する前に、サーバーを起動してください。

```bash
# vcknotsリポジトリのルートから
pnpm install

# issuer+verifierモジュール、server-coreモジュール、serverモジュールをbuild
pnpm -F @trustknots/vcknots build
pnpm -F @trustknots/server-core build
pnpm -F @trustknots/server build

# サーバーを起動（http://localhost:8080 で待ち受け）
pnpm -F @trustknots/server start
```

サーバーは、このチュートリアルで使用する以下のエンドポイントを提供します。

* `POST /configurations/:configurationId/offer`：Credential Offer の作成
* `POST /token`, `POST /nonce`, `POST /credentials`：OID4VCI の token エンドポイント、nonce エンドポイント、credential エンドポイント
* `POST /request`, `POST /request-object`：OID4VP の Authorization Request の作成
* `POST /callback`：Verifier の応答受け取りエンドポイント
* `GET /.well-known/openid-credential-issuer`, `GET /.well-known/oauth-authorization-server`：メタデータエンドポイント

* **ローカルテストでの HTTP 許可:** wallet はデフォルトで、Issuer と Verifier のエンドポイントに HTTPS を要求します。
ローカルのサンプルサーバーは HTTP で動作するため、ローカルテスト時は明示的に HTTP を許可してください。

```bash
export VCKNOTS_WALLET_HTTP_ALLOWED=true
```

テストコードから `env.SetHTTPAllowed(true)`（パッケージ `github.com/trustknots/vcknots/wallet/env`）を呼び出す方法もあります。

> ⚠️ **セキュリティ警告**: 本番環境では `VCKNOTS_WALLET_HTTP_ALLOWED` を有効化しないでください。HTTPS 必須の検証を維持してください。

## 2. 初期設定

このセクションでは、ライブラリの依存関係をインストールし、wallet のコア機能を集約する `Wallet` インスタンスを初期化する手順を説明します。

### 2-1. 依存関係のインストール

GOPRIVATE を設定した後、`wallet` ディレクトリで以下のコマンドを実行し、`go.mod` にリストされている依存ライブラリ（`github.com/go-jose/go-jose/v4`, `go.etcd.io/bbolt`, `golang.org/x/crypto` など）をダウンロードします。

```bash
go mod download
```

### 2-2. Walletの初期化

ライブラリのトップレベル API は `github.com/trustknots/vcknots/wallet` パッケージにあります。
最も簡単な初期化は `wallet.NewWallet()` で、すべてのディスパッチャコンポーネントをデフォルトのプラグイン実装で初期化します。

```go
import (
    "log"

    "github.com/trustknots/vcknots/wallet"
)

w, err := wallet.NewWallet()
if err != nil {
    log.Fatal(err)
}
```

`Wallet` は内部で 6 つのディスパッチャコンポーネントを協調させます。
それぞれが wallet 機能の一つの側面を担当します。

* `credstore.CredStoreDispatcher`：Credential の永続化（デフォルトは bbolt を使うローカルストレージ）
* `receiver.ReceivingDispatcher`：Credential 発行プロトコル（OID4VCI）
* `presenter.PresentationDispatcher`：Credential 提示プロトコル（OID4VP）
* `serializer.SerializationDispatcher`：Credential のシリアライズ（JWT-VC, SD-JWT VC）
* `verifier.VerificationDispatcher`：署名の暗号学的検証
* `idprof.IdentityProfileDispatcher`：DID とアイデンティティプロファイル（`did:key`）

カスタム設定が必要な場合（たとえば OID4VP の Request Object 検証に使うトラストルートを設定する場合）は、ディスパッチャを自分で構築して `wallet.NewWalletWithConfig` に渡します。
各ディスパッチャのコンストラクタはエラーを返します。
`wallet.Config` で `nil` のままにしたフィールドには、デフォルト実装が自動的に補われます。
以下のコードは、`wallet/examples/` 配下のサンプルで使われている初期化です。

```go
package main

import (
    "crypto/x509"
    "fmt"
    "os"

    "github.com/trustknots/vcknots/wallet"
    "github.com/trustknots/vcknots/wallet/credstore"
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

    // OID4VP Request Objectのx5c証明書チェーン検証に使うトラストルート
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

* **保存先:** デフォルトの Credential ストアは、`go.etcd.io/bbolt` を使って `<ユーザー設定ディレクトリ>/vcknots/wallet/.local_credstore.db` に永続化します（Linux では `~/.config/vcknots/wallet/.local_credstore.db`、macOS では `~/Library/Application Support/vcknots/wallet/.local_credstore.db` など）。

## 3. Wallet機能のサンプル実装

`Wallet` インスタンスを使用して、wallet の主要な機能（鍵の準備、Credential の受領、Credential の提示）を実行する具体的な Go コードサンプルを示します。
これらのサンプルは `wallet/examples/server_integration_sdjwt/server_integration_sdjwt.go` と `wallet/examples/common/common.go` に基づいています。

### 3-1. テスト用の鍵の準備 (IKeyEntryインターフェース)

主要なワークフローメソッド（`ReceiveCredential`, `PresentCredential`）は、署名操作のために `IKeyEntry` インターフェースを要求します。
これにより、ライブラリ利用者は鍵管理の実装（例: メモリ、HSM、セキュアエンクレーブ）を差し替えることができます。

`IKeyEntry` インターフェースは以下のように定義されています。

```go
// IKeyEntry は、署名操作のための鍵エントリを表すインターフェースです。
type IKeyEntry interface {
    ID() string
    PublicKey() jose.JSONWebKey
    Sign(data []byte) ([]byte, error)
}
```

* **署名フォーマット:** ECDSA 実装の `Sign` は、DER エンコードされた ASN.1 署名と、生の IEEE P1363（`R || S`）署名のどちらを返しても構いません。
ライブラリが内部で（`JWKSigner` により）DER 署名を IEEE P1363 に正規化するため、両方の形式が動作します。

チュートリアル用に、`wallet/examples/common/common.go` の `MockKeyEntry` と同等のインメモリ実装を使用します。

```go
// MockKeyEntry は IKeyEntry のテスト用実装です。
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
        Algorithm: "ES256", // P-256曲線
        Use:       "sig",
    }
}

// Sign は SHA-256 ハッシュ -> ECDSA署名 -> IEEE P1363 形式へのシリアライズ を行います。
func (m *MockKeyEntry) Sign(payload []byte) ([]byte, error) {
    hash := sha256.Sum256(payload)
    r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
    if err != nil {
        return nil, err
    }

    const keySize = 32 // P-256: 256 bits / 8
    signature := make([]byte, 2*keySize)
    r.FillBytes(signature[:keySize])
    s.FillBytes(signature[keySize:])
    return signature, nil
}
```

### 3-2. Credentialの受領 (OID4VCI)

wallet は、Issuer から取得した `CredentialOffer` を `ReceiveCredential` に渡して Credential を受領します。
実際の運用では offer URI は QR コードやディープリンクから取得します。
ローカルのサンプルサーバーでは `POST /configurations/:configurationId/offer` で作成できます。

offer URI は `openid-credential-offer://?credential_offer=...` という形式です。
これを `wallet.CredentialOffer` にパースして `ReceiveCredential` に渡します。

```go
import (
    "encoding/json"
    "net/url"

    "github.com/trustknots/vcknots/wallet"
    "github.com/trustknots/vcknots/wallet/credential"
    "github.com/trustknots/vcknots/wallet/receiver"
)

func receiveSDJwtCredential(w *wallet.Wallet, key wallet.IKeyEntry, offerURI string) (*wallet.SavedCredential, error) {
    // 1. openid-credential-offer:// URIをパース
    parsed, err := url.Parse(offerURI)
    if err != nil {
        return nil, err
    }

    var offerJSON struct {
        CredentialIssuer           string                                  `json:"credential_issuer"`
        CredentialConfigurationIDs []string                                `json:"credential_configuration_ids"`
        Grants                     map[string]*wallet.CredentialOfferGrant `json:"grants"`
    }
    if err := json.Unmarshal([]byte(parsed.Query().Get("credential_offer")), &offerJSON); err != nil {
        return nil, err
    }

    issuerURL, err := url.Parse(offerJSON.CredentialIssuer)
    if err != nil {
        return nil, err
    }

    offer := &wallet.CredentialOffer{
        CredentialIssuer:           issuerURL,
        CredentialConfigurationIDs: offerJSON.CredentialConfigurationIDs,
        Grants:                     offerJSON.Grants, // キー: "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }

    // 2. OID4VCI (pre-authorized codeフロー) でCredentialを受領
    return w.ReceiveCredential(wallet.ReceiveCredentialRequest{
        CredentialOffer: offer,
        Type:            receiver.Oid4vci,
        Key:             key,                 // JWT proof (key binding) の署名に使用
        RequestedFormat: credential.SDJwtVC,  // "application/dc+sd-jwt"
    })
}
```

`ReceiveCredentialRequest` の補足:

* **RequestedFormat:** SD-JWT VC を受領する場合は `credential.SDJwtVC`、JWT-VC を受領する場合は `credential.JwtVc` を指定します。
省略した場合は、先頭の credential configuration ID について Issuer メタデータからフォーマットを解決します（解決できない場合は JWT-VC にフォールバックします）。
* **TxCode:** offer が transaction code を要求する場合は `TxCode` を設定します。token エンドポイントに `tx_code` として送信されます。
* **CachedIssuerMetadata:** 設定すると、`ReceiveCredential` は Issuer メタデータの取得をスキップします（セクション 4 を参照）。

`ReceiveCredential` は、Issuer と Authorization Server のメタデータを取得し、pre-authorized code でアクセストークンを取得し、`Key` で署名した JWT proof を生成して Credential を要求し、結果を Credential ストアに保存します。
戻り値の `*wallet.SavedCredential` には、パース済みの Credential とストレージエントリの両方が含まれます。

### 3-3. Credentialの提示 (OpenID4VP)

Verifier から `openid4vp://authorize?...` 形式のリクエスト URI を受け取ったら（通常は QR コードのスキャンで取得します。ローカルのサンプルサーバーでは `POST /request` または `POST /request-object` で作成できます）、`PresentCredential` を呼び出します。

```go
import (
    "log"

    sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

func presentCredential(w *wallet.Wallet, key wallet.IKeyEntry, oid4vpURI string) error {
    // SD-JWT VC提示のオプション: 選択的開示とKey Binding JWT
    options := &sdjwtvc.SdJwtVcPresentationOptions{
        SelectedClaims:    []string{"given_name", "family_name"},
        RequireKeyBinding: true,
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

`PresentCredential` は、OID4VP リクエストをパースし（`request_uri` で参照される JAR Request Object も含み、その署名は `X509TrustChainRoots` に対して検証されます）、保存済みの Credential のうち最も新しく受領した 1 件を選択し（presentation definition との照合は現時点では行いません）、`key` で Verifiable Presentation をシリアライズして署名し、Verifier の `response_uri`（`response_mode=direct_post`）に POST します。
Wallet が `redirect_uri` に送信することはありません。
Verifier の応答に `redirect_uri` が含まれる場合、その値が戻り値として呼び出し側に返されます（含まれない場合は空文字列です）。

* **提示オプション:** 第 3 引数にはフォーマット固有のオプションを渡します。
SD-JWT VC では `sdjwtvc.SdJwtVcPresentationOptions` により、開示するクレーム（`SelectedClaims`）と Key Binding JWT の付与（`RequireKeyBinding`）を制御します。
KB-JWT の audience と nonce は OID4VP リクエスト（`client_id` と `nonce`）から自動的に設定されます。リクエストに transaction data が含まれる場合の `transaction_data` ハッシュも同様です。
`nil` を渡すと、その Credential のフォーマットに応じたデフォルトのオプションが使われます（JWT-VC の提示では `nil` が典型的です）。
* **リダイレクト処理:** Verifier のリダイレクト URI をコールバックで受け取りたい場合は、`PresentCredentialWithOptions` に `&wallet.PresentCredentialOptions{OnRedirect: func(uri string) error {...}}` を渡します。

### 3-4. 保存されたCredentialの参照

`ReceiveCredential` で保存された Credential は、`GetCredentialEntries` で一覧取得できます。
ページネーション（`Offset`, `Limit`）と Go 関数によるフィルタリング（`Filter`）をサポートします。
ID を指定して 1 件だけ取得する場合は `GetCredentialEntry` を使います。

```go
func listSavedCredentials(w *wallet.Wallet) ([]*wallet.SavedCredential, error) {
    limit := 10
    entries, total, err := w.GetCredentialEntries(wallet.GetCredentialEntriesRequest{
        Offset: 0,
        Limit:  &limit,
        Filter: func(sc *wallet.SavedCredential) bool {
            return true // 例: return sc.Entry.MimeType == string(credential.SDJwtVC)
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

Credential を受領する際、wallet は Issuer の `.well-known/openid-credential-issuer` エンドポイントにアクセスし、Issuer の設定（credential エンドポイント、サポートする credential configuration など）を取得する必要があります。

`ReceiveCredential` はこのメタデータを内部で取得しますが、`FetchCredentialIssuerMetadata` で明示的に取得し、`ReceiveCredentialRequest` の `CachedIssuerMetadata` フィールドに渡すこともできます。
これにより、`ReceiveCredential` を呼び出すたびにメタデータを再取得するオーバーヘッドを回避できます。

```go
import (
    "log"
    "net/url"

    receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func fetchIssuerMetadata(w *wallet.Wallet) (*receiverTypes.CredentialIssuerMetadata, error) {
    // 注意: IssuerのベースURLを渡します。/.well-known/... パスは内部で解決されます
    issuerURL, _ := url.Parse("http://localhost:8080")

    metadata, err := w.FetchCredentialIssuerMetadata(issuerURL, receiverTypes.Oid4vci)
    if err != nil {
        return nil, err
    }

    log.Printf("Fetched metadata for issuer: %s\n", metadata.CredentialIssuer)
    // metadata.CredentialEndpoint, metadata.CredentialConfigurationSupported, ...
    return metadata, nil
}
```

## 5. 型定義の説明

vcknots/wallet ライブラリの `Wallet` とのインタラクションに使用される主要な Go の型定義について説明します。

### IKeyEntry {#IKeyEntry}

鍵管理のコアインターフェース。`ID()`, `PublicKey()`, `Sign()` の 3 つのメソッドを定義します。ライブラリ利用者は、HSM やセキュアエンクレーブと連携するためにこれを実装します。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### Config {#Config}

`NewWalletWithConfig` の入力。6 つのディスパッチャコンポーネントと、オプションの DPoP 設定（[DPoPConfig](#DPoPConfig)）を保持します。`nil` のフィールドにはデフォルト実装が補われます。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### ReceiveCredentialRequest {#ReceiveCredentialRequest}

`ReceiveCredential` の主要な入力。[CredentialOffer](#CredentialOffer)、受領プロトコル（`Type`）、proof の署名に使用する鍵（[IKeyEntry](#IKeyEntry)）、要求する Credential フォーマット（`RequestedFormat`）、オプションの `CachedIssuerMetadata` と `TxCode` をカプセル化します。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### CredentialOffer {#CredentialOffer}

Issuer から受け取るオファーの詳細。Issuer の URL（`CredentialIssuer`）、credential configuration ID（`CredentialConfigurationIDs`）、認可グラント（`Grants`）を含みます。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### SavedCredential {#SavedCredential}

Credential ストアに保存された Credential。`*credential.Credential`（パース済みの Credential）と `*types.CredentialEntry`（ストレージメタデータ: ID、生データ、MIME タイプ、受領時刻）をラップします。`ReceiveCredential`, `GetCredentialEntries`, `GetCredentialEntry` の戻り値です。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### GetCredentialEntriesRequest {#GetCredentialEntriesRequest}

`GetCredentialEntries` の検索条件。ページネーション（`Offset`, `Limit`）と、Go 関数による動的なフィルタリング（`Filter`）をサポートします。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### PresentCredentialOptions {#PresentCredentialOptions}

`PresentCredentialWithOptions` の入力。フォーマット固有の `SerializeOptions` と、オプションの `OnRedirect` コールバックを保持します。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### SdJwtVcPresentationOptions {#SdJwtVcPresentationOptions}

SD-JWT VC 提示のオプション: `SelectedClaims`, `RequireKeyBinding`, `Audience`, `Nonce`, `TransactionData`。audience と nonce は OID4VP リクエストから自動的に設定されます。

定義は [wallet/serializer/plugins/sdjwtvc/sdjwtvc.go](https://github.com/trustknots/vcknots/blob/main/wallet/serializer/plugins/sdjwtvc/sdjwtvc.go) を参照してください。

### DIDCreateOptions {#DIDCreateOptions}

`GenerateDID` のオプション。DID のタイプ（`TypeID`、例: `"did:key"`）と、関連付ける公開鍵（`PublicKey`）を指定します。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

### DPoPConfig {#DPoPConfig}

token エンドポイントと credential エンドポイントへの DPoP proof 付与を有効化します（`Enabled`）。専用の鍵（`Key`）も指定できます。有効化時に鍵を指定しない場合は、インメモリの P-256 鍵が生成されます。

定義は [wallet/wallet.go](https://github.com/trustknots/vcknots/blob/main/wallet/wallet.go) を参照してください。

## 6. Walletのメソッド

### ReceiveCredential

OID4VCI（Pre-Authorized Code フロー）で Issuer から Credential を受領し、Credential ストアに保存します。

```go
func (w *Wallet) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error)
```

**パラメータ**:
- `req`: 受領リクエスト（[ReceiveCredentialRequest](#ReceiveCredentialRequest)）

**戻り値**:
- 受領し保存された Credential（[SavedCredential](#SavedCredential)）

### PresentCredential

OID4VP の Authorization Request に応答し、Verifiable Presentation を Verifier に送信します。

```go
func (w *Wallet) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error)
```

**パラメータ**:
- `uriString`: OID4VP リクエスト URI（`openid4vp://authorize?...`）
- `key`: Presentation の署名に使用する鍵（[IKeyEntry](#IKeyEntry)）
- `options`: フォーマット固有の提示オプション（SD-JWT VC では [SdJwtVcPresentationOptions](#SdJwtVcPresentationOptions)）。`nil` を渡すと、その Credential のフォーマットのデフォルトが使われます

**戻り値**:
- Verifier が提示したリダイレクト URI（リダイレクトがない場合は空文字列）

### PresentCredentialWithOptions

`PresentCredential` と同じ動作に加えて、Verifier がリダイレクト URI を返した場合にコールバックを呼び出します。

```go
func (w *Wallet) PresentCredentialWithOptions(uriString string, key IKeyEntry, options *PresentCredentialOptions) (string, error)
```

**パラメータ**:
- `uriString`: OID4VP リクエスト URI（`openid4vp://authorize?...`）
- `key`: Presentation の署名に使用する鍵（[IKeyEntry](#IKeyEntry)）
- `options`: シリアライズオプションとリダイレクトコールバック（[PresentCredentialOptions](#PresentCredentialOptions)）

**戻り値**:
- Verifier が提示したリダイレクト URI（リダイレクトがない場合は空文字列）

### GetCredentialEntries

保存された Credential を、ページネーションとフィルタリング付きで取得します。

```go
func (w *Wallet) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error)
```

**パラメータ**:
- `req`: 検索条件（[GetCredentialEntriesRequest](#GetCredentialEntriesRequest)）

**戻り値**:
- 条件に一致した Credential（[SavedCredential](#SavedCredential)）と、一致件数の合計

### GetCredentialEntry

ID を指定して、保存された Credential を 1 件取得します。

```go
func (w *Wallet) GetCredentialEntry(id string) (*SavedCredential, error)
```

**パラメータ**:
- `id`: Credential エントリの ID

**戻り値**:
- 保存された Credential（[SavedCredential](#SavedCredential)）。デフォルトのローカルストアでは、ID が存在しない場合はエラーを返します

### FetchCredentialIssuerMetadata

Issuer の `.well-known/openid-credential-issuer` エンドポイントから Issuer メタデータを取得します。

```go
func (w *Wallet) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error)
```

**パラメータ**:
- `endpoint`: Issuer のベース URL（`/.well-known/...` パスは内部で解決されます）
- `receivingType`: 受領プロトコル（`receiver.Oid4vci`）

**戻り値**:
- Issuer メタデータ（`receiverTypes.CredentialIssuerMetadata`）

### GenerateDID

公開鍵から DID を生成します。

```go
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error)
```

**パラメータ**:
- `options`: DID のタイプと公開鍵（[DIDCreateOptions](#DIDCreateOptions)）

**戻り値**:
- 生成されたアイデンティティプロファイル（`idprofTypes.IdentityProfile`）

## 7. 注意事項

1. **モック鍵は本番環境で使用禁止 (CRITICAL):**
    - このチュートリアルで示したインメモリの鍵実装（および `wallet/examples/common/` の `MockKeyEntry`）は、秘密鍵を Go のヒープメモリ上に平文で保持するため、テストとデモンストレーションのみを目的としています。
    - 本番環境では、`Sign` オペレーションを OS のキーストア（iOS Secure Enclave, Android Keystore）や HSM に委譲し、秘密鍵自体がアプリケーションのメモリ空間にロードされない（non-exportable な）形で `IKeyEntry` を実装してください。

2. **GOPRIVATE の設定:**
    - `go mod download` または `go build` が失敗する場合、GOPRIVATE 環境変数の設定が欠落している可能性が最も高いです。

3. **署名フォーマットの互換性:**
    - `Sign` は ES256 について、DER エンコードされた ASN.1 署名と生の IEEE P1363 署名のどちらを返しても構いません。ライブラリが JWS 構造に埋め込む前に DER を P1363 に正規化します。

4. **永続化ストレージ (bbolt):**
    - `credstore.WithDefaultConfig()` は、`go.etcd.io/bbolt` を使って `<ユーザー設定ディレクトリ>/vcknots/wallet/.local_credstore.db` に Credential を永続化します。プロセスがこのディレクトリを作成し書き込めることを確認してください。

5. **HTTPS の強制と実行時の環境変数（`wallet/env/env.go`）:**
    - wallet はデフォルトで、Issuer と Verifier のエンドポイントに HTTPS を要求します。
    - `VCKNOTS_WALLET_HTTP_ALLOWED=true` を設定すると、HTTP エンドポイントを許可します（ローカル開発とテスト用途のみ）。
    - `VCKNOTS_WALLET_DEBUG=true` はデバッグモードを有効化し、同時に HTTP 許可動作も有効化します。
    - **本番運用の指針:** 本番環境では両方とも未設定（または `false`）のままにし、HTTPS 必須の検証を維持してください。

6. **OpenID4VP `client_id` の厳格な検証:**
    - この wallet は、OpenID4VP コンフォーマンステストに準拠するため、`client_id` を厳格に検証します。重複プレフィックス（例: `x509_san_dns:x509_san_dns:...`）や不正な形式は拒否されます。
    - `x509_san_dns:` スキームの場合、リクエスト JWT の `x5c` ヘッダーから証明書を抽出し、証明書の Subject Alternative Name (SAN) DNS フィールドと `client_id` の値を照合します。
    - 検証ロジックは `wallet/presenter/plugins/oid4vp/` を参照してください。

7. **証明書検証のテスト設定（`InsecureSkipX509Verify`）:**
    - `Oid4vpPresenter` 構造体は、テスト環境用に `InsecureSkipX509Verify` オプションを提供しています。
    - **デフォルト動作（本番環境）:** `X509TrustChainRoots` に対する完全な証明書チェーン検証を実行します。
    - **テスト設定（`InsecureSkipX509Verify: true`）:** 証明書チェーンの検証をスキップし、`x5c` ヘッダーから証明書を直接抽出します。SAN と `client_id` の照合のみを実行します。
    - ⚠️ **重大な警告**: `InsecureSkipX509Verify: true` は、コンフォーマンステストやローカル開発環境でのみ使用してください。本番環境では**絶対に**使用しないでください。

8. **DPoP サポート（オプション）:**
    - `wallet.Config{DPoP: wallet.DPoPConfig{Enabled: true}}` を設定すると、wallet は token リクエストと credential リクエストに DPoP proof を付与し、サーバーからの DPoP nonce チャレンジも処理します。

## 8. トラブルシューティング

* **Q: `go mod download` が `package ... is private` または `404 Not Found` で失敗する。**
  * **A:** GOPRIVATE 環境変数が設定されていません。「1. 前提条件」に戻り、`export GOPRIVATE="github.com/trustknots/vcknots/wallet"` が実行されていること（または mise を使用していること）を確認してください。

* **Q: `ReceiveCredential` または `PresentCredential` が `connection refused` または `timeout` で失敗する。**
  * **A:** Issuer/Verifier サーバーが起動していません。「1. 前提条件」に従い、`pnpm -F @trustknots/server start` でサーバーを起動し、http://localhost:8080 が応答することを確認してください。

* **Q: `ReceiveCredential` が `credential issuer must use https scheme` で失敗する。**
  * **A:** wallet はデフォルトで HTTPS を強制します。HTTP のサンプルサーバーに対してローカルテストする場合は、`VCKNOTS_WALLET_HTTP_ALLOWED=true` を設定してください（または `env.SetHTTPAllowed(true)` を呼び出してください）。

* **Q: `ReceiveCredential` が `failed to fetch issuer metadata` で失敗する。**
  * **A:** サーバーは起動していても、`/.well-known/openid-credential-issuer` エンドポイントが正しく機能していない可能性があります。`curl http://localhost:8080/.well-known/openid-credential-issuer` を実行して、JSON メタデータが返されることを確認してください。

* **Q: OpenID4VP コンフォーマンステストで `client_id` 検証エラーが発生する。**
  * **A:** コンフォーマンステストは、意図的に不正な `client_id`（重複プレフィックスなど）を送信して wallet の検証ロジックをテストします。`invalid client_id: duplicate prefix detected` や `SAN of the certificate and client_id did not match` のようなエラーは**期待される動作**であり、wallet が正しくセキュリティチェックを実施していることを示します。

* **Q: OpenID4VP コンフォーマンステストで `x509: certificate is not standards compliant` エラーが発生する。**
  * **A:** コンフォーマンステストサーバーは、自己署名証明書や非標準的な証明書を使用することがあります。テスト環境でのみ `InsecureSkipX509Verify: true` を設定してください。
    ```go
    p := &oid4vp.Oid4vpPresenter{
        X509TrustChainRoots:    systemRoots,
        InsecureSkipX509Verify: true, // テスト環境のみ
    }
    ```
  * ⚠️ **警告**: 本番環境では必ず `false`（または未設定）にしてください。

実行可能なエンドツーエンドのサンプル（JWT-VC、SD-JWT VC、KB-JWT 付き SD-JWT VC）は [wallet/examples/README.ja.md](https://github.com/trustknots/vcknots/blob/main/wallet/examples/README.ja.md) を参照してください。
