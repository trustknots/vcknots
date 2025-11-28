---
sidebar_position: 4
---

# Wallet機能のセットアップと使用方法

このチュートリアルは、VCKnotsのwallet ライブラリのセットアップ、主要機能のサンプル実装、および本番環境での利用に向けた重要な考慮事項について解説します。

## 1. 前提条件

このセクションでは、vcknots/wallet ライブラリのビルドと、チュートリアルサンプルの実行に必要なすべての技術的要件を概説します。

### 1-1. Go環境の要件

* **Goのバージョン:** vcknots/wallet ライブラリは、Go 1.24.5 を要求します。  
* **開発環境管理 (mise):** 
    - プロジェクトでは、開発環境の管理に mise ([https://mise.jdx.dev/](https://mise.jdx.dev/)) の使用を強く推奨しています。
    - 例えば、以下のような手順で `mise install` を実行すると、必要なGoバージョンが自動的にインストールされ、環境変数が設定されます。  

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
    - もしmise を使用しない場合、`go mod download` が失敗します。
    - これを回避するため、以下の環境変数を手動で設定する必要があります。

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 1-2. サンプル実行環境の要件 (Verifier/Issuerサーバー)

本ライブラリのWalletのチュートリアルのサンプルコード（特にCredentialの受領と提示）は、対話する相手（IssuerおよびVerifier）が存在することを前提としています。

* **Node.jsサーバー:** チュートリアルのサンプルコード は、`README.md` および `package.json` で参照されているNode.jsベースのサンプルサーバー（`vcknots/server`）が http://localhost:8080 で動作している必要があります。  

* **サーバーのセットアップ:** このサーバーは Hono フレームワーク と `@trustknots/vcknots` を使用し、`example.ts` に定義されたIssuerおよびVerifierのエンドポイント（例: `/issue/credentials`, `/verifiers/:verifier/callback`）を提供します。  

* **サーバーの起動手順:** 
    - このNode.jsサーバーのセットアップはオプションではなく、**必須**です。
    - `server_integration.go` 内の `receiveMockCredential` や `presentation` 関数は、localhost:8080 への暗黙的なHTTPリクエストをトリガーします。このサーバーが稼働していない場合、「3. サンプル実装」のコードは `connection refused` エラーで失敗します。

wallet のGoコードを実行する **前に**、必ず以下のコマンドを実行してサーバーを起動してください 

```bash
# walletディレクトリから、serverディレクトリへ移動
cd ../server
pnpm install
pnpm -F server start
```

## 2. 初期設定 

このセクションでは、ライブラリの依存関係をインストールし、wallet のコア機能を集約する Controller インスタンスを初期化する手順を説明します。

### 2-1. 依存関係のインストール

前提条件で GOPRIVATE を設定した後、プロジェクトのルート（wallet ディレクトリ）で以下のコマンドを実行し、`go.mod` にリストされている依存ライブラリ（`github.com/go-jose/go-jose/v4`, `go.etcd.io/bbolt`, `golang.org/x/crypto` など）をダウンロードします。


```bash
go mod download
```

### 2-2. Walletコントローラの初期化

- vcknots/wallet ライブラリは、モジュール性の高いディスパッチャベースのアーキテクチャを採用しています。
- コアロジック（`controller.go`）は、credstore (永続化), receiver (受領), presenter (提示), verifier (検証) といった特定のタスクを処理するインターフェースに依存しています。

- `server_integration.go` の `main` 関数は、Controller をインスタンス化するための標準的なレシピを提供します。
- これは、ライブラリがデフォルト設定 (`WithDefaultConfig()`) とプラグイン （`WithPlugin(presenter.Oid4vp,...)`）の組み合わせによる依存性注入（DI）パターンに大きく依存していることを示しています。

以下のコードは、`server_integration.go` に基づく Controller の標準的な初期化プロセスです。
チュートリアルのサンプルコードを実行するために、この controller インスタンスが必要になります。

```go
package main

import (
	"log"
	"net/url"
	
	// vcknots/wallet 内の各ディスパッチャパッケージ
	vcknots_wallet "github.com/trustknots/vcknots/wallet/pkg/controller"
	"github.com/trustknots/vcknots/wallet/pkg/credstore"
	"github.com/trustknots/vcknots/wallet/pkg/dispatcher/idprof"
	receiverTypes "github.com/trustknots/vcknots/wallet/pkg/dispatcher/receiver"
	"github.com/trustknots/vcknots/wallet/pkg/dispatcher/serializer"
	"github.com/trustknots/vcknots/wallet/pkg/dispatcher/verifier"
	"github.com/trustknots/vcknots/wallet/pkg/presenter"
	oid4vp "github.com/trustknots/vcknots/wallet/pkg/presenter/oid4vp" // OID4VPプラグイン
	"github.com/trustknots/vcknots/wallet/pkg/util"
	
	// 鍵生成と署名のための標準ライブラリ
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	// サンプル実装で使用するライブラリ
	"io"
	"net/http"
	"github.com/trustknots/vcknots/wallet/pkg/types"
)

// NewController は、すべてのディスパッチャを初期化し、
// 統合されたWalletコントローラを返します。
func NewController() *vcknots_wallet.Controller {
    logger := util.NewLogger()

    // 1. 各ディスパッチャをデフォルト設定で初期化
    credStoreDispatcher := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
    receiverDispatcher := receiverTypes.NewReceivingDispatcher(receiverTypes.WithDefaultConfig())
    serializationDispatcher := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
    verificationDispatcher := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
    idProfileDispatcher := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())

    // 2. OID4VPプラグインの初期化
    // (プレゼンテーションのロジックはプラグイン化されている)
    oid4vpPlugin, err := oid4vp.New(
        oid4vp.WithLogger(logger),
        oid4vp.WithVerificationDispatcher(verificationDispatcher),
    )
    if err!= nil {
        panic(err)
    }

    // 3. 提示ディスパッチャにOID4VPプラグインを登録
    presentationDispatcher := presenter.NewPresentationDispatcher(
        presenter.WithPlugin(presenter.Oid4vp, oid4vpPlugin),
    )

    // 4. すべてのディスパッチャをコントローラ設定に集約
    config := vcknots_wallet.ControllerConfig{
        CredStore:  credStoreDispatcher,
        IdProf:     idProfileDispatcher,
        Receiver:   receiverDispatcher,
        Serializer: serializationDispatcher,
        Verifier:   verificationDispatcher,
        Presenter:  presentationDispatcher,
        Logger:     logger,
    }

    // 5. コントローラのインスタンス化
    return vcknots_wallet.NewController(config)
}

var (
    // このコントローラをチュートリアルの後半で使用します
    controller = NewController()
)
```

## 3. Wallet機能のサンプル実装

Controller インスタンスを使用して、Walletの主要な機能（鍵の準備、Credentialの受領、Credentialの提示）を実行する具体的なGoコードサンプルを示します。
これらのサンプルは `server_integration.go` のロジックに基づいています。

### 3-1. テスト用の鍵の準備 (IKeyEntryインターフェース)

`controller.go` の主要なメソッド（`ReceiveCredential`, `PresentCredential`）は、署名操作のために `IKeyEntry`インターフェースを要求します。
これにより、ライブラリ利用者は鍵管理の実装（例: メモリ、HSM、セキュアエンクレーブ）を自由に差し替えることができます。

`IKeyEntry` インターフェースは以下のように定義されています:

```go
// IKeyEntry は、鍵とその操作をカプセル化するインターフェースです。
type IKeyEntry interface {
    ID() string
    PublicKey() jose.JSONWebKey
    Sign(databyte) (byte, error)
}
```

チュートリアル用に、`server_integration.go` で提供されているインメモリのモック実装（`MockKeyEntry`）を使用します。

この `MockKeyEntry` の `Sign` メソッド は、単なる `ecdsa.Sign` のラッパーではありません。
これは、OID4VPで一般的に要求される ES256 署名（SHA-256ハッシュ）と、その結果をIEEE P1363形式（r と s を連結した64バイトのバイト列）にシリアライズするロジックを含んでいます。


```go
// MockKeyEntry は IKeyEntry のテスト用実装です
type MockKeyEntry struct {
    id         string
    privateKey *ecdsa.PrivateKey
}

func (m *MockKeyEntry) ID() string { return m.id }

func (m *MockKeyEntry) PublicKey() jose.JSONWebKey {
    return jose.JSONWebKey{
        Key:       m.privateKey.PublicKey,
        Algorithm: "ES256", // P-256曲線
        Use:       "sig",
    }
}

// Sign は SHA-256 ハッシュ -> ECDSA署名 -> IEEE P1363 形式への変換 を行います
func (m *MockKeyEntry) Sign(payloadbyte) (byte, error) {
    hash := sha256.Sum256(payload)
    r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
    if err!= nil {
        return nil, err
    }

    // P-256 (256 bits / 8 = 32 bytes)
    const keySize = 32
    // r と s を 64-byte (IEEE P1363) 形式にシリアライズ
    signature := make(byte, 2*keySize)
    r.FillBytes(signature)
    s.FillBytes(signature)
    return signature, nil
}

// NewMockKeyEntry は新しいテスト鍵を生成します
func NewMockKeyEntry() (*MockKeyEntry, error) {
    // P-256曲線で新しい鍵を生成します
    privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err!= nil {
        return nil, err
    }
    
    return &MockKeyEntry{
        id:         "test-key-id-" + uuid.NewString(), // 実行ごとに一意のID
        privateKey: privKey,
    }, nil
}

// チュートリアルの後半で使用する鍵を準備します
var testKey, _ = NewMockKeyEntry()
```

### 3-2. Credentialの受領

- この機能は、Issuer (Node.jsサーバー) からの `CredentialOffer` に基づき、Controller の `ReceiveCredential` メソッドを呼び出します。
- `ReceiveCredential` メソッド は、`ReceiveCredentialRequest` 構造体を引数に取ります。
- `server_integration.go` の `receiveMockCredential` 関数を参考に、Mock タイプのCredential（テスト用Issuerから発行される）を受領するプロセスを示します。


```go
func receiveTestCredential(key *MockKeyEntry) (*vcknots_wallet.SavedCredential, error) {
    // 1. Credential Offer をシミュレート (Mock)
    // 実際のオファーURLは QRコードやディープリンクから取得されます
    issuerURL, _ := url.Parse("http://localhost:8080/issuers/test_issuer/configurations/test_config")

    offer := &vcknots_wallet.CredentialOffer{
        CredentialIssuer:         issuerURL,
        CredentialConfigurationIDs:string{"UniversityDegree_jwt_vc_json-ld"}, // サーバー側 と一致
        Grants: map[string]*vcknots_wallet.CredentialOfferGrant{
            "pre-authorized_code": {
                PreAuthorizedCode: "test_code", // モック用の固定コード
            },
        },
    }

    // 2. 受領リクエストを作成
    receiveReq := vcknots_wallet.ReceiveCredentialRequest{
        CredentialOffer:    offer,
        Type:               receiverTypes.Mock, // サーバー側と通信しないモックタイプ
        Key:                key,                // 署名に使用する鍵 (PoPなど)
        CachedIssuerMetadata: nil,              // メタデータがない場合は nil を指定
    }

    // 3. Controller の ReceiveCredential を呼び出す
    log.Println("Attempting to receive credential...")
    savedCred, err := controller.ReceiveCredential(receiveReq)
    if err!= nil {
        log.Printf("Error receiving credential: %v\n", err)
        return nil, err
    }

    log.Printf("Successfully received and saved credential. ID: %s\n", savedCred.Entry.ID)
    return savedCred, nil
}
```

### 3-3. Credentialの提示 (OID4VP)

- Verifier (Node.jsサーバー) から `openid4vp://authorize?...` 形式のリクエストURIを受け取った後、Controller の `PresentCredential` メソッドを呼び出します。
- このメソッド は、`uriString`（OID4VPリクエスト）をパースし、リクエスト内容（`presentation_definition`）を解析し、`credstore` から適合するCredentialを検索し、`IKeyEntry` を使ってVerifiable Presentation (VP) に署名し、Verifierの`callback` エンドポイント に`HTTP POST`します。
- `server_integration.go` の `presentation` 関数に基づき、Node.jsサーバー（`/verifiers/test_verifier/request` エンドポイント）から取得したリクエストURIを処理します。


```go
func presentTestCredential(key *MockKeyEntry) error {
    // 1. Verifier (Node.js サーバー) から OID4VP リクエストURIを取得
    // このURIは通常、QRコードのスキャンによって取得されます
    // ここでは の /verifiers/test_verifier/request を直接呼び出します
    resp, err := http.Get("http://localhost:8080/verifiers/test_verifier/request")
    if err!= nil {
        log.Printf("Failed to get OID4VP request URI from server: %v\n", err)
        return err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err!= nil {
        return err
    }

    oid4vpRequestURI := string(body)
    log.Printf("Received OID4VP Request URI: %s\n", oid4vpRequestURI)

    // 2. Controller の PresentCredential を呼び出す
    // 内部でパース、検索、署名、HTTP POST が実行されます
    log.Println("Attempting to present credential...")
    err = controller.PresentCredential(oid4vpRequestURI, key)
    if err!= nil {
        log.Printf("Error presenting credential: %v\n", err)
        return err
    }

    log.Println("Successfully presented credential to the verifier.")
    return nil
}
```

### 3-4. 保存されたCredentialの参照

- `ReceiveCredential` で保存されたCredentialは、Controller の `GetCredentialEntries` メソッドで検索・一覧取得できます。
- このリクエスト により、ページネーション（`Offset`, `Limit`）や、`Filter` 関数による高度な絞り込みが可能です。


```go
func listSavedCredentials() (*vcknots_wallet.SavedCredential, error) {
    limit := 10
    getEntriesReq := vcknots_wallet.GetCredentialEntriesRequest{
        Offset: 0,
        Limit:  &limit,
        Filter: func(sc *vcknots_wallet.SavedCredential) bool {
            // (例: 'UniversityDegree' のみフィルタリング)
            // return sc.Credential.HasType("UniversityDegree")
            return true // この例ではすべて取得
        },
    }

    log.Println("Fetching saved credential entries...")
    entries, total, err := controller.GetCredentialEntries(getEntriesReq)
    if err!= nil {
        log.Printf("Error getting credential entries: %v\n", err)
        return nil, err
    }

    log.Printf("Found %d matching entries (Total: %d)\n", len(entries), total)
    for _, entry := range entries {
        log.Printf(" - Entry ID: %s, Credential Type: %v\n", entry.Entry.ID, entry.Credential.Types)
    }
    return entries, nil
}
```

## 4. Walletメタデータの登録

- このセクションは、Walletが **自身の** メタデータを登録する機能ではなく、Walletが対話する **Issuer** のメタデータを **取得・処理** する機能について説明します。

- Credentialを受領する際、WalletはまずIssuerの `.well-known/openid-credential-issuer` エンドポイント にアクセスし、そのIssuerの設定（公開鍵、サポートするCredentialタイプ、エンドポイントなど）を取得する必要があります。

- Controller は、このタスク専用の `FetchCredentialIssuerMetadata` メソッドを提供します。
- これは `ReceiveCredential` の内部フローで暗黙的に呼び出されるか、`ReceiveCredentialRequest` の `CachedIssuerMetadata` フィールド に設定するために事前に明示的に呼び出すことができます。

- `ReceiveCredential` を呼び出す際に `CachedIssuerMetadata` を提供することで、`ReceiveCredential` が実行されるたびにメタデータを再フェッチするネットワークオーバーヘッドを回避できます。


```go
func fetchIssuerMetadata() (*receiverTypes.CredentialIssuerMetadata, error) {
    // 注意: このURLはIssuerのベースURLであり、/.well-known/... パス自体を含みません
    // FetchCredentialIssuerMetadata が内部でパスを解決します
    issuerURL, _ := url.Parse("http://localhost:8080") // IssuerのベースURL

    log.Println("Fetching issuer metadata from:", issuerURL.String())
    
    // で定義されたメソッドを呼び出す
    metadata, err := controller.FetchCredentialIssuerMetadata(
        issuerURL,
        receiverTypes.OpenID4VCI, // プロトコルタイプを指定
    )

    if err!= nil {
        log.Printf("Failed to fetch issuer metadata: %v\n", err)
        return nil, err
    }

    log.Printf("Successfully fetched metadata for issuer: %s\n", metadata.CredentialIssuer)
    // metadata.CredentialEndpoint, metadata.JWKS...
    return metadata, nil
}
```

## 5. 型定義の説明

vcknots/wallet ライブラリの Controller とのインタラクションに使用される主要なGoの型定義について説明します。

| 型 / インターフェース | 説明 |
| :---- | :---- |
| **IKeyEntry** | 鍵管理のコア・インターフェース。`ID()`, `PublicKey()`, `Sign()` の3つのメソッドを定義します。ライブラリ利用者は、HSMやセキュアエンクレーブと連携するためにこれを実装する必要があります。 |
| **DIDCreateOptions** | `GenerateDID` メソッドに渡すオプション。生成するDIDのタイプ (`TypeID`) と、関連付ける公開鍵 (`PublicKey`) を指定します。 |
| **ReceiveCredentialRequest** | `ReceiveCredential` メソッドの主要な入力。`CredentialOffer`、署名に使用する Key (`IKeyEntry`)、およびオプションの `CachedIssuerMetadata` をカプセル化します。 |
| **CredentialOffer** | Issuerから受け取るオファーの詳細。IssuerのURL (`CredentialIssuer`)、要求するCredentialのID (`CredentialConfigurationIDs`)、および認可グラント (`Grants`) を含みます。 |
| **SavedCredential** | `credstore` に保存されたCredentialの実体。`\*credential.Credential`（VCの生データ）と `\*types.CredentialEntry`（メタデータ）をラップします。`GetCredentialEntries` の戻り値です。 |
| **GetCredentialEntriesRequest** | `GetCredentialEntries` メソッドでの検索条件。ページネーション (`Offset`, `Limit`) と、動的なGo関数によるフィルタリング (`Filter`) をサポートします。 |

## 6. 注意事項

1. **MockKeyEntry は本番環境で使用禁止 (CRITICAL):**  
    - `server_integration.go` で提供されている `MockKeyEntry` は、テストとデモンストレーションのみを目的としています。
    - **理由:** これは秘密鍵（`*ecdsa.PrivateKey`）をGoのヒープメモリ上に平文で保持します。
    - **本番実装:** 本番環境では、`IKeyEntry` インターフェースを独自に実装する必要があります。この実装は、`Sign` オペレーションをOSのキーストア（`iOS Secure Enclave`, `Android Keystore`）やHSM（`Hardware Security Module`）に委譲し、秘密鍵自体がアプリケーションのメモリ空間にロードされないように（`Non-exportable`）設計する必要があります。  

2. **GOPRIVATE の設定:**  
    - `go mod download` または `go build` が失敗する場合、GOPRIVATE 環境変数の設定 が欠落している可能性が最も高いです。 

3. **署名フォーマットの互換性:**  
    - 独自の `IKeyEntry` を実装する場合、`Sign` メソッド が生成する署名フォーマットに注意してください。
    - `MockKeygit Entry` は、ES256（SHA-256 with P-256）署名を **IEEE P1363** 形式（64バイト固定長）でシリアライズします。
    - Verifier が異なる形式（例: ASN.1 DER）を期待している場合、`PresentCredential` は署名検証エラーで失敗します。  

4. **永続化ストレージ (bbolt):**  
    - `credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())` は、デフォルトで `go.etcd.io/bbolt` （組み込みKVS）を `wallet.db` のようなローカルファイルに永続化しようと試みます。
    - 実行ディレクトリに書き込み権限があることを確認してください。

## 7. トラブルシューティング

* **Q: `go mod download` が `package... is private` または `404 Not Found` で失敗する。**  
  * **A:** GOPRIVATE 環境変数が正しく設定されていません。「1. 前提条件」 に戻り、`export GOPRIVATE="github.com/trustknots/vcknots/wallet"` が実行されていることを確認してください。  

* **Q: `ReceiveCredential` または `PresentCredential` が `connection refused` または `timeout` で失敗する。**  
  * **A:** vcknots/wallet のGoコードが通信しようとしているIssuer/Verifierサーバーが起動していません。「1. 前提条件」 に従い、`packages/server` ディレクトリで `pnpm start` を実行し、http://localhost:8080 が応答することを確認してください。  

* **Q: `PresentCredential` は成功するが、Verifier側（Node.jsサーバーのログ）で `Invalid signature` や `Presentation verification failed` と表示される。**  
  * **A:** これは、Walletが使用した `IKeyEntry` と Verifier の間で署名アルゴリズムまたはフォーマットの不一致があることを示します。  
    1. `MockKeyEntry` を使用しているか確認してください。  
    2. 独自の `IKeyEntry` を使用している場合、`Sign` メソッドが `MockKeyEntry` と同様に、SHA-256ハッシュとIEEE P1363シリアライゼーションを使用しているか確認してください。  

* **Q: `controller.ReceiveCredential` が `issuer metadata not found` で失敗する。**  
  * **A:** Node.jsサーバー は起動しているかもしれませんが、`/.well-known/openid-credential-issuer` エンドポイントが正しく機能していない可能性があります。`curl http://localhost:8080/.well-known/openid-credential-issuer` （または「4. Walletメタデータの登録」で指定されたIssuerのベースURL）を実行して、JSONメタデータが返されることを確認してください。