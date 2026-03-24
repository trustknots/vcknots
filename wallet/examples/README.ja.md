# vcknots-wallet サーバー統合・コンフォーマンステストサンプル

このディレクトリには、vcknots-walletの2つの主要なテストシナリオを実演するサンプルコードが含まれています：

1. **サーバー統合テスト**: ローカルのvcknotsサーバーとの統合をテスト
2. **コンフォーマンステスト**: 外部のOID4VPコンフォーマンステストサービスとの統合をテスト

どちらのモードも、同じプログラム（`server_integration_sdjwt.go`）でコマンドライン引数の有無により切り替わります。
両モードとも同一のフロー（クレデンシャルのシード → ウォレット構築 → OID4VPリクエストURI取得 → プレゼンテーション）に従います。

## 前提条件

### 1. mise のインストール

Walletのパッケージは開発環境管理に[mise](https://mise.jdx.dev/)を使用しています。
miseがインストールされていない場合はまずインストールしてください。

例えば:
```bash
# macOS
brew install mise

# curl経由でのインストール
curl https://mise.jdx.dev/install.sh | sh
```

### 2. 環境のセットアップ

プロジェクトディレクトリに移動して環境をセットアップします：

```bash
cd /path/to/vcknots/wallet
mise install
```

これにより、`mise.toml`に基づいてGo 1.24.5が自動的にインストールされ、必要な環境変数が設定されます。
miseを利用しない場合は、Go 1.24.5を手動でインストールし、`GOPRIVATE`環境変数を設定してください：

```bash
export GOPRIVATE="github.com/trustknots/vcknots/wallet"
```

### 3. 依存関係のインストール

Goモジュールの依存関係をインストールします：

```bash
go mod download
```

## サンプルの実行方法

このサンプルプログラムは2つのモードで動作します。

### モード1: サーバー統合テスト（推奨：初回実行）

ローカルのvcknotsサーバーとの統合をテストします。

#### ステップ1: Issuer、Verifierサーバーの起動

サンプルを実行するためには、verifierサーバーが動作している必要があります。サーバーディレクトリに移動してサーバーを起動します：

```bash
# walletディレクトリから、vcknotsルートディレクトリへ移動(/path/to/vcknots)
cd ../

# 依存関係をインストール（未実施の場合）
pnpm install

# issuer+verifierモジュールのbuild
pnpm -F @trustknots/vcknots build    

# サーバーモジュールのbuild
pnpm -F @trustknots/server build    

# サーバーを起動
pnpm -F @trustknots/server start
```

#### サーバー起動確認

サーバーを起動すると以下のメッセージが出力されます：

```
> @trustknots/server@0.1.0 start /path/to/vcknots/server/single
> tsx src/example.ts

POST  /configurations/:configuration/offer
        [handler]
POST  /credentials
        [handler]
GET   /.well-known/openid-credential-issuer
        [handler]
GET   /.well-known/jwt-vc-issuer
        [handler]
POST  /token
        [handler]
GET   /.well-known/oauth-authorization-server
        [handler]
POST  /request
        [handler]
POST  /callback
        [handler]
POST  /request-object
        [handler]
GET   /request.jwt/:request-object-Id
        [handler]
Server is running on http://localhost:8080
Verifier metadata initialized for http://localhost:8080
Issuer metadata initialized
Authz metadata initialized
```

サーバーはデフォルトで`http://localhost:8080`で起動します。
テスト用スクリプトも上記のURLを使用します。

#### ステップ2: 統合テスト用のスクリプト実行（引数なし）

新しいターミナルで、各テストディレクトリに移動してサーバー統合テスト用のスクリプトを実行します：

```bash
# JWT-VC 統合テスト
cd /path/to/vcknots/wallet/examples/server_integration_jwtvc
go run server_integration_jwtvc.go

# SD-JWT 統合テスト（kb-jwt なし）
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go

# SD-JWT 統合テスト（kb-jwt あり）
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt+kbjwt
go run server_integration_sdjwt_kbjwt.go
```



### ステップ3: 結果の確認

うまくいけば、以下のような出力が表示されます：

```
time=2025-11-27T14:03:25.066+09:00 level=INFO msg="Starting server integration check..."
time=2025-11-27T14:03:25.066+09:00 level=INFO msg="Fetching credential offer from server..."
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Received offer URL" url="openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%220d6386e621c740d1a02771312039efeb%22%7D%7D%7D"
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Decoded offer" offer="{\"credential_issuer\":\"http://localhost:8080\",\"credential_configuration_ids\":[\"UniversityDegreeCredential\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"0d6386e621c740d1a02771312039efeb\"}}}"
time=2025-11-27T14:03:25.077+09:00 level=INFO msg="Parsed credential offer" issuer=http://localhost:8080 configs=[UniversityDegreeCredential] grants=1
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Successfully imported demo credential via controller.ReceiveCredential" entry_id=0909df8b-cecb-4432-a047-a1a9c2dfc720 raw_length=808
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="=== Received Credential Details ==="
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential Entry ID" id=0909df8b-cecb-4432-a047-a1a9c2dfc720
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential MimeType" mime_type=application/vc+jwt
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential Received At" received_at=2025-11-27T14:03:25.143+09:00
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential Raw Content" raw=eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC92Yy83ZWE5MjI1YmMxZDM0ZmUxOWJkYmYwOWU4NjhkYjRmMSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJpc3N1YW5jZURhdGUiOiIyMDI1LTExLTI3VDA1OjAzOjI1LjE0MloiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSIsImdpdmVuX25hbWUiOiJ0ZXN0IiwiZmFtaWx5X25hbWUiOiJ0YXJvIiwiZGVncmVlIjoiNSIsImdwYSI6InRlc3QifX0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInN1YiI6ImRpZDprZXk6ekRuYWVZaXdITmVNWWFqMjFXbzlqUENvd3RuQnJZOGhlOFVDSzhaWk4xbWhoeDhQTSJ9.Qd1dNQbpoRvpfkWF8m2z-EVvo8dZ3IM4gtlN2JTvoqnh8TDoXegh0OBC6gO6FwpODxf7m_IO_PhR1WnhztHC2Q
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Stored credentials" count=2 total=2
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Verifier Details" URL=http://localhost:8080
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Using received credential for presentation" credential_id=0909df8b-cecb-4432-a047-a1a9c2dfc720
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Decoding received credential JWT"
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Decoded credential" credential="map[iss:http://localhost:8080 sub:did:key:zDnaeYiwHNeMYaj21Wo9jPCowtnBrY8he8UCK8ZZN1mhhx8PM vc:map[@context:[https://www.w3.org/2018/credentials/v1] credentialSubject:map[degree:5 family_name:taro given_name:test gpa:test id:did:key:zDnaeYiwHNeMYaj21Wo9jPCowtnBrY8he8UCK8ZZN1mhhx8PM] id:http://localhost:8080/vc/7ea9225bc1d34fe19bdbf09e868db4f1 issuanceDate:2025-11-27T05:03:25.142Z issuer:http://localhost:8080 type:[VerifiableCredential UniversityDegreeCredential]]]"
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Credential analysis" types="[VerifiableCredential UniversityDegreeCredential]" subject_fields="[gpa id given_name family_name degree]"
time=2025-11-27T14:03:25.152+09:00 level=INFO msg="Generated presentation definition" json="{\n\t\t\"query\": {\n\t\t\t\"presentation_definition\": {\n\t\t\t\"id\": \"dynamic-presentation-UniversityDegreeCredential\",\n\t\t\t\"input_descriptors\": [\n\t\t\t{\n\t\t\t\t\"id\": \"credential-request\",\n\t\t\t\t\"name\": \"UniversityDegreeCredential\",\n\t\t\t\t\"purpose\": \"Verify credential\",\n\t\t\t\t\"format\": {\n\t\t\t\t\"jwt_vc_json\": {\n\t\t\t\t\t\"alg\": [\"ES256\"]\n\t\t\t\t}\n\t\t\t\t},\n\t\t\t\t\"constraints\": {\n\t\t\t\t\"fields\": [\n\t\t{\n\t\t\t\"path\": [\"$.type\"],\n\t\t\t\"filter\": {\n\t\t\t\t\"type\": \"array\",\n\t\t\t\t\"contains\": {\"const\": \"UniversityDegreeCredential\"}\n\t\t\t}\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.gpa\"],\n\t\t\t\"intent_to_retain\": false\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.given_name\"],\n\t\t\t\"intent_to_retain\": false\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.family_name\"],\n\t\t\t\"intent_to_retain\": false\n\t\t},\n\t\t{\n\t\t\t\"path\": [\"$.credentialSubject.degree\"],\n\t\t\t\"intent_to_retain\": false\n\t\t}\n\t]\n\t\t\t\t}\n\t\t\t}\n\t\t\t]\n\t\t}\n\t\t},\n\t\t\"state\": \"example-state\",\n\t\t\"base_url\": \"http://localhost:8080\",\n\t\t\"is_request_uri\": true,\n\t\t\"response_uri\": \"http://localhost:8080/callback\",\n\t\t\"client_id\": \"x509_san_dns:localhost\"\n\t}"
time=2025-11-27T14:03:25.155+09:00 level=INFO msg="Authorization RequestURI" status="200 OK" body="openid4vp://authorize?client_id=x509_san_dns%3Alocalhost&request_uri=http%3A%2F%2Flocalhost%3A8080%2Frequest.jwt%2F9855a937fda74c3f8de9d7f92537206e"
time=2025-11-27T14:03:25.155+09:00 level=INFO msg="Request URI is valid" scheme=openid4vp
time=2025-11-27T14:03:25.174+09:00 level=INFO msg="Credential presented successfully"
```

`Credential presented successfully`と表示されれば、成功です。

---

### モード2: コンフォーマンステスト（外部URL使用）

外部のOID4VPコンフォーマンステストサービスに対してテストを実行します。
コンフォーマンステスト用のURLは、[OIDF Conformance Testing for OpenID for Verifiable Presentations](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/) ページから取得できます。
`Testing a wallet` ボタンをクリックしてください。

#### 実行方法

```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go "openid4vp://authorize?client_id=...&request_uri=..."
```

**重要**: OID4VP URIを引数に指定すると、自動的にコンフォーマンステストモードで動作します。

#### 動作の違い

コンフォーマンステストモードでは、以下の設定が自動的に適用されます：

- **証明書検証**: システムルート証明書プールを使用
- **証明書チェーン検証スキップ**: `InsecureSkipX509Verify: true` が自動設定され、自己署名証明書や非標準証明書を使用するコンフォーマンステストサーバーとの通信を可能にします
- **選択クレーム**: `given_name`と`family_name`を選択
- **キーバインディング**: 必須（`RequireKeyBinding: true`）
- **Audience/Nonce**: リクエストURIから自動的に抽出

> ⚠️ **警告**: `InsecureSkipX509Verify: true` はコンフォーマンステストやローカル開発時のみ有効です。本番環境では**絶対に**使用しないでください。

---

## ファイル構成と使用方法

### 統合テストプログラム

`server_integration_sdjwt/server_integration_sdjwt.go` は2つのモードで動作します：

**モード1: サーバー統合テスト（引数なし）**
```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go
```
- ローカルのvcknotsサーバーとの統合をテスト
- 厳格な証明書検証（特定の証明書ファイルを使用）
- サーバーは http://localhost:8080 で起動している必要があります

**モード2: コンフォーマンステスト（OID4VP URI引数あり）**
```bash
cd /path/to/vcknots/wallet/examples/server_integration_sdjwt
go run server_integration_sdjwt.go "openid4vp://authorize?..."
```
- 外部のOID4VPコンフォーマンステストサービスに対してテスト
- システムルート証明書プールを使用
- `InsecureSkipX509Verify: true` を自動設定（非標準証明書に対応）

### ファイル構成

```
examples/
├── server_integration_jwtvc/
│   └── server_integration_jwtvc.go   # JWT-VC 統合テスト
├── server_integration_sdjwt/
│   ├── server_integration_sdjwt.go   # SD-JWT 統合テスト（kb-jwt なし）
│   └── example_sd_jwt.txt            # サンプル SD-JWT クレデンシャル
├── server_integration_sdjwt+kbjwt/
│   ├── server_integration_sdjwt_kbjwt.go # kb-jwt 付き SD-JWT 統合テスト
│   └── example_sd_jwt.txt                 # サンプル SD-JWT クレデンシャル
├── custom_dispatcher/                 # カスタムディスパッチャー実装例
├── custom_plugin/                     # カスタムプラグイン実装例
└── README.md                          # このファイル
```

**注意**: 証明書ファイルと SD-JWT サンプルファイルは、各テストディレクトリからの相対パスで読み込まれます。デフォルトでは：
- 証明書: `../../../server/samples/certificate-openid-test/certificate_openid.pem`
- SD-JWT サンプル: `example_sd_jwt.txt` (server_integration_sdjwt/ 内)

kb-jwt 付き検証を行う場合は `server_integration_sdjwt+kbjwt` を利用してください。このサンプルは `dc+sd-jwt` を要求し、`http://localhost:8080/callback-kbjwt` に送信し、`x509_san_dns:localhost` に一致する audience と固定 nonce を使って KB-JWT を付与します。

別の証明書を使用する場合は、`VCKNOTS_CERT_PATH` 環境変数を設定してください：

```bash
cd /path/to/vcknots/wallet/examples/server_integration_jwtvc
VCKNOTS_CERT_PATH=/path/to/custom/cert.pem go run server_integration_jwtvc.go
```

---

## トラブルシューティング

### `client_id` 検証エラー（コンフォーマンステスト）

コンフォーマンステストは、意図的に不正な `client_id` を送信してウォレットの検証ロジックをテストします。

- **エラー例**:
  - `invalid client_id: duplicate prefix detected`（例: `x509_san_dns:x509_san_dns:...`）
  - `SAN of the certificate and client_id did not match`
- これらのエラーは**期待される動作**であり、ウォレットが正しくセキュリティチェックを実施していることを示します。

### `x509: certificate is not standards compliant` エラー

コンフォーマンステストサーバーは、テスト目的で自己署名証明書や非標準的な証明書構造を使用することがあります。

- **状況**: サーバー統合テスト（`引数なしモード`）で発生する場合、証明書ファイルが正しく設定されていない可能性があります。
- **状況**: コンフォーマンステスト（`引数ありモード`）では `InsecureSkipX509Verify: true` が自動設定されるため、通常は発生しません。
- **解決策（サーバー統合テスト向け）**: 正しい証明書ファイルが `../../../server/samples/certificate-openid-test/certificate_openid.pem` に配置されていることを確認するか、`VCKNOTS_CERT_PATH` で指定してください。

