# AWS Lambda Server (Local Development)

`@trustknots/server-aws` — Lambda handlers for Issuer, Authorization Server, and Verifier on AWS API Gateway.

Shared routes are provided by `@trustknots/server-core`. The Issuer, Authorization Server, and Verifier all use DynamoDB-backed metadata stores (`@trustknots/aws`). The Issuer and the Verifier additionally store their signing keys in AWS KMS (see [Issuer signing keys (AWS KMS)](#issuer-signing-keys-aws-kms) and [Verifier signing keys (AWS KMS)](#verifier-signing-keys-aws-kms)), and the Verifier stores its X.509 certificate in AWS Secrets Manager (see [Verifier certificate (AWS Secrets Manager)](#verifier-certificate-aws-secrets-manager)).

For **actual API specifications, parameters, type definitions, and usage examples** for Issuer, Authorization Server, and Verifier, please refer to the following official documentation:

- **Issuer**: [Issuer Setup and Usage Guide](https://trustknots.github.io/vcknots/docs/issuer)
- **Verifier**: [Verifier Setup and Usage Guide](https://trustknots.github.io/vcknots/docs/verifier)

The endpoint list in this README is an overview of the paths used in this server. Detailed request/response formats and error codes follow the above documentation.

## Directory Structure

```text
src/
├── apps/
│   ├── create-base-app.ts      # Shared Hono app factory
│   ├── create-issuer-app.ts    # Issuer app (DynamoDB issuer metadata store + KMS signature key store)
│   ├── create-authz-app.ts     # Authorization Server app (DynamoDB authz server metadata store)
│   └── create-verifier-app.ts  # Verifier app (DynamoDB verifier metadata store + KMS signature key store)
├── handlers/
│   ├── issuer.ts               # Lambda handler / local entrypoint — Issuer (port 8081)
│   ├── authz.ts                # Lambda handler / local entrypoint — Authorization Server (port 8082)
│   └── verifier.ts             # Lambda handler / local entrypoint — Verifier (port 8083)
├── context/
│   └── vcknots-context.ts      # VcknotsContext and baseUrl helpers
├── utils/
│   └── error-logger.ts         # Sanitized error logging
├── .env.example                # Sample environment variables
└── package.json
```

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| [Node.js](https://nodejs.org/) | 20+ | |
| [pnpm](https://pnpm.io/) | 10.11.0 | Monorepo package manager |
| AWS credentials | — | Required for the Issuer, Authorization Server, and Verifier (DynamoDB; the Issuer and Verifier also use KMS) |

AWS credentials can be set via `~/.aws/credentials`, `~/.aws/config`, environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), or `AWS_PROFILE`.

The CDK stack (`server/aws/resources`) must be deployed to AWS before starting the Issuer, Authorization Server, or Verifier locally, because all three read from live DynamoDB tables.

## Setup

### 1. Install dependencies

From the monorepo root:

```bash
pnpm install
```

### 2. Build workspace packages

```bash
pnpm -F @trustknots/vcknots build
pnpm -F @trustknots/server-core build
pnpm -F @trustknots/aws build
```

### 3. Configure environment variables

```bash
cd server/aws/src
cp .env.example .env
```

Edit `.env`. Table names are available in the CloudFormation stack outputs after deploying `server/aws/resources`.

| Variable | Required by | Description |
|---|---|---|
| `AWS_REGION` | All **required** | AWS region where the DynamoDB tables and KMS keys live (e.g. `ap-northeast-1`) |
| `AWS_PROFILE` | All (optional) | AWS profile to use (omit to use the default) |
| `TX_CODE_PEPPER` | All **required** | Secret pepper used to HMAC-hash `tx_code` before storing it in DynamoDB |
| `ISSUERS_TABLE_NAME` | Issuer **required** | DynamoDB table name (stack output: `IssuersTableName`) |
| `NONCES_TABLE_NAME` | Issuer **required** | DynamoDB table name (stack output: `NoncesTableName`) |
| `PRE_CODES_TABLE_NAME` | Issuer & Authz **required** | DynamoDB table name, shared by both servers (stack output: `PreCodesTableName`) |
| `AUTH_SERVERS_TABLE_NAME` | Authz **required** | DynamoDB table name (stack output: `AuthServersTableName`) |
| `VERIFIERS_TABLE_NAME` | Verifier **required** | DynamoDB table name (stack output: `VerifiersTableName`) |
| `REQUEST_OBJECTS_TABLE_NAME` | Verifier **required** | DynamoDB table name (stack output: `RequestObjectsTableName`) |
| `NONCES_TABLE_NAME` | Verifier **required** | DynamoDB table name (stack output: `NoncesTableName`) |
| `ISSUER_PORT` | Issuer (optional) | Override the Issuer listening port (default: `8081`) |
| `ISSUER_BASE_URL` | Issuer (optional) | Override the base URL used in Issuer metadata (default: `http://localhost:{ISSUER_PORT}`) |
| `AUTHZ_PORT` | Authz (optional) | Override the Authorization Server listening port (default: `8082`) |
| `AUTHZ_BASE_URL` | Authz (optional) | Override the base URL used in Authz metadata (default: `http://localhost:{AUTHZ_PORT}`) |
| `VERIFIER_PORT` | Verifier (optional) | Override the Verifier listening port (default: `8083`) |
| `VERIFIER_BASE_URL` | Verifier (optional) | Override the base URL used in Verifier metadata (default: `http://localhost:{VERIFIER_PORT}`) |
| `VERIFIER_CERTIFICATE_SECRET_PREFIX` | Verifier (optional) | Secrets Manager name prefix for verifier certificates (default: `vcknots/verifier-certificates`). Changing it requires updating the IAM grant in `server/aws/resources` to match |
| `PRIVATE_KEY_PATH` / `CERTIFICATE_PATH` | Verifier (optional) | Paths to the PEM private key and X.509 certificate registered on first startup (default: the sample chain in `server/samples/certificate-openid-test/`) |
| `PRIVATE_KEY` / `CERTIFICATE` | Verifier (optional) | The same material inline as PEM (`\n` escaped). Takes precedence over the `*_PATH` variants |

**`ISSUERS_TABLE_NAME`, `PRE_CODES_TABLE_NAME` (Issuer & Authz), `NONCES_TABLE_NAME` (Issuer & Verifier), `AUTH_SERVERS_TABLE_NAME`, `VERIFIERS_TABLE_NAME`, and `REQUEST_OBJECTS_TABLE_NAME` are required** — each server exits at startup if a table name it needs is missing.

**`TX_CODE_PEPPER` is required by every server.** It is a secret pepper used to HMAC-hash `tx_code` values before storing them in DynamoDB. Because `@trustknots/aws` evaluates it at import time, the Issuer, Authorization Server, and Verifier all fail at startup with `TX_CODE_PEPPER environment variable is required` when it is missing. Use a sufficiently long random secret and keep it stable per environment — rotating it invalidates previously stored `tx_code` hashes.

Failed `tx_code` attempts are limited per pre-authorized code (default **5**) by `dynamodbPreAuthorizedCodeStore`. To change the limit, pass `maxTxCodeAttempts` when constructing the provider in `server/aws/src/apps` (no environment variable yet). After the limit is reached the code is deleted, and further requests fail with `invalid_grant` even with the correct `tx_code`.

## Start the Servers

Run each server in a separate terminal from `server/aws/src`:

```bash
# Issuer — http://localhost:8081
pnpm start:issuer

# Authorization Server — http://localhost:8082
pnpm start:authz

# Verifier — http://localhost:8083
pnpm start:verifier
```

You can also run from the monorepo root using the package filter:

```bash
pnpm -F @trustknots/server-aws start:issuer
```

### Startup confirmation

On first run, the Issuer, Authorization Server, and Verifier automatically seed initial metadata into DynamoDB from the `server/samples/` directory:

```text
Issuer metadata initialized
Issuer is running on http://localhost:8081
```

```text
Authz server metadata initialized
Authz is running on http://localhost:8082
```

```text
Verifier metadata and certificate initialized
Verifier is running on http://localhost:8083
```

On subsequent runs, initialization is skipped if the data already exists:

```text
Issuer metadata already exists, skipping initialization
Issuer is running on http://localhost:8081
```

```text
Authz server metadata already exists, skipping initialization
Authz is running on http://localhost:8082
```

```text
Verifier metadata already exists, skipping initialization
Verifier is running on http://localhost:8083
```

### Override port or base URL

```bash
ISSUER_PORT=9081 ISSUER_BASE_URL=http://localhost:9081 pnpm start:issuer
```

## Endpoints

### Issuer (`http://localhost:8081`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/configurations/:configuration/offer` | Create credential offer |
| `POST` | `/credentials` | Issue credential |
| `GET` | `/.well-known/openid-credential-issuer` | Issuer metadata |
| `GET` | `/.well-known/jwt-vc-issuer` | JWT VC Issuer metadata |
| `POST` | `/nonce` | Create nonce (c_nonce) |
| `GET` | `/nonce/:nonce` | Validate nonce |
| `DELETE` | `/nonce/:nonce` | Revoke nonce |

### Authorization Server (`http://localhost:8082`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/token` | Token endpoint (Pre-Authorized Code grant) |
| `GET` | `/.well-known/oauth-authorization-server` | Authorization Server metadata |

### Verifier (`http://localhost:8083`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/request` | Create authorization request |
| `POST` | `/request-object` | Create authorization request (by reference) |
| `GET` | `/request.jwt/:request-object-Id` | Get Request Object JWT |
| `POST` | `/callback` | VP verification callback |
| `POST` | `/callback-kbjwt` | VP verification callback (Key Binding JWT) |
| `GET` | `/verified` | Redirect endpoint after verification |

## Issuer Signing Keys (AWS KMS)

The Issuer stores its credential-signing keys in AWS KMS via `kmsIssuerSignatureKeyStore()` (`@trustknots/aws`). Signing is always performed by the KMS `Sign` API. For keys generated inside KMS, the private key never leaves KMS. For an externally generated key pair, the application receives the private key, wraps it, and sends it to KMS via `ImportKeyMaterial` — the private key exists outside KMS up to that point.

- **Alias naming**: each key is referenced through the alias `alias/vcknots/issuers/<md5(issuer)>-<alg>` (base64url MD5 of the issuer identifier plus the JOSE algorithm, e.g. `ES256`). Without a key pair, the key is created once and the same alias is reused on subsequent `save` calls. When importing an externally generated key pair, every `save` call creates a brand-new KMS key and repoints the alias to it (the previous key is kept, not deleted). No additional environment variables are required.
- **Supported algorithms**: `ES256`, `ES384`, `RS256`, `RS512`, `PS256`, `PS512`. Keys can be generated inside KMS for all of them. Importing an externally generated key pair is supported for EC algorithms (`ES256`/`ES384`) only — RSA private keys exceed the RSAES_OAEP_SHA_256 wrapping limit and would require `RSA_AES_KEY_WRAP`, which is not implemented (same limitation as the Google Cloud provider).
- **Required IAM** (granted to the Issuer Lambda role by the CDK stack): `kms:CreateKey`, `kms:TagResource`, `kms:CreateAlias`, `kms:UpdateAlias`, `kms:DescribeKey`, `kms:GetPublicKey`, `kms:Sign`, `kms:GetParametersForImport`, `kms:ImportKeyMaterial`, `kms:ScheduleKeyDeletion`. When running locally, the AWS profile needs the same permissions. Every key the provider creates is tagged (`vcknots:issuer-signature-key=true`); the CDK stack uses this tag to authorize `CreateAlias`/`UpdateAlias` on the key itself, since a brand-new key has no alias yet to scope access by.

## Verifier Signing Keys (AWS KMS)

The Verifier stores the key that signs Authorization Request Objects (JAR) in AWS KMS via `kmsVerifierSignatureKeyStore()` (`@trustknots/aws`). It is built from the same provider factory as the Issuer store, so the KMS behaviour — in-KMS generation, wrapped import, and signing through the KMS `Sign` API — is identical; only the alias namespace and the key tag differ.

- **Alias naming**: each key is referenced through the alias `alias/vcknots/verifiers/<md5(client_id)>-<alg>` (base64url MD5 of the verifier client id plus the JOSE algorithm). The key is created when the verifier is registered (`createVerifierMetadata`), and its public key is published as `jwks` in the verifier metadata. No additional environment variables are required.
- **Supported algorithms**: same as the Issuer — `ES256`, `ES384`, `RS256`, `RS512`, `PS256`, `PS512` for in-KMS generation, EC only (`ES256`/`ES384`) for importing an externally generated key pair.
- **Required IAM** (granted to the Verifier Lambda role by the CDK stack): the same actions as the Issuer, scoped to the `alias/vcknots/verifiers/*` namespace and to keys tagged `vcknots:verifier-signature-key=true`.
- **Store drift**: the verifier metadata lives in DynamoDB while the key lives in KMS, so the two can drift apart — most often when an environment that previously ran on the in-memory key store is pointed at KMS. `createVerifierMetadata` rejects an already-registered verifier and cannot repair that, so the Verifier only logs a warning at startup (`Verifier metadata exists but no <alg> key is registered in KMS`) and keeps running. Recovery is manual, and it is the same procedure that seeds a verifier in the first place — note that **registration only runs locally**: `handlers/verifier.ts` skips `initialize()` when `AWS_LAMBDA_FUNCTION_NAME` is set, and there is no HTTP endpoint that registers a verifier, so a deployed Lambda never registers one by itself.

  `initialize()` always registers the bundled `server/samples/verifier_metadata.json`, so the steps below **replace whatever metadata the verifier had** and are only appropriate for a verifier that runs on that sample metadata:

  1. Delete the verifier's item from the Verifiers table. Its partition key is not the client id itself but the base64url MD5 of it: `node -e "console.log(require('crypto').createHash('md5').update('<client-id>').digest('base64url'))"`.
  2. Locally, point `.env` at the same tables and set `VERIFIER_BASE_URL` to the verifier you are repairing (the deployed API URL, not `localhost`, when fixing a deployed environment).
  3. Run `pnpm start:verifier` once. It registers the sample metadata and creates the KMS key for that verifier id, then you can stop it.

  For a verifier with custom metadata, back the item up first and re-register that same metadata from a script that calls `createVerifierMetadata` — the flow creates the key and rewrites `jwks` from it. Do not restore the backed-up item verbatim: its `jwks` still describes the key that went missing, which is the drift you are repairing.

## Verifier Certificate (AWS Secrets Manager)

The Verifier stores its X.509 certificate chain in AWS Secrets Manager via `secretsManagerVerifierCertificateStore()` (`@trustknots/aws`). The chain is read every time a signed authorization request (JAR) is built for an `x509_san_dns` or `x509_san_uri` client id, and embedded in the JWT `x5c` header so the wallet can verify the Verifier's identity against its own trust anchors. Other client id prefixes (for example `redirect_uri`) never touch this store.

- **Secret naming**: one secret per verifier, named `vcknots/verifier-certificates/<md5(verifier id)>` (hex MD5 of the verifier's base URL, since a URL cannot be used verbatim in a secret name). Override the prefix with `VERIFIER_CERTIFICATE_SECRET_PREFIX`. The chain is stored as PEM and returned as bare base64 DER.
- **Registration**: the certificate is written on first local startup, from `PRIVATE_KEY`/`CERTIFICATE` (or the `*_PATH` variants), defaulting to the sample chain in `server/samples/certificate-openid-test/`. The sample certificate's SAN is `localhost`, which matches the `x509_san_dns:localhost` client id that `POST /request` falls back to when none is given.
- **Deployed Lambdas do not self-register.** Initialization only runs outside Lambda (`server/aws/src/handlers/verifier.ts` skips it when `AWS_LAMBDA_FUNCTION_NAME` is set), and the secret name is derived from the verifier's base URL, so a certificate seeded from `http://localhost:8083` is not the one an API Gateway URL looks up. On a deployed stack, either write the secret manually or use a client id prefix that needs no certificate.
- **Required IAM** (granted to the Verifier Lambda role by the CDK stack): `secretsmanager:CreateSecret`, `secretsmanager:PutSecretValue`, `secretsmanager:GetSecretValue`, scoped to `secret:vcknots/verifier-certificates/*`. Secrets use the `aws/secretsmanager` managed key, so no separate KMS grant is needed. When running locally, the AWS profile needs the same permissions.
- **Re-running initialization**: metadata lives in DynamoDB and the certificate in Secrets Manager, so both must be cleared to start over. Deleting only one leaves a half-initialized verifier; startup logs `Verifier metadata exists but no certificate is registered` when the certificate is the missing half. A deleted secret stays name-reserved for its recovery window, so use `--force-delete-without-recovery` if you intend to re-create it immediately.

## Authorization Server Signing Keys (AWS KMS)

The Authorization Server stores the key that signs access tokens / responses in AWS KMS via `kmsAuthzSignatureKeyStore()` (`@trustknots/aws`). It is built from the same provider factory as the Issuer and Verifier stores, so the KMS behaviour — in-KMS generation, wrapped import, and signing through the KMS `Sign` API — is identical; only the alias namespace and the key tag differ.

- **Alias naming**: each key is referenced through the alias `alias/vcknots/authz/<md5(issuer)>-<alg>` (base64url MD5 of the authorization server issuer URL plus the JOSE algorithm). The key is created when the authorization server is registered (`createAuthzServerMetadata`), always with `ES256` (`create-authz-app.ts` does not pass a custom `alg`). No additional environment variables are required.
- **Supported algorithms**: same as the Issuer and Verifier — `ES256`, `ES384`, `RS256`, `RS512`, `PS256`, `PS512` for in-KMS generation, EC only (`ES256`/`ES384`) for importing an externally generated key pair.
- **Required IAM** (granted to the Authz Lambda role by the CDK stack): the same actions as the Issuer and Verifier, scoped to the `alias/vcknots/authz/*` namespace and to keys tagged `vcknots:authz-signature-key=true`.
- **Store drift**: the authz server metadata lives in DynamoDB while the key lives in KMS, so the two can drift apart — most often when an environment that previously ran on the in-memory key store is pointed at KMS. `createAuthzServerMetadata` rejects an already-registered authorization server and cannot repair that, so the Authorization Server only logs a warning at startup (`Authz server metadata exists but no <alg> key is registered in KMS`) and keeps running. Recovery is manual, and it is the same procedure that seeds an authorization server in the first place — note that **registration only runs locally**: `handlers/authz.ts` skips `initialize()` when `AWS_LAMBDA_FUNCTION_NAME` is set, and there is no HTTP endpoint that registers an authorization server, so a deployed Lambda never registers one by itself.

  `initialize()` always registers the bundled `server/samples/authorization_metadata.json`, so the steps below **replace whatever metadata the authorization server had** and are only appropriate for one that runs on that sample metadata:

  1. Delete the authorization server's item from the AuthServers table. Its partition key is not the issuer URL itself but the base64url MD5 of it: `node -e "console.log(require('crypto').createHash('md5').update('<issuer-url>').digest('base64url'))"`.
  2. Locally, point `.env` at the same tables and set `AUTHZ_BASE_URL` to the authorization server you are repairing (the deployed API URL, not `localhost`, when fixing a deployed environment).
  3. Run `pnpm start:authz` once. It registers the sample metadata and creates the KMS key for that authorization server, then you can stop it.

## Notes

- `.env` is loaded by `dotenv/config` at startup; changes require a server restart.
- After changing workspace packages, run `pnpm install` at the repository root to refresh links, then rebuild the affected packages.
- For AWS deployment, see [`server/aws/resources/README.md`](./resources/README.md).
