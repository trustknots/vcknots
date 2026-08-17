# AWS Resources

CDK stack for vcknots on AWS.

Related packages:

- [`@trustknots/server-aws`](../src) — Lambda handlers, vcknots context, and utilities (`src/handlers/`, `src/context/`, `src/utils/`)
- [`@trustknots/aws`](../../../aws) — AWS providers for DynamoDB and KMS (Issuer, Authz, and Verifier signature keys; Secrets Manager not yet implemented)

## Architecture

```text
aws/                       @trustknots/aws

server/aws/
├── src/                   @trustknots/server-aws
│   ├── package.json
│   ├── handlers/
│   │   ├── issuer.ts      Lambda handler (Issuer)
│   │   ├── authz.ts       Lambda handler (Authz)
│   │   └── verifier.ts    Lambda handler (Verifier)
│   ├── apps/
│   │   ├── create-issuer-app.ts   Issuer app (DynamoDB issuer metadata store, KMS signature key store)
│   │   ├── create-authz-app.ts    Authorization Server app (DynamoDB authz metadata store, KMS signature key store)
│   │   └── create-verifier-app.ts Verifier app (DynamoDB verifier metadata store, KMS signature key store)
│   ├── context/
│   │   └── vcknots-context.ts context / baseUrl helpers
│   └── utils/
│       └── error-logger.ts  sanitized CloudWatch error logging
└── resources/             this package (CDK app)
    ├── bin/resources.ts
    ├── scripts/
    │   ├── deploy-resources.sh
    │   └── .env.example
    └── lib/
        ├── construct/
        │   ├── data/
        │   │   └── data-stores.ts
        │   ├── api/
        │   │   ├── lambda-api.ts
        │   │   ├── issuer-api.ts
        │   │   ├── authz-api.ts
        │   │   └── verifier-api.ts
        │   └── security/
        │       └── secret-management.ts   (placeholder, not in stack yet)
        ├── util/
        │   └── paths.ts
        └── resources-stack.ts

ResourcesStack
├── DataStores (construct/data)
├── IssuerApi  (construct/api) → Lambda + REST API (vcknots-issuer-{stage})
├── AuthzApi   (construct/api) → Lambda + REST API (vcknots-authz-{stage})
└── VerifierApi (construct/api) → Lambda + REST API (vcknots-verifier-{stage})
```

### Lambda handlers

Handler sources live in `@trustknots/server-aws` (`server/aws/src/handlers/` and `server/aws/src/context/`).

Each handler mounts a single route from `@trustknots/server-core` on a Hono app and exports `handle(app)` for API Gateway.

| Handler (`server/aws/src/handlers/`) | Route |
|---|---|
| `issuer.ts` | `@trustknots/server-core/routes/issue` |
| `authz.ts` | `@trustknots/server-core/routes/authz` |
| `verifier.ts` | `@trustknots/server-core/routes/verify` |

The Issuer uses `dynamodbIssuerMetadataStore` and `kmsIssuerSignatureKeyStore` from `@trustknots/aws`, the Authorization Server uses `dynamodbAuthzServerMetadataStore` and `kmsAuthzSignatureKeyStore`, and the Verifier uses `dynamodbVerifierMetadataStore` and `kmsVerifierSignatureKeyStore`.

Unhandled errors are logged via `utils/error-logger.ts` (`sanitizeError`) so only safe fields reach CloudWatch.

### API Gateway + Lambda

Each role uses the shared `LambdaApi` construct (`lib/construct/api/lambda-api.ts`).

Physical names (log groups, REST API names) include the deployment stage from `API_STAGE` (default: `test`) so multiple stages can coexist in the same account/region.

| Resource | Setting |
|---|---|
| API type | `LambdaRestApi` with `{proxy+}` |
| Stage | `API_STAGE` env var (default: `test`; set via deploy `--stage` or `scripts/.env`) |
| CORS | `defaultCorsPreflightOptions`: non-`prod` stages allow all origins; `prod` requires `CORS_ALLOWED_ORIGINS` (comma-separated HTTPS origins). Methods: GET, POST, DELETE, OPTIONS |
| Lambda runtime | Node.js 24 (`NODEJS_24_X`, ARM64) |
| Timeout | 29s |
| Memory | 512 MB |
| Log retention | 1 week |
| `API_GATEWAY_ID`, `API_STAGE` | Used to build the API Gateway default URL at runtime |

| Lambda | Log group (`{stage}` = `API_STAGE`) | REST API name | Environment variables |
|---|---|---|---|
| Issuer | `/vcknots/{stage}/issuer` | `vcknots-issuer-{stage}` | `ISSUERS_TABLE_NAME`, `NONCES_TABLE_NAME`, `PRE_CODES_TABLE_NAME`, `TX_CODE_PEPPER` |
| Authz | `/vcknots/{stage}/authz` | `vcknots-authz-{stage}` | `AUTH_SERVERS_TABLE_NAME`, `PRE_CODES_TABLE_NAME`, `TX_CODE_PEPPER` |
| Verifier | `/vcknots/{stage}/verifier` | `vcknots-verifier-{stage}` | `VERIFIERS_TABLE_NAME`, `REQUEST_OBJECTS_TABLE_NAME`, `NONCES_TABLE_NAME` |

`TX_CODE_PEPPER` is read from the deploy-time environment (see [Deploy](#deploy)) and injected into the Issuer/Authz Lambda environment; CDK synth fails fast if it is unset.

Role-specific constructs in `lib/construct/api/` wire DynamoDB tables, IAM, and environment variables.

Custom domains (ACM / Route 53) are not configured yet.

### DynamoDB Table Design

There is one table per data type.  
Each table uses a single partition key, `id`, to identify one item (no sort key).  
Billing is on-demand (`PAY_PER_REQUEST`). Tables use `RETAIN` on stack deletion and **Point-in-Time Recovery (PITR)** is enabled.

| Table | Example `id` value | TTL | Stored data |
|---|---|---|---|
| IssuersTable | Hash of Issuer URL | no | Credential Issuer metadata |
| AuthServersTable | Hash of Authorization Server URL | no | Authorization Server metadata |
| PreCodesTable | Pre-Authorized Code string | yes (`ttl`) | Pre-authorized code used at issuance |
| NoncesTable | Nonce string | yes (`ttl`) | Nonce for replay protection |
| VerifiersTable | Hash of Verifier client ID | no | Verifier metadata |
| RequestObjectsTable | Request Object ID | yes (`ttl`) | VP request Request Object |

Attributes other than `id` (metadata body, `expires_at`, `ttl`, and so on) are written by the application. For the TTL-enabled tables (PreCodesTable / NoncesTable / RequestObjectsTable), `expires_at` is the application-level expiry in **epoch milliseconds** (used for expiry checks, matching the Firestore / in-memory providers) and `ttl` is a separate **epoch-seconds** attribute used only by DynamoDB TTL.

### IAM

| Lambda | DynamoDB access |
|---|---|
| Issuer | IssuersTable, NoncesTable (read/write); PreCodesTable (write only) |
| Authz | AuthServersTable, PreCodesTable (read/write) |
| Verifier | VerifiersTable, RequestObjectsTable, NoncesTable (read/write) |

The Issuer, Authz, and Verifier roles also have a scoped KMS policy for their signature key store, granted by `grantSignatureKeyStoreAccess()` (`lib/construct/security/signature-key-policy.ts`). Keys are created at runtime, so none of them can be referenced by ARN here; each statement is scoped by a condition instead:

| Actions | Scoped by |
|---|---|
| `CreateKey`, `TagResource` | `kms:KeyUsage=SIGN_VERIFY` plus the `kms:KeySpec`/`kms:KeyOrigin` values the provider creates |
| `CreateAlias`, `UpdateAlias` | the role's alias namespace (alias side) and `aws:ResourceTag` (key side — a new key has no alias yet) |
| `DescribeKey`, `GetPublicKey`, `Sign` | `kms:ResourceAliases` matching the role's alias namespace |
| `GetParametersForImport`, `ImportKeyMaterial`, `ScheduleKeyDeletion` | `aws:ResourceTag` |

The last row is separate on purpose: `kms:ResourceAliases` matches on the aliases a key already carries, so it can never authorize an action on a key that has none. The provider imports key material and discards orphan keys before (or instead of) the first `CreateAlias`, so those calls are scoped by the tag the provider sets at `CreateKey` time.

The two roles differ only in the alias namespace and the tag:

| Role | Alias namespace | Key tag |
|---|---|---|
| Issuer | `alias/vcknots/issuers/*` | `vcknots:issuer-signature-key=true` |
| Verifier | `alias/vcknots/verifiers/*` | `vcknots:verifier-signature-key=true` |

### Stack Outputs

- `IssuerApiUrl`, `AuthzApiUrl`, `VerifierApiUrl`
- `IssuersTableName`, `AuthServersTableName`, `PreCodesTableName`, `NoncesTableName`, `VerifiersTableName`, `RequestObjectsTableName`

## Prerequisites

### Install on your machine

| Tool | Version | Notes |
|---|---|---|
| [Node.js](https://nodejs.org/) | 20+ | Required to run CDK and bundle Lambda handlers (Lambda runtime: Node.js 24) |
| [pnpm](https://pnpm.io/) | 10.11.0 | Monorepo package manager (`packageManager` in root `package.json`) |
| [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) | v2 recommended | Used by `deploy-resources.sh` for identity/region lookup |
| POSIX `sh` | — | Deploy script (`scripts/deploy-resources.sh`; `/bin/sh` on macOS/Linux) |

`aws-cdk`, `ts-node`, and `esbuild` are installed as `server/aws/resources` devDependencies.  
You do **not** need a global `cdk` install; use `pnpm cdk` or `pnpm run deploy` from `server/aws/resources`.

### AWS account access

- Credentials for the target account/region (`~/.aws/credentials`, `~/.aws/config`, or environment variables).
- IAM permissions to run CDK bootstrap and deploy (CloudFormation, Lambda, API Gateway, DynamoDB, IAM, S3, ECR, SSM, and related resources).
- First deploy to an account/region runs `cdk bootstrap` automatically via the deploy script.

Verify access before deploying:

```bash
aws sts get-caller-identity
aws configure get region
```

### Project setup

From the monorepo root:

```bash
pnpm install
```

Optional local deploy defaults:

```bash
cp server/aws/resources/scripts/.env.example server/aws/resources/scripts/.env
# edit API_STAGE, AWS_PROFILE, CORS_ALLOWED_ORIGINS (required for API_STAGE=prod), etc.
```

## Build

TypeScript compiles to `dist/` (not alongside source files).

```bash
# from project root
pnpm -F @trustknots/aws-resources build

# or from server/aws/resources
pnpm build
```

## Deploy

Use the deploy script (runs `cdk bootstrap` then `cdk deploy`). CDK runs via `ts-node` (`cdk.json`); `pnpm build` is not required.

```bash
# from project root
pnpm -F @trustknots/aws-resources run deploy

# or from server/aws/resources
cd server/aws/resources

# default AWS profile, stage: test
pnpm run deploy

# specify profile and/or stage
pnpm run deploy -- --profile vc-knots
pnpm run deploy -- --stage prod --profile vc-knots
# prod requires CORS_ALLOWED_ORIGINS (env or scripts/.env)
CORS_ALLOWED_ORIGINS=https://app.example.com pnpm run deploy -- --stage prod
# TX_CODE_PEPPER is always required (env or scripts/.env) — CDK synth throws if it is unset
TX_CODE_PEPPER=<your-tx-code-pepper-here> pnpm run deploy -- --profile vc-knots
```

Options:

| Flag / env | Description |
|---|---|
| `--profile` | AWS profile (optional; uses CLI default when omitted) |
| `--stage` | API Gateway stage name (default: `test`). Also sets `API_STAGE` for CDK synth |
| `CORS_ALLOWED_ORIGINS` | Comma-separated HTTPS origins for API Gateway CORS (**required when `API_STAGE=prod`**) |
| `TX_CODE_PEPPER` | Secret pepper for `tx_code` HMAC hashing, injected into the Issuer/Authz Lambda environment (**always required**) |
| `STACK_NAME` | CloudFormation stack name (default: `ResourcesStack`) |

`scripts/.env` is loaded when present. CLI flags override `.env`.

## Synth only

```bash
cd server/aws/resources
pnpm cdk synth
```
