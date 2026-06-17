# AWS Resources

CDK stack for vcknots on AWS.

Related packages:

- [`@trustknots/server-aws`](../lambda) — Lambda handlers and vcknots context (`handlers/`, `context/`)
- [`@trustknots/aws`](../../../aws/provider) — AWS providers for DynamoDB / KMS / Secrets Manager (placeholder)

## Architecture

```
aws/
└── provider/              @trustknots/aws (placeholder)

server/aws/
├── lambda/                @trustknots/server-aws
│   ├── package.json
│   ├── handlers/
│   │   ├── issuer.ts      Lambda handler (Issuer)
│   │   ├── authz.ts       Lambda handler (Authz)
│   │   └── verifier.ts    Lambda handler (Verifier)
│   └── context/
│       └── vcknots-context.ts context / baseUrl helpers
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
        │       ├── key-management.ts      (placeholder, not in stack yet)
        │       └── secret-management.ts   (placeholder, not in stack yet)
        ├── util/
        │   └── paths.ts
        └── resources-stack.ts

ResourcesStack
├── DataStores (construct/data)
├── IssuerApi  (construct/api) → Lambda + REST API (vcknots-issuer)
├── AuthzApi   (construct/api) → Lambda + REST API (vcknots-authz)
└── VerifierApi (construct/api) → Lambda + REST API (vcknots-verifier)
```

### Lambda handlers

Handler sources live in `@trustknots/server-aws` (`server/aws/lambda/handlers/` and `server/aws/lambda/context/`).

Each handler mounts a single route from `@trustknots/server-core` on a Hono app and exports `handle(app)` for API Gateway.

| Handler (`server/aws/lambda/handlers/`) | Route |
|---|---|
| `issuer.ts` | `@trustknots/server-core/routes/issue` |
| `authz.ts` | `@trustknots/server-core/routes/authz` |
| `verifier.ts` | `@trustknots/server-core/routes/verify` |

Handlers currently use the default in-memory vcknots providers. Wire `@trustknots/aws` providers once implemented.

### API Gateway + Lambda

Each role uses the shared `LambdaApi` construct (`lib/construct/api/lambda-api.ts`):

| Resource | Setting |
|---|---|
| API type | `LambdaRestApi` with `{proxy+}` |
| Stage | `test` |
| CORS | Enabled on all routes via `defaultCorsPreflightOptions` |
| Lambda runtime | Node.js latest (`NODEJS_LATEST`, ARM64) |
| Timeout | 29s |
| Memory | 512 MB |
| Log retention | 1 week |
| `API_GATEWAY_ID`, `API_STAGE` | Used to build the API Gateway default URL at runtime |

| Lambda | Log group | Table env vars |
|---|---|---|
| Issuer | `/vcknots/issuer` | `ISSUERS_TABLE_NAME`, `NONCES_TABLE_NAME`, `PRE_CODES_TABLE_NAME` |
| Authz | `/vcknots/authz` | `AUTH_SERVERS_TABLE_NAME`, `PRE_CODES_TABLE_NAME` |
| Verifier | `/vcknots/verifier` | `VERIFIERS_TABLE_NAME`, `REQUEST_OBJECTS_TABLE_NAME`, `NONCES_TABLE_NAME` |

Role-specific constructs in `lib/construct/api/` wire DynamoDB tables, IAM, and environment variables.

Custom domains (ACM / Route 53) are not configured yet.

### DynamoDB Table Design

There is one table per data type.  
Each table uses a single partition key, `id`, to identify one item (no sort key).  
Billing is on-demand (`PAY_PER_REQUEST`). Tables use `RETAIN` on stack deletion.

| Table | Example `id` value | TTL | Stored data |
|---|---|---|---|
| IssuersTable | Hash of Issuer URL | no | Credential Issuer metadata |
| AuthServersTable | Hash of Authorization Server URL | no | Authorization Server metadata |
| PreCodesTable | Pre-Authorized Code string | yes (`expires_at`) | Pre-authorized code used at issuance |
| NoncesTable | Nonce string | yes (`expires_at`) | Nonce for replay protection |
| VerifiersTable | Hash of Verifier client ID | no | Verifier metadata |
| RequestObjectsTable | Request Object ID | yes (`expires_at`) | VP request Request Object |

Attributes other than `id` (metadata body, `expires_at`, and so on) are written by the application.

### IAM

| Lambda | DynamoDB access |
|---|---|
| Issuer | IssuersTable, NoncesTable (read/write); PreCodesTable (write only) |
| Authz | AuthServersTable, PreCodesTable (read/write) |
| Verifier | VerifiersTable, RequestObjectsTable, NoncesTable (read/write) |

### Stack Outputs

- `IssuerApiUrl`, `AuthzApiUrl`, `VerifierApiUrl`
- `IssuersTableName`, `AuthServersTableName`, `PreCodesTableName`, `NoncesTableName`, `VerifiersTableName`, `RequestObjectsTableName`

## Prerequisites

### Install on your machine

| Tool | Version | Notes |
|---|---|---|
| [Node.js](https://nodejs.org/) | 20+ | Required to run CDK and bundle Lambda handlers |
| [pnpm](https://pnpm.io/) | 10.11.0 | Monorepo package manager (`packageManager` in root `package.json`) |
| [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) | v2 recommended | Used by `deploy-resources.sh` for identity/region lookup |
| POSIX `sh` | — | Deploy script (`scripts/deploy-resources.sh`; `/bin/sh` on macOS/Linux) |

`aws-cdk`, `ts-node`, and `esbuild` are installed as `server/aws/resources` devDependencies.  
You do **not** need a global `cdk` install; use `pnpm cdk` or `pnpm deploy` from `server/aws/resources`.

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
# edit API_STAGE, AWS_PROFILE, etc.
```

## Build

TypeScript compiles to `dist/` (not alongside source files).

```bash
cd server/aws/resources
pnpm build
```

## Deploy

Use the deploy script (runs `cdk bootstrap` then `cdk deploy`). CDK runs via `ts-node` (`cdk.json`); `pnpm build` is not required.

```bash
cd server/aws/resources

# default AWS profile, stage: test
pnpm deploy

# specify profile and/or stage
pnpm deploy -- --profile vc-knots
pnpm deploy -- --stage prod
pnpm deploy -- --profile vc-knots --stage prod
```

Options:

| Flag | Description |
|---|---|
| `--profile` | AWS profile (optional; uses CLI default when omitted) |
| `--stage` | API Gateway stage name (default: `test`) |

`scripts/.env` is loaded when present. CLI flags override `.env`.

## Synth only

```bash
cd server/aws/resources
pnpm cdk synth
```
