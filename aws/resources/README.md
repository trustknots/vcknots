# AWS Resources

CDK stack for vcknots on AWS.

Related package: [`@trustknots/aws`](../provider) (AWS providers for DynamoDB / KMS / Secrets Manager — placeholder).

## Architecture

```
aws/
├── provider/          @trustknots/aws (placeholder)
└── resources/         this package (CDK app)
    ├── bin/resources.ts
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
        ├── handlers/
        │   ├── issuer.ts
        │   ├── authz.ts
        │   └── verifier.ts
        ├── util/
        │   ├── paths.ts
        │   └── vcknots-context.ts
        └── resources-stack.ts

ResourcesStack
├── DataStores (construct/data)
├── IssuerApi  (construct/api) → Lambda + REST API (vcknots-issuer)
├── AuthzApi   (construct/api) → Lambda + REST API (vcknots-authz)
└── VerifierApi (construct/api) → Lambda + REST API (vcknots-verifier)
```

### Lambda handlers

Each handler mounts a single route from `@trustknots/server-core` on a Hono app and exports `handle(app)` for API Gateway.

| Handler | Route |
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
| Stage | `prod` |
| CORS | Enabled on all routes via `defaultCorsPreflightOptions` |
| Lambda runtime | Node.js latest (`NODEJS_LATEST`, ARM64) |
| Timeout | 29s |
| Memory | 512 MB |
| Log retention | 1 week |
| `BASE_URL` | Set automatically from the API Gateway URL |

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

From the monorepo root:

```bash
pnpm install
```

First deploy to an account/region may require CDK bootstrap:

```bash
cd aws/resources
pnpm cdk bootstrap
```

## Build

TypeScript compiles to `dist/` (not alongside source files).

```bash
cd aws/resources
pnpm build
```

## Synth and deploy

CDK runs via `ts-node` (`cdk.json`). `pnpm build` is not required for synth/deploy.

```bash
cd aws/resources
pnpm cdk synth
pnpm cdk deploy
```
