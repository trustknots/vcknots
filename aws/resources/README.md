# AWS Resources

CDK stack for vcknots on AWS.

## Architecture

```
lib/
├── construct/
│   ├── data/
│   │   └── data-stores.ts
│   ├── api/
│   │   ├── lambda-api.ts
│   │   ├── issuer-api.ts
│   │   ├── authz-api.ts
│   │   └── verifier-api.ts
│   └── security/
│       ├── key-management.ts      (placeholder)
│       └── secret-management.ts   (placeholder)
├── handlers/
└── util/

ResourcesStack
├── DataStores (construct/data)
├── IssuerApi  (construct/api) → Lambda + REST API (vcknots-issuer)
├── AuthzApi   (construct/api) → Lambda + REST API (vcknots-authz)
└── VerifierApi (construct/api) → Lambda + REST API (vcknots-verifier)
```

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
| `BASE_URL` | Set automatically from the API Gateway URL |

Role-specific constructs in `lib/construct/api/` wire DynamoDB tables, IAM, and environment variables.

Custom domains (ACM / Route 53) are not configured yet.

### DynamoDB Table Design

There is one table per data type.  
Each table uses a single partition key, `id`, to identify one item (no sort key).

| Table | Example `id` value | TTL | Stored data |
|---|---|---|---|
| IssuersTable | Hash of Issuer URL | no | Credential Issuer metadata |
| AuthServersTable | Hash of Authorization Server URL | no | Authorization Server metadata |
| PreCodesTable | Pre-Authorized Code string | yes | Pre-authorized code used at issuance |
| NoncesTable | Nonce string | yes | Nonce for replay protection |
| VerifiersTable | Hash of Verifier client ID | no | Verifier metadata |
| RequestObjectsTable | Request Object ID | yes | VP request Request Object |

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

## Build

TypeScript compiles to `dist/` (not alongside source files).

```bash
cd aws/resources
pnpm build
```

## Deploy

CDK runs via `ts-node` (`cdk.json`). `pnpm build` is not required for synth/deploy.

```bash
cd aws/resources
pnpm cdk synth
pnpm cdk deploy
```
