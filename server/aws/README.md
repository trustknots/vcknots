# AWS Lambda Server (Local Development)

`@trustknots/server-aws` — Lambda handlers for Issuer, Authorization Server, and Verifier on AWS API Gateway.

Shared routes are provided by `@trustknots/server-core`. The Issuer uses a DynamoDB-backed metadata store (`@trustknots/aws`). The Authorization Server and Verifier use in-memory providers by default.

For **actual API specifications, parameters, type definitions, and usage examples** for Issuer, Authorization Server, and Verifier, please refer to the following official documentation:

- **Issuer**: [Issuer Setup and Usage Guide](https://trustknots.github.io/vcknots/docs/issuer)
- **Verifier**: [Verifier Setup and Usage Guide](https://trustknots.github.io/vcknots/docs/verifier)

The endpoint list in this README is an overview of the paths used in this server. Detailed request/response formats and error codes follow the above documentation.

## Directory Structure

```text
src/
├── apps/
│   ├── create-base-app.ts      # Shared Hono app factory
│   ├── create-issuer-app.ts    # Issuer app (DynamoDB issuer metadata store)
│   ├── create-authz-app.ts     # Authorization Server app (in-memory)
│   └── create-verifier-app.ts  # Verifier app (in-memory)
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
| AWS credentials | — | Required only for the Issuer (DynamoDB) |

AWS credentials can be set via `~/.aws/credentials`, `~/.aws/config`, environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), or `AWS_PROFILE`.

The CDK stack (`server/aws/resources`) must be deployed to AWS before starting the Issuer locally, because the Issuer reads from a live DynamoDB table. The Authorization Server and Verifier use in-memory providers and do **not** require AWS.

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
| `AWS_REGION` | Issuer | AWS region where DynamoDB tables are deployed (e.g. `ap-northeast-1`) |
| `AWS_PROFILE` | Issuer (optional) | AWS profile to use (omit to use the default) |
| `ISSUERS_TABLE_NAME` | Issuer **required** | DynamoDB table name (stack output: `IssuersTableName`) |
| `NONCES_TABLE_NAME` | Issuer (optional) | DynamoDB table name (stack output: `NoncesTableName`) |
| `PRE_CODES_TABLE_NAME` | Issuer (optional) | DynamoDB table name (stack output: `PreCodesTableName`) |
| `AUTH_SERVERS_TABLE_NAME` | Authz (optional) | DynamoDB table name (stack output: `AuthServersTableName`) |
| `PRE_CODES_TABLE_NAME` | Authz (optional) | DynamoDB table name (stack output: `PreCodesTableName`) |
| `VERIFIERS_TABLE_NAME` | Verifier (optional) | DynamoDB table name (stack output: `VerifiersTableName`) |
| `REQUEST_OBJECTS_TABLE_NAME` | Verifier (optional) | DynamoDB table name (stack output: `RequestObjectsTableName`) |
| `NONCES_TABLE_NAME` | Verifier (optional) | DynamoDB table name (stack output: `NoncesTableName`) |
| `BASE_URL` | All (optional) | Override the base URL used in metadata (default: `http://localhost:{port}`) |
| `PORT` | All (optional) | Override the listening port |

**`ISSUERS_TABLE_NAME` is required** — the Issuer server exits at startup if it is missing.

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

```
Issuer is running on http://localhost:8081
```

### Override port or base URL

```bash
PORT=9081 BASE_URL=http://localhost:9081 pnpm start:issuer
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

## Notes

- `.env` is loaded by `dotenv/config` at startup; changes require a server restart.
- After changing workspace packages, run `pnpm install` at the repository root to refresh links, then rebuild the affected packages.
- For AWS deployment, see [`server/aws/resources/README.md`](./resources/README.md).
