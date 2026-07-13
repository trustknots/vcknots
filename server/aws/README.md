# AWS Lambda Server (Local Development)

`@trustknots/server-aws` — Lambda handlers for Issuer, Authorization Server, and Verifier on AWS API Gateway.

Shared routes are provided by `@trustknots/server-core`. The Issuer, Authorization Server, and Verifier all use DynamoDB-backed metadata stores (`@trustknots/aws`).

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
│   ├── create-authz-app.ts     # Authorization Server app (DynamoDB authz server metadata store)
│   └── create-verifier-app.ts  # Verifier app (DynamoDB verifier metadata store)
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
| AWS credentials | — | Required for the Issuer, Authorization Server, and Verifier (DynamoDB) |

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
| `AWS_REGION` | Issuer | AWS region where DynamoDB tables are deployed (e.g. `ap-northeast-1`) |
| `AWS_PROFILE` | Issuer (optional) | AWS profile to use (omit to use the default) |
| `TX_CODE_PEPPER` | All **required** | Secret pepper used to HMAC-hash `tx_code` before storing it in DynamoDB |
| `ISSUERS_TABLE_NAME` | Issuer **required** | DynamoDB table name (stack output: `IssuersTableName`) |
| `NONCES_TABLE_NAME` | Issuer **required** | DynamoDB table name (stack output: `NoncesTableName`) |
| `PRE_CODES_TABLE_NAME` | Issuer **required** | DynamoDB table name (stack output: `PreCodesTableName`) |
| `AUTH_SERVERS_TABLE_NAME` | Authz **required** | DynamoDB table name (stack output: `AuthServersTableName`) |
| `PRE_CODES_TABLE_NAME` | Authz **required** | DynamoDB table name (stack output: `PreCodesTableName`) |
| `VERIFIERS_TABLE_NAME` | Verifier **required** | DynamoDB table name (stack output: `VerifiersTableName`) |
| `REQUEST_OBJECTS_TABLE_NAME` | Verifier **required** | DynamoDB table name (stack output: `RequestObjectsTableName`) |
| `NONCES_TABLE_NAME` | Verifier **required** | DynamoDB table name (stack output: `NoncesTableName`) |
| `ISSUER_PORT` | Issuer (optional) | Override the Issuer listening port (default: `8081`) |
| `ISSUER_BASE_URL` | Issuer (optional) | Override the base URL used in Issuer metadata (default: `http://localhost:{ISSUER_PORT}`) |
| `AUTHZ_PORT` | Authz (optional) | Override the Authorization Server listening port (default: `8082`) |
| `AUTHZ_BASE_URL` | Authz (optional) | Override the base URL used in Authz metadata (default: `http://localhost:{AUTHZ_PORT}`) |
| `VERIFIER_PORT` | Verifier (optional) | Override the Verifier listening port (default: `8083`) |
| `VERIFIER_BASE_URL` | Verifier (optional) | Override the base URL used in Verifier metadata (default: `http://localhost:{VERIFIER_PORT}`) |

**`ISSUERS_TABLE_NAME`, `PRE_CODES_TABLE_NAME` (Issuer & Authz), `NONCES_TABLE_NAME` (Issuer & Verifier), `AUTH_SERVERS_TABLE_NAME`, `VERIFIERS_TABLE_NAME`, and `REQUEST_OBJECTS_TABLE_NAME` are required** — each server exits at startup if a table name it needs is missing.

**`TX_CODE_PEPPER` is required by every server.** It is a secret pepper used to HMAC-hash `tx_code` values before storing them in DynamoDB. Because `@trustknots/aws` evaluates it at import time, the Issuer, Authorization Server, and Verifier all fail at startup with `TX_CODE_PEPPER environment variable is required` when it is missing. Use a sufficiently long random secret and keep it stable per environment — rotating it invalidates previously stored `tx_code` hashes.

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
Verifier metadata initialized
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

## Notes

- `.env` is loaded by `dotenv/config` at startup; changes require a server restart.
- After changing workspace packages, run `pnpm install` at the repository root to refresh links, then rebuild the affected packages.
- For AWS deployment, see [`server/aws/resources/README.md`](./resources/README.md).
