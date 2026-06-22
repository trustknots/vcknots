# @trustknots/server-aws

Lambda handlers and vcknots context for vcknots on AWS.

## Directory structure

```text
lambda/
├── src/
│   ├── handlers/
│   │   ├── issuer.ts       Lambda handler (Issuer)
│   │   ├── authz.ts        Lambda handler (Authz)
│   │   └── verifier.ts     Lambda handler (Verifier)
│   ├── context/
│   │   └── vcknots-context.ts  vcknots context initialization and base URL resolution
│   └── utils/
│       └── error-logger.ts     Sanitized error logging for CloudWatch
├── package.json
└── tsconfig.json
```

## Overview

Each handler mounts a single route from `@trustknots/server-core` on a Hono app and exports `handle(app)` for API Gateway proxy integration.

| Handler | Route |
|---|---|
| `issuer.ts` | `@trustknots/server-core/routes/issue` |
| `authz.ts` | `@trustknots/server-core/routes/authz` |
| `verifier.ts` | `@trustknots/server-core/routes/verify` |

Handlers use in-memory vcknots providers by default. Replace with `@trustknots/aws` providers (DynamoDB / KMS / Secrets Manager) once implemented.

Unhandled errors are logged via `utils/error-logger.ts` (`sanitizeError`) so only safe fields (message, name, stack in dev) reach CloudWatch.

### Base URL resolution (`context/vcknots-context.ts`)

| Environment variables | Result |
|---|---|
| `API_GATEWAY_ID` + `AWS_REGION` + `API_STAGE` set | `https://{id}.execute-api.{region}.amazonaws.com/{stage}` |
| `BASE_URL` set | value of `BASE_URL` |
| neither | `http://localhost:8080` (local fallback) |

The CDK stack (`resources/`) injects `API_GATEWAY_ID` and `API_STAGE` automatically.

## Build

```bash
# from project root
pnpm --filter @trustknots/server-aws build

# or from server/aws/lambda
pnpm build
```

## Local development

Set `BASE_URL` in `.env` (copy from `.env` in this directory) and run handlers locally with your preferred Lambda emulation tool.
