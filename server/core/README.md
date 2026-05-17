# Server Core

Shared server components for the sample server packages.

This package contains the shared server bootstrap, Hono app factory, shared routes, and shared utilities used by:

- `server/single`
- `server/google-cloud`

Package name: `@trustknots/server-core`

## What It Provides

- `createServer(options?)` shared server bootstrap used by `server/single` and `server/google-cloud`
- `createApp(context, baseUrl)` shared Hono application factory
- Shared route factories:
  - `createIssueRouter`
  - `createAuthzRouter`
  - `createVerifierRouter`
- Shared utility:
  - `handleError`

## Directory Structure

```text
core/
├─ src/
│  ├─ app.ts
│  ├─ index.ts
│  ├─ server.ts
│  ├─ routes/
│  │  ├─ authz.ts
│  │  ├─ issue.ts
│  │  └─ verify.ts
│  └─ utils/
│     └─ error-handler.ts
├─ package.json
└─ tsconfig.json
```

## Usage

Import from the package root (recommended):

```ts
import { createApp, createServer } from '@trustknots/server-core'
```

`createServer(options?)` accepts implementation-specific settings such as Providers and Extensions. OAuth policy such as the DPoP mode is loaded from `server/samples/oauth-server.json` and registered in the per-authorization-server policy store at startup.

The shared `POST /nonce` route can add a `DPoP-Nonce` response header when the OAuth policy DPoP mode is not `off`. `c_nonce` and `DPoP-Nonce` are issued as different values, and `DPoP-Nonce` is used as the DPoP Proof nonce for the token endpoint.

The shared `POST /token` route also uses the same OAuth policy.

| mode | `POST /token` behavior |
|------|-------------------------|
| `off` | DPoP is not used. The server issues a Bearer access token. |
| `optional` | If the DPoP header is absent, the server issues a Bearer access token. If the DPoP header is present, the server verifies the proof and issues a DPoP-bound access token. |
| `required` | The DPoP header is required. A missing or malformed DPoP header results in `invalid_request`. |

If the DPoP Proof has no nonce, or the nonce is invalid, the route returns `use_dpop_nonce` with a `DPoP-Nonce` response header. When DPoP Proof verification succeeds, the response contains `token_type: "DPoP"` and the access token contains `cnf.jkt`.

You can also import route/util modules via subpath exports:

```ts
import { createIssueRouter } from '@trustknots/server-core/routes/issue'
import { handleError } from '@trustknots/server-core/utils/error-handler'
```

## Build

From the repository root:

```bash
pnpm install
pnpm -F @trustknots/server-core build
```

## Notes

- This is a workspace package (private).
- It depends on `@trustknots/vcknots`, `hono`, and `@hono/node-server`.
