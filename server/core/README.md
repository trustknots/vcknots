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

The shared `POST /token` route also uses the same OAuth policy. It can also verify `private_key_jwt` client authentication using clients registered in the OAuth client store. In the samples, `server/samples/oauth-clients.json` is loaded at startup and registers per-client sender constraint settings, `jwks.keys`, `client_assertion_audience`, and related metadata.

If the token request body contains `client_id`, that value is used first. If it is absent, the client id is derived from the `client_assertion` JWT `iss` / `sub`. For Pre-Authorized Code token requests where neither source yields a client id, the request is treated as an anonymous token request and the anonymous client policy is used only when the Authorization Server metadata `pre-authorized_grant_anonymous_access_supported` is `true`. If it is omitted or `false`, the request fails with `invalid_client`. See the [single-server README](../single/README.md#post-token) for details.

| mode | `POST /token` behavior |
| --- | --- |
| `off` | DPoP is not used. The server issues a Bearer access token. |
| `optional` | If the DPoP header is absent, the server issues a Bearer access token. If the DPoP header is present, the server verifies the proof and issues a DPoP-bound access token. |
| `required` | The DPoP header is required. A missing or malformed DPoP header results in `invalid_request`. |

If the DPoP Proof has no nonce, or the nonce is invalid, the route returns `use_dpop_nonce` with a `DPoP-Nonce` response header. When DPoP Proof verification succeeds, the response contains `token_type: "DPoP"` and the access token contains `cnf.jkt`.

You can also import route/util modules via subpath exports:

```ts
import { createIssueRouter } from '@trustknots/server-core/routes/issue'
import { handleError } from '@trustknots/server-core/utils/error-handler'
```

## Server Options

`createServer(options?)` accepts `ServerOptions`, which extends `VcknotsOptions` from the vcknots library (providers, extensions, etc.).

The design allows component-specific options to be passed via independent namespaces.

Currently only the `verifier` namespace is implemented. The same pattern can be extended to `issuer` and `authz` in the future.

### `verifier` options

#### `vpAudTransactionStore`

Inject a `DirectPostVpAudTransactionStore` implementation used in the `direct_post` flow to bind the OAuth `state` parameter to a verifier transaction ID. When omitted, an in-process in-memory implementation (`createDirectPostVpAudTransactionStore()`) is used.

**In-memory limitation**: The in-memory implementation is for single-process environments only. In environments such as Cloud Run where multiple instances run concurrently, `/request` and `/callback` may be routed to different instances, causing state lookup failures. In such cases, inject an external store implementation.

`DirectPostVpAudTransactionStore` interface:

| Method | Description |
| --- | --- |
| `reserve(state)` | Reserves the state and returns a `reservationToken`. Returns `invalid_request` if the state is already in use. |
| `register(state, transactionId, reservationToken)` | Validates the `reservationToken` and binds the verifier transaction ID to the state. |
| `resolve(state)` | Returns the `transactionId` for the state. Returns `invalid_request` if unknown or expired. |
| `consume(state, transactionId)` | Deletes the state entry only when the stored transaction ID matches `transactionId`. Called after successful VP verification. |
| `release(state, reservationToken)` | Rollback on error. Validates the `reservationToken` and deletes the state entry. |

This follows a two-phase commit pattern: `reserve` → `register` (on success) or `release` (on error), preventing duplicate state registration from concurrent requests.

For a Firestore-backed implementation example, see the [Google Cloud server README](../google-cloud/README.md#vpaudtransactionstore-firestore-implementation).

## Build

From the repository root:

```bash
pnpm install
pnpm -F @trustknots/server-core build
```

## Notes

- This is a workspace package (private).
- It depends on `@trustknots/vcknots`, `hono`, and `@hono/node-server`.
