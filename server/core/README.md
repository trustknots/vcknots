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

