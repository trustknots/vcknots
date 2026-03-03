# Server

This directory contains sample server implementations using the VCKnots library.

## Directory Structure

### `core/`

Shared server components used by `single/` and `google-cloud/`.

- Common Hono app factory (`createApp`)
- Shared server bootstrap (`createServer`)
- Shared routes (`authz`, `issue`, `verify`)
- Shared utilities (e.g. error handling)

### `single/`

Single-tenant server implementation. All endpoints are mounted at the root path (`/`).
This package now uses `@trustknots/server-core` for shared app/routes/util logic.

For details, see [single/README.md](./single/README.md).

### `google-cloud/`

Single-tenant server implementation with Google Cloud integration.
This package also uses `@trustknots/server-core` for shared app/routes/util logic.

### `multi/`

Multi-tenant server implementation (work in progress). Endpoints are mounted with prefixes such as `/issuers`, `/authorizations`, `/verifiers`, etc.

### `samples/`

Sample configuration files used by the server implementations.

- `issuer_metadata.json`: Credential Issuer metadata configuration
- `authorization_metadata.json`: Authorization Server metadata configuration
- `verifier_metadata.json`: Verifier metadata configuration
- `certificate-chain/`: Sample certificate chain files
- `certificate-openid-test/`: Test certificates and private keys provided by the OpenID Foundation
