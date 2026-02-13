# Server

This directory contains sample server implementations using the VCKnots library.

## Directory Structure

### `single/`

Single-tenant server implementation. All endpoints are mounted at the root path (`/`).

For details, see [single/README.md](./single/README.md).

### `multi/`

Multi-tenant server implementation (work in progress). Endpoints are mounted with prefixes such as `/issuers`, `/authorizations`, `/verifiers`, etc.

### `samples/`

Sample configuration files used by the server implementations.

- `issuer_metadata.json`: Credential Issuer metadata configuration
- `authorization_metadata.json`: Authorization Server metadata configuration
- `verifier_metadata.json`: Verifier metadata configuration
- `certificate-chain/`: Sample certificate chain files
- `certificate-openid-test/`: Test certificates and private keys provided by the OpenID Foundation
