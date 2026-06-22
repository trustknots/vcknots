# server/aws

AWS Lambda deployment of vcknots.

## Packages

| Directory | Package | Description |
|---|---|---|
| [`lambda/`](./lambda) | `@trustknots/server-aws` | Lambda handlers, vcknots context, and utilities |
| [`resources/`](./resources) | `resources` | CDK stack: API Gateway, Lambda, DynamoDB |

## Overview

Each of the three vcknots roles (Issuer, Authz, Verifier) is deployed as a separate Lambda function behind its own API Gateway REST API.

Infrastructure is defined in `resources/` using AWS CDK. Handler source code lives in `lambda/src/`.

See [resources/README.md](./resources/README.md) for architecture details and deployment instructions.
