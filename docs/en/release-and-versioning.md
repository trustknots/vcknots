---
sidebar_position: 2
---

# Library Releases and Versioning

This document describes the release process and versioning policy for the VC Knots library.

## Scope

This document applies to the following library officially provided and supported by VC Knots:

- `@trustknots/vcknots`
  - An npm package
  - Provides Issuer functionality compliant with OpenID4VCI and Verifier functionality compliant with OpenID4VP.

## Library Releases

The Issuer and Verifier are published as an npm package.

GitHub Actions and Changesets are used to update versions and publish the package to npm.

## Release Frequency

Releases are made as needed for new features and bug fixes. There is no fixed release schedule.

## Versioning Policy

Versions are managed in accordance with Semantic Versioning 2.0.0.

### Versioning Before v1.0.0

Versions prior to `v1.0.0` are provided as beta releases in the initial development phase and may be changed without prior notice as the project progresses toward a stable release.

Before `v1.0.0`, backward-incompatible changes increment the minor version rather than the major version.
