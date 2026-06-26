# VCKnots

<p align="center">Pluggable framework for building Verifiable Credentials ecosystems.</p>

## Overview

VCKnots is an open-source library for building Verifiable Credentials ecosystems.
It implements OID4VCI (OpenID for Verifiable Credential Issuance) and OID4VP (OpenID for Verifiable Presentations), with core wallet functionalities for identifier and key management.

The framework supports pluggable extensions for data serialization formats, protocol flavors, and cryptographic algorithms.

**Key Features:**
- OID4VCI and OID4VP implementations
- Core wallet functionalities (identifier and key management)
- Pluggable architecture (extensible formats, protocols, and algorithms)

## Installation

```bash
# TypeScript
npm install @trustknots/vcknots

# Go
go get github.com/trustknots/vcknots/wallet
```

## Repository Structure

```
vcknots/
├── issuer+verifier/    # @trustknots/vcknots (TypeScript)
│                       # Issuer, Verifier, and Authorization Server library
├── wallet/             # Wallet library (Go)
│                       # Credential operations and key management
├── aws/                # @trustknots/aws (TypeScript)
│                       # AWS providers (DynamoDB, KMS, Secrets Manager)
└── server/             # Sample server implementations (TypeScript)
    ├── single/         # @trustknots/server-single — single-tenant server
    ├── google-cloud/   # @trustknots/server-google-cloud — Google Cloud integration
    └── aws/            # @trustknots/server-aws — AWS Lambda handlers + CDK stack
```

## User Documentation
For detailed user documentation, please visit the [VCKnots Documentation Site](https://trustknots.github.io/vcknots/).

## Contributing

Contributions are welcome, from bug fixes to new features.

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).

## License

[Apache License 2.0](./LICENSE)

## Contact

This project is managed by the VCKnots Project Team, composed of volunteer individual members, as part of the Trust Knots initiative.

- **Bug Reports & Features Requests**: [GitHub Issues](https://github.com/trustknots/vcknots/issues)
- **General Inquiries**: vcknots@googlegroups.com
