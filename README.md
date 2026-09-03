# VC Knots

<h3 align="center">A pluggable framework for building Verifiable Credentials ecosystems.</h3>

## Overview

VCKnots is an open-source library for building Verifiable Credentials ecosystems.
It implements OpenID4VCI (OpenID for Verifiable Credential Issuance) and OpenID4VP (OpenID for Verifiable Presentations), with core wallet functionalities for identifier and key management.

The framework supports pluggable extensions for data serialization formats, protocol flavors, and cryptographic algorithms.

**Key Features:**
- OpenID4VCI and OpenID4VP implementations
- Core wallet functionalities (identifier and key management)
- Pluggable architecture (extensible formats, protocols, and algorithms)

## Start Here

Choose the documentation that matches your goal.

| Goal | Documentation |
| --- | --- |
| Learn how to use VC Knots | [User Documentation](https://trustknots.github.io/vcknots/) |
| Build an Issuer | [Issuer Guide](https://trustknots.github.io/vcknots/docs/issuer) |
| Implement a Wallet | [Wallet Guide](https://trustknots.github.io/vcknots/docs/wallet) |
| Build a Verifier | [Verifier Guide](https://trustknots.github.io/vcknots/docs/verifier) |
| Check OpenID4VCI / OpenID4VP support | [Support Matrix](https://trustknots.github.io/vcknots/docs/support-matrix) |
| Run the sample server | [Single Server README](./server/single/README.md) |

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

## Contributing

Contributions are welcome, from bug fixes to new features.

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).

## License

[Apache License 2.0](./LICENSE)

## Contact

This project is managed by the VCKnots Project Team, composed of volunteer individual members, as part of the Trust Knots initiative.

- **Bug Reports & Features Requests**: [GitHub Issues](https://github.com/trustknots/vcknots/issues)
- **General Inquiries**: vcknots@googlegroups.com
