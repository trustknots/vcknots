# Architecture Overview

VC Knots is a **pluggable framework** for building Verifiable Credentials (VC) ecosystems.

It provides reusable core libraries that implement OpenID4VCI and OpenID4VP, while allowing infrastructure components such as cloud providers, databases, and key management services to be integrated through pluggable providers. This enables developers to build Issuer, Wallet, and Verifier applications in a flexible and extensible way.

---

# Overall Architecture

```mermaid
flowchart TB

    subgraph APP["Applications"]
        ISSUER[Issuer]
        WALLET[Wallet]
        VERIFIER[Verifier]
    end

    subgraph CORE["VC Knots Core Libraries"]
        IV["issuer+verifier<br/>TypeScript"]
        W["wallet<br/>Go"]
    end

    subgraph PROVIDER["Provider Implementations"]
        AWS[AWS]
        GCP[Google Cloud]
        CUSTOM[Custom Providers]
    end

    subgraph INFRA["External Infrastructure"]
        DB[(Database)]
        KMS[(Key Management)]
        SECRET[(Secrets Manager)]
    end

    ISSUER --> IV
    VERIFIER --> IV
    WALLET --> W

    IV --> AWS
    IV --> GCP
    IV --> CUSTOM

    AWS --> DB
    AWS --> KMS
    AWS --> SECRET
```

The architecture is organized into four logical layers.

| Layer              | Responsibility                                                                          |
| ------------------ | --------------------------------------------------------------------------------------- |
| **Applications**   | Implement Issuer, Wallet, and Verifier applications.                                    |
| **Core Libraries** | Provide OpenID4VCI/OpenID4VP protocol implementations and wallet functionality.         |
| **Providers**      | Integrate external services such as databases, KMS, and cloud platforms.                |
| **Infrastructure** | Consists of the actual databases, key management services, and other backend resources. |

---

# Package Responsibilities

| Package               | Language   | Responsibility                                                                            |
| --------------------- | ---------- | ----------------------------------------------------------------------------------------- |
| `issuer+verifier`     | TypeScript | Implements OpenID4VCI/OpenID4VP, Issuer, Verifier, and Authorization Server functionality |
| `wallet`              | Go         | Provides wallet functionality, DID management, key management, and credential operations  |
| `aws`                 | TypeScript | AWS provider implementations for DynamoDB, KMS, Secrets Manager, and related services     |
| `server/single`       | TypeScript | Reference implementation for a single-tenant deployment                                   |
| `server/aws`          | TypeScript | AWS Lambda and CDK deployment example                                                     |
| `server/google-cloud` | TypeScript | Google Cloud deployment example                                                           |

---

# Package Relationships

```mermaid
flowchart LR

    APP[Applications]

    IV["issuer+verifier"]
    W["wallet"]

    AWS[AWS Provider]
    CUSTOM[Custom Provider]

    SERVER[Sample Servers]

    APP --> IV
    APP --> W

    IV --> AWS
    IV --> CUSTOM

    SERVER --> IV
    SERVER --> W
```

The relationship between the packages is as follows:

* Applications are built using the `issuer+verifier` and `wallet` libraries.
* `issuer+verifier` communicates with external infrastructure through provider implementations.
* `server/*` packages are reference implementations that compose the reusable libraries.

---

# Credential Issuance Flow (OpenID4VCI)

```mermaid
sequenceDiagram

    participant Wallet
    participant Issuer
    participant Library as issuer+verifier
    participant Provider
    participant KMS

    Wallet->>Issuer: Credential Request

    Issuer->>Library: Process Request

    Library->>Provider: Access Storage

    Provider->>KMS: Sign Credential

    KMS-->>Provider: Signature

    Provider-->>Library: Credential

    Library-->>Wallet: Verifiable Credential
```

### Flow

1. The Wallet sends an OpenID4VCI credential request.
2. The Issuer delegates protocol processing to `issuer+verifier`.
3. The provider accesses storage and key management services.
4. The credential is signed.
5. The Wallet receives and stores the issued Verifiable Credential.

---

# Presentation Verification Flow (OpenID4VP)

```mermaid
sequenceDiagram

    participant Wallet
    participant Verifier
    participant Library as issuer+verifier
    participant Trust as DID Resolver / Trust Registry

    Wallet->>Verifier: Verifiable Presentation

    Verifier->>Library: Verify Presentation

    Library->>Trust: Resolve DID

    Trust-->>Library: DID Document

    Library->>Library: Verify Signature

    Library-->>Verifier: Verification Result
```

### Flow

1. The Wallet sends a Verifiable Presentation.
2. The Verifier delegates the verification process to `issuer+verifier`.
3. The library resolves the DID, verifies the signature, and validates trust requirements.
4. The verification result is returned to the Verifier.

---

# Layered Architecture

```mermaid
flowchart TB

    subgraph L1["Application Layer"]
        APP[Issuer / Wallet / Verifier]
    end

    subgraph L2["Core Libraries"]
        CORE["issuer+verifier<br/>wallet"]
    end

    subgraph L3["Provider Layer"]
        PROVIDER["AWS<br/>Google Cloud<br/>Custom Providers"]
    end

    subgraph L4["Infrastructure Layer"]
        INFRA["Database<br/>KMS<br/>Storage"]
    end

    APP --> CORE
    CORE --> PROVIDER
    PROVIDER --> INFRA
```

Applications are built on top of the core libraries, which interact with external infrastructure through provider implementations. This layered architecture separates protocol logic from infrastructure, making it easy to replace cloud platforms, storage backends, and key management services without affecting application logic.

---

# Design Principles

VC Knots is designed around the following principles:

* **Separation of protocol logic and infrastructure**, allowing business logic to remain independent of cloud-specific implementations.
* **Pluggable provider architecture**, enabling integration with AWS, Google Cloud, or custom environments.
* **Reusable core libraries**, allowing applications to implement OpenID4VCI/OpenID4VP without reimplementing protocol logic.
* **Reference server implementations**, demonstrating recommended deployment patterns while keeping the framework itself infrastructure-agnostic.
