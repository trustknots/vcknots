---
sidebar_position: 10
---

# Architecture Overview

VC Knots is a pluggable framework for building Verifiable Credentials ecosystems. The framework consists of reusable libraries, provider implementations, and sample server applications.

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
        IV[issuer+verifier<br/>TypeScript]
        W[wallet<br/>Go]
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

The architecture is divided into four layers:

* **Applications** implement Issuer, Wallet, and Verifier services.
* **Core Libraries** implement OpenID4VCI/OpenID4VP and wallet functionality.
* **Providers** integrate cloud services and infrastructure.
* **Infrastructure** provides storage, key management, and secrets.

---

# Package Responsibilities

| Package               | Language   | Responsibility                                                              |
| --------------------- | ---------- | --------------------------------------------------------------------------- |
| `issuer+verifier`     | TypeScript | OpenID4VCI/OpenID4VP implementation, Issuer, Verifier, Authorization Server |
| `wallet`              | Go         | Wallet functionality, DID management, key management, credential operations |
| `aws`                 | TypeScript | AWS integrations (DynamoDB, KMS, Secrets Manager)                           |
| `server/single`       | TypeScript | Single-tenant reference server                                              |
| `server/aws`          | TypeScript | AWS Lambda deployment                                                       |
| `server/google-cloud` | TypeScript | Google Cloud deployment                                                     |

---

# Package Relationships

```mermaid
flowchart LR

    APP[Applications]

    IV[issuer+verifier]
    W[wallet]

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

Sample servers are reference implementations that compose the reusable libraries.

---

# Credential Issuance Flow

```mermaid
sequenceDiagram

    participant Holder as Wallet
    participant Issuer
    participant Library as issuer+verifier
    participant Provider
    participant KMS

    Holder->>Issuer: Credential Request (OpenID4VCI)

    Issuer->>Library: Process Request

    Library->>Provider: Store / Retrieve Data

    Provider->>KMS: Sign Credential

    KMS-->>Provider: Signature

    Provider-->>Library: Credential

    Library-->>Holder: Verifiable Credential
```

### Steps

1. The Wallet requests a credential.
2. The Issuer delegates protocol processing to `issuer+verifier`.
3. Providers access storage and key management.
4. The credential is signed.
5. The Wallet receives the credential.

---

# Presentation Verification Flow

```mermaid
sequenceDiagram

    participant Wallet
    participant Verifier
    participant Library as issuer+verifier
    participant Trust as Trust Registry / DID Resolver

    Wallet->>Verifier: Verifiable Presentation (OpenID4VP)

    Verifier->>Library: Verify Presentation

    Library->>Trust: Resolve DID

    Trust-->>Library: DID Document

    Library->>Library: Verify Signature

    Library-->>Verifier: Verification Result

    Verifier-->>Wallet: Accept / Reject
```

### Steps

1. The Wallet sends a Verifiable Presentation.
2. The Verifier delegates validation to `issuer+verifier`.
3. The framework resolves DIDs and verifies signatures.
4. The verification result is returned.

---

# Layered Architecture

```mermaid
flowchart TB

    subgraph L1["Application Layer"]
        APP[Issuer / Wallet / Verifier]
    end

    subgraph L2["Core Libraries"]
        CORE[issuer+verifier<br/>wallet]
    end

    subgraph L3["Provider Layer"]
        P[AWS<br/>Google Cloud<br/>Custom Providers]
    end

    subgraph L4["Infrastructure Layer"]
        I[(Database / KMS / Storage)]
    end

    APP --> CORE
    CORE --> P
    P --> I
```

---

# Design Principles

* **Protocol and infrastructure are separated.**
* **Cloud providers are replaceable through provider interfaces.**
* **Applications build on reusable libraries instead of implementing OpenID4VCI/OpenID4VP directly.**
* **Sample servers demonstrate deployment patterns without being part of the framework core.**

---

```mermaid
flowchart TB

    APP[Issuer]

    CORE[issuer+verifier]

    FORMAT["Credential Format Plugin"]
    CRYPTO["Crypto Plugin"]
    STORAGE["Storage Provider"]

    APP --> CORE

    CORE --> FORMAT
    CORE --> CRYPTO
    CORE --> STORAGE

    FORMAT --> JWT
    FORMAT --> SDJWT
    FORMAT --> mdoc

    CRYPTO --> ES256
    CRYPTO --> EdDSA

    STORAGE --> DynamoDB
    STORAGE --> PostgreSQL
```
