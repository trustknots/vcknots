# @trustknots/vcknots

A flexible and extensible library for implementing OpenID for Verifiable Credential Issuance (OID4VCI) Draft 13 and OpenID for Verifiable Presentations (OID4VP) Draft 24.

This package provides the core logic for both Issuers and Verifiers, allowing you to build compliant SSI (Self-Sovereign Identity) applications. It is designed with a provider-based architecture, making it easy to swap out implementations for storage, key management, and other infrastructure dependencies.

## Features

*   **OID4VCI (Issuer):**
    *   Manage Issuer Metadata.
    *   Create Credential Offers (Pre-Authorized Code Flow).
    *   Issue Verifiable Credentials (JWT-VC format).
    *   Support for `did:key` and other DID methods via resolvers.
*   **OID4VP (Verifier):**
    *   Manage Verifier Metadata.
    *   Create Authorization Requests (JAR - Signed Request Objects).
    *   Verify Verifiable Presentations (VP Token).
    *   Support for Presentation Exchange and DCQL (comming soon).
*   **Extensible Architecture:**
    *   All external dependencies (Database, Key Management, DID Resolution) are abstracted as "Providers".
    *   Includes default in-memory implementations for rapid prototyping and testing.

## Installation

```bash
npm install @trustknots/vcknots
# or
pnpm add @trustknots/vcknots
# or
yarn add @trustknots/vcknots
```

## Quick Start

The easiest way to get started is to use the default configuration, which uses in-memory storage for metadata, keys, and session data.

```typescript
import { vcknots } from '@trustknots/vcknots'

// Initialize with default (in-memory) providers
const { issuer, verifier } = vcknots()
```

## Tutorial

For a step-by-step guide on how to use this library, please refer to our documents: [https://trustknots.github.io/vcknots/](https://trustknots.github.io/vcknots/)

## Usage

For comprehensive examples and detailed configurations for both Issuer and Verifier flows, please refer to the example implementations located in the [`server/single`](https://github.com/trustknots/vcknots/tree/main/server/single) or [`server/multi`](https://github.com/trustknots/vcknots/tree/main/server/multi) directory.

### Issuer Flow

#### 1. Setup Issuer Metadata & Keys
First, define your issuer's metadata and generate signing keys.

```typescript
const base = 'https://myissuer.example.com'
const issuerId = CredentialIssuer(base)

// Define metadata (simplified example)
const metadata: CredentialIssuerMetadata = {
  credential_issuer: issuerId,
  authorization_servers: [base],
  credential_endpoint: `${base}/credentials`,
  credential_configurations_supported: {
    'MyCredential': {
      format: 'jwt_vc_json',
      credential_definition: { type: ['VerifiableCredential', 'MyCredential'] },
      credential_signing_alg_values_supported: ['ES256'],
      proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } }
    }
  }
}

// This will save metadata and generate/save keys in the configured store
await issuer.createIssuerMetadata(metadata)
```

#### 2. Create a Credential Offer
Generate a credential offer to be sent to the wallet.

```typescript
const offer = await issuer.offerCredential(issuerId, ['MyCredential'])
const encoded = encodeURIComponent(JSON.stringify(offer))
const scheme = `openid-credential-offer://?credential_offer=${encoded}`
console.log('Credential Offer:', scheme)
```

#### 3. Issue a Credential
When the wallet sends a credential request (after processing the offer), issue the credential.

```typescript
// `req` represents the HTTP request sent by wallet 
const request = CredentialRequest(req.json() /* extract body as json */)
const credential = await issuer.issueCredential(
  issuerId,
  request, 
  {
    alg: 'ES256',
    claims: {
      name: 'Alice',
      from: 'Wonderland'
    }
  }
)

console.log('Issued Credential:', credential)
```

### Verifier Flow

#### 1. Setup Verifier Metadata
Initialize the verifier identity.

```typescript
const base = 'https://myverifier.example.com'
const verifierId = VerifierClientId(base)
const metadata: VerifierMetadata = {
	client_name: 'MyVerifier',
	client_uri: base,
	vp_formats: {
		jwt_vp: {
			alg: ['ES256']
		}
	},
	client_id_scheme: 'redirect_uri'
}

// This will generate signing keys for the verifier (for JAR)
await verifier.createVerifierMetadata(verifierId, metadata)
```

#### 2. Create an Authorization Request
Create a request (typically converted to a QR code) for the wallet to prove something.

```typescript
const base = 'https://myverifier.example.com'
const verifierId = VerifierClientId(base)
const request = await verifier.createAuthzRequest(
  verifierId,
  'vp_token',
  `redirect_uri:${base}`, // client_id
  'direct_post',
  {
    // Presentation Exchange Definition
    presentation_definition: {
      id: 'request',
      input_descriptors: [{
        id: 'id-card',
        constraints: { fields: [{ path: ['$.vc.type'], filter: { type: 'string', pattern: 'MyCredential' } }] }
      }]
    }
  },
  false, // use request_uri (JAR)
  { base_url: base }
)

// Encode authorization request object
const encoded = Object.entries(request)
  .map(([key, value]) => {
    const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
    return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
  })
  .join('&')

const scheme = `openid4vp://authorize?${encoded}`

console.log('Authorization Request', scheme)
```

#### 3. Verify Presentation
Verify the response sent by the wallet.

```typescript
// req represents the HTTP request submitted by wallet
const response = VerifierAuthorizationResponse(req.json())
await verifier.verifyPresentations(verifierId, response)
console.log('Verification Successful!')
```

## Configuration & Providers

To use persistent storage (e.g., Redis, PostgreSQL) or external KMS, you can override the default providers.

```typescript
import { vcknots, Provider } from '@trustknots/vcknots'

const customMetadataStore: IssuerMetadataStoreProvider = {
  kind: 'issuer-metadata-store-provider',
  single: true,
  fetch(issuer) { ... },
  save(metadata) { ... },
}

const { issuer } = vcknots({
  providers: [
    customMetadataStore,
    // ... other custom providers
  ]
})
```

## Developing & Testing

To run the unit tests:

```bash
pnpm test
```

To run integration tests:

```bash
pnpm it
```

## Related Projects

* **Wallet Implementation:** For a reference OID4VC wallet implementation, see the [`wallet`](https://github.com/trustknots/vcknots/tree/main/wallet) directory in the root of this repository.
* **Server Examples:** The [`server/single`](https://github.com/trustknots/vcknots/tree/main/server/single) and [`server/multi`](https://github.com/trustknots/vcknots/tree/main/server/multi) directories provide example implementations for Issuers and Verifiers.

## Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](https://github.com/trustknots/vcknots/tree/main/CONTRIBUTING.md) for details on how to get started.

## License

[Apache-2.0](https://github.com/trustknots/vcknots/blob/main/LICENSE)
