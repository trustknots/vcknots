---
sidebar_position: 7
---

# 03. Creating a Custom Provider

This chapter explains how to create a custom `provider` and integrate it into VC Knots.

The basic workflow is as follows.

1. Install VC Knots in your project.
2. Implement a custom `provider`.
3. Register it in `VcknotsOptions.providers`.
4. Verify its behavior through testing.

This chapter introduces representative examples of both `single: true` and `single: false` providers.

## Preparing to Create a Provider

Create a project that uses VC Knots (and implements custom `provider`s), then install VC Knots.

```bash
npm install @trustknots/vcknots
```

The following is an example project structure.

```text
my-vcknots-plugin/
├── package.json
├── tsconfig.json
├── src/
│   ├── providers/
│   │   ├── timestamp-nonce.provider.ts // Single Provider example
│   │   └── did-web.provider.ts         // Multi Provider example
│   ├── index.ts
│   └── main.ts
└── test/
    ├── timestamp-nonce.provider.test.ts
    └── integration.test.ts
```

Each file has the following responsibility.

| File | Description |
|------|-------------|
| `src/providers/` | Custom `provider` implementations |
| `src/index.ts` | Entry point for exporting your plugin package |
| `src/main.ts` | Initializes VC Knots by calling `initializeContext()` |
| `test/` | Unit Tests and Integration Tests |

## Example of a Single Provider

A `single: true` provider allows only one provider to be registered for the same `kind`.

If another provider with the same `kind` is registered in `VcknotsOptions.providers`, the default provider is replaced by the newly registered provider.

### Use Case

The `nonce-provider` generates the `c_nonce` used in OID4VCI.

For example, by including a timestamp in the generated `c_nonce`, you can generate identifiers that are easier to sort chronologically in an external database.

It can also be used to integrate an external random number generator or replace the random generation algorithm with one that complies with your organization's standards.

### Implementation Example

```ts
import { randomUUID } from 'node:crypto'
import { Nonce } from '../nonce.types'
import { NonceProvider } from './provider.types'

const DEFAULT_NONCE_EXPIRES_IN_MS = 60 * 5 * 1000 // 5 minutes

export const timestampNonce = (): NonceProvider => {
  return {
    kind: 'nonce-provider',
    name: 'timestamp-nonce-provider',
    single: true,

    async generate(options?: { nonce_expires_in?: number }): Promise<Nonce> {
      const timestamp = Date.now()
      const uuid = randomUUID().replaceAll('-', '')

      return Nonce({
        nonce: `${timestamp}-${uuid}`,
        nonce_expires_in:
          options?.nonce_expires_in ?? DEFAULT_NONCE_EXPIRES_IN_MS,
      })
    },
  }
}
```

For details about provider registration, see [How to Set Up and Use the Issuer Feature](../issuer.md).

### Registration Example

```ts
import { initializeContext } from '@trustknots/vcknots'

const context = initializeContext({
  providers: [
    timestampNonce(),
  ],
})
```

After registration, this provider is used instead of the default `nonce-provider`.

## Example of a Multi Provider

A `single: false` provider allows multiple providers to be registered for the same `kind`.

Additional providers coexist with the default provider rather than replacing it.

When resolving providers of the same `kind`, providers registered later are evaluated first. If none of them can handle the request, the default provider is used.

### Use Case

The `did-provider` supports DID resolution for the `did:key` method by default. By registering an additional provider, you can add support for other DID methods such as `did:web`.

There is no need to remove the default `did-provider`; Multi Providers are designed to extend the set of supported implementations rather than replace existing ones.

If you need to provide custom behavior, implement a provider according to the interface, just as you would for a Single Provider, and register it in `VcknotsOptions.providers`.

### Implementation Example

```ts
import { DidDocument } from '../did.types'
import { DidProvider } from './provider.types'

export const didWeb = (): DidProvider => {
  return {
    kind: 'did-provider',
    name: 'did-web-provider',
    single: false,

    async resolveDid(did: string): Promise<DidDocument | null> {
      // Build the target URL from the did:web identifier
      // and retrieve the DID Document.
      const response = await fetch(
        `https://example.com`
      )

      const document = await response.json()

      // Implement validation for the retrieved DID Document.

      return document as DidDocument
    },

    canHandle(method: string): boolean {
      return method === 'web'
    },
  }
}
```

### Registration Example

```ts
import { initializeContext } from '@trustknots/vcknots'

const context = initializeContext({
  providers: [
    didWeb(),
  ],
})
```

## Collaboration Between Providers

Providers can collaborate with one another.

If a registered provider instance exposes a `provider` property, VC Knots automatically injects its `ProviderRegistry` instance into that property.

This allows custom providers to retrieve and use other registered providers (such as `did-provider` and `jwt-signature-provider`) from within their own implementation.

### Recommended Implementation Pattern

If your custom provider needs to collaborate with other providers, it is recommended to implement it as a factory function that spreads `withProviderRegistry`, as shown below.

```ts
import {
  WithProviderRegistry,
  withProviderRegistry,
  selectProvider,
} from '@trustknots/vcknots'

// Define the provider as a factory function.
export const myCustomProvider = (): MyCustomProvider & WithProviderRegistry => {
  return {
    ...withProviderRegistry, // Expands the placeholder for the automatically injected providers

    kind: 'some-custom-provider',
    name: 'my-custom-provider',
    single: true,

    async doSomething() {
      // Retrieve another provider (for example, a DID provider)
      // from the injected ProviderRegistry.
      const didProvider = selectProvider(
        this.providers.get('did-provider'),
        'key'
      )

      const didDocument = await didProvider.resolveDid('did:example:123')

      // Perform processing in collaboration with the retrieved provider.
      // ...
    }
  }
}
```

This pattern lets you define the initial placeholder for the automatically injected `provider` property in a type-safe manner while keeping your provider loosely coupled with other providers, such as those responsible for DID resolution and key management.

For more information about `ProviderRegistry`, see [05. ProviderRegistry: Roles and Internal Mechanisms](./05-provider-registry.md).

## Testing

When implementing a custom provider, it is recommended to perform both Unit Tests and Integration Tests.

### Unit Test

Verify the provider's standalone behavior, including expected outputs and error handling.

### Integration Test

Register the provider in VC Knots and verify that it behaves as expected as part of the Issuer and Verifier workflows.