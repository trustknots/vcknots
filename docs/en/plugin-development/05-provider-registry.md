---
sidebar_position: 45
---

# 05. ProviderRegistry: Roles and Internal Mechanisms

`ProviderRegistry` is the core component of the VC Knots plugin architecture. Rather than simply storing `provider` instances, it serves as the central engine responsible for merging providers during initialization, automatically resolving dependency injection (DI), and dynamically weaving Aspect-Oriented Programming (AOP)-style extensions into providers.

This chapter explains how `ProviderRegistry` internally processes and coordinates `provider` instances, including its design and implementation behavior.

---

## 1. Initialization and Merge Behavior

When a VC Knots context is initialized (`initializeContext`), the framework merges the built-in default `provider` instances with any custom `provider` instances supplied through `options.providers`, creating a single integrated `ProviderRegistry`.

The merge process consists of the following two stages.

### 1. Flattening and Single Provider Replacement

All default and user-defined `provider` instances are combined into a single list.

- **`single: true` (Single Provider)**: If another `provider` with the same `kind` already exists, it is completely replaced by the newly registered `provider`.
- **`single: false` (Multi Provider)**: Existing `provider` instances are preserved, allowing multiple implementations of the same `kind` to coexist.

### 2. Indexing and Multi Provider Priority

For Multi Providers, VC Knots determines the order in which providers will be evaluated.

- Newly merged providers (typically user-defined providers registered later) are inserted **at the beginning of the resolution list**.
- As a result, custom implementations are automatically evaluated before the default implementations.

---

## 2. ProviderRegistry Methods

`ProviderRegistry` exposes two primary methods to both application code and other `provider` instances.

### `get(kind)`

Returns the registered `provider` for the specified `kind`.

- For **Single Providers (`single: true`)**, returns the single registered provider instance.
- For **Multi Providers (`single: false`)**, returns an array of providers ordered by evaluation priority (newest first).

### `select(kind, value)`

Selects the most appropriate provider from a Multi Provider collection according to a runtime condition.

#### Dynamic Resolution Flow

1. Retrieve the list of Multi Providers for the specified `kind`.
2. Iterate through the providers from highest to lowest priority.
3. Call `canHandle(value)` on each provider.
4. Return the first provider whose `canHandle(value)` returns `true`.
5. If no provider matches, a resolution error is thrown.

This mechanism allows custom providers to take precedence while automatically falling back to the default provider when appropriate.

---

## 3. Dependency Injection and Lazy Resolution

When multiple `provider` instances collaborate, developers do not need to manually wire dependencies together. `ProviderRegistry` automatically injects itself into providers when necessary.

### The `withProviderRegistry` Helper

To indicate that a custom `provider` supports automatic dependency injection, VC Knots provides the `withProviderRegistry` helper.

When implementing a custom provider, it is recommended to spread this helper into the returned object and combine it with the `WithProviderRegistry` type.

```ts
import { WithProviderRegistry, withProviderRegistry } from '@trustknots/vcknots'

export const customProvider = (): MyProvider & WithProviderRegistry => {
  return {
    ...withProviderRegistry, // Expands the providers placeholder
    kind: 'my-provider',
    name: 'custom-provider',
    single: true,
    // ...
  }
}
```

### Automatic Injection Behavior

Whenever a provider is retrieved through `ProviderRegistry` (`get()` or `select()`), the registry performs the following steps.

- It checks whether the provider contains a `provider` property supplied by `withProviderRegistry`.
- If present, it injects the current `ProviderRegistry` instance into that property.

This design provides several advantages.

1. **Avoiding Circular Dependencies**

   Even if Provider A depends on Provider B and Provider B also depends on Provider A, both can be safely initialized without dependency ordering issues.

2. **Lazy Resolution**

   Other providers are resolved only when they are actually needed. This reduces initialization overhead and always retrieves the latest active provider instance, even after providers have been replaced.

As a result, provider implementations can simply call `this.providers.get('other-provider')` or `this.providers.select(...)` to safely access any other registered provider.

---

## 4. Extension Weaving

VC Knots provides an **Extension** mechanism that injects cross-cutting concerns—such as logging, auditing, exception handling, or performance measurement—before or after provider method execution without modifying the provider implementation itself.

`ProviderRegistry` performs this weaving process immediately before returning a provider.

### Example: How Weaving Works

The following example defines an extension that logs issuer metadata whenever it is retrieved.

```ts
import { CredentialIssuer, CredentialIssuerMetadata } from '../credential-issuer.types'
import { Extension } from './extension.types'

export const traceFetchedIssuerMetadata = (): Extension<
  CredentialIssuer,
  Promise<CredentialIssuerMetadata | null>
> => {
  return {
    // Target provider method
    on: 'issuer-store-metadata-provider.fetch',

    // Interceptor logic
    async intercept(original, xs) {
      const issuer = await original(xs)

      if (issuer) {
        console.log(JSON.stringify(issuer, null, '\t'))
      }

      return issuer
    },
  }
}
```

Once this extension is registered, `ProviderRegistry` automatically performs the following steps.

1. **Monitor Provider Retrieval**

   When application code calls `context.providers.get('issuer-store-metadata-provider')`, the registry checks all registered extensions.

2. **Generate a Wrapper (Weaving)**

   If an extension targets `issuer-store-metadata-provider.fetch`, the registry creates a wrapper around the original `fetch()` method instead of returning the original provider directly.

3. **Execute Transparently**

   When `fetch()` is invoked, the extension's `intercept()` method executes automatically, calls the original implementation, writes the JSON log, and returns the original result.

### Benefits for Developers

Because weaving is handled transparently by `ProviderRegistry`, neither provider authors nor application developers need to write any special integration code.

- **Provider developers** can focus solely on implementing business logic such as DID resolution or metadata storage without embedding logging, monitoring, or auditing logic.
- **Application developers** simply use providers through the normal interfaces, while all registered extensions are automatically and transparently applied.