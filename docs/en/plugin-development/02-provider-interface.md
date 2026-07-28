---
sidebar_position: 42
---

# 02. Provider Interface Basics

In VC Knots, the `provider` interface is used to keep functional modules—such as storage, key management, DID resolution, and verification—loosely coupled while allowing them to be replaced or extended flexibly.

This chapter explains the core properties shared by all `provider` and how providers are registered and resolved.

---

## 1. Core Properties of a Provider

All `provider` in VC Knots share the following three common properties.

```ts
export type Provider = {
  kind: string
  name: string
  single: boolean
  // ... Provider-specific methods and properties
}
```

### `kind` (string)

A unique identifier that represents the **type (category)** of a `provider`.

- Examples: `'nonce-provider'`, `'did-provider'`, `'jwt-signature-provider'`
- VC Knots retrieves the required `provider` by specifying its `kind`.
- For the purpose of each `kind`, see [04. Choosing a Provider Type](./04-provider-type.md).

### `name` (string)

A unique name that identifies a specific `provider` implementation.

- Examples: `'in-memory-nonce-provider'`, `'aws-kms-signature-provider'`
- Used for logging, debugging, or identifying a specific `provider` among multiple implementations of the same `kind`.

### `single` (boolean)

Indicates whether only **one provider (Single Provider)** or **multiple providers (Multi Provider)** can coexist for the same `kind`.

| `single` | Type | Description | Typical Examples |
| --- | --- | --- | --- |
| `true` | **Single Provider** | Only one provider can be registered for the same `kind`. When a user registers a new provider, the default provider is completely replaced. | `nonce-provider`, `issuer-metadata-store-provider` |
| `false` | **Multi Provider** | Multiple providers of the same `kind` can coexist. The appropriate provider is selected dynamically using methods such as `canHandle(...)`. | `did-provider`, `issue-credential-provider` |

---

## 2. Provider Resolution and Priority

When `single: false` (Multi Provider) is used, both the default provider and user-defined providers can coexist. In this case, VC Knots determines which provider to use according to the following rules.

### Provider Resolution Rules

When providers are registered in the `ProviderRegistry`, the internal mapping is built as follows.

1. If `single: true`, any existing provider with the same `kind` is removed and replaced with the new provider.
2. If `single: false`, the new provider is added to the existing list. Newly registered providers are inserted at the beginning of the evaluation list (`[provider, ...current]`), giving them higher priority during provider selection.

When selecting an appropriate provider from multiple providers, the registry's `select(kind, value)` method is used.

```ts
// Example: Select a did-provider that can resolve "did:key:123"
const didProvider = context.providers.select('did-provider', 'did:key:123')
```

The `select` method iterates through the registered providers **from the beginning of the list** and returns the first provider whose `canHandle(value)` method returns `true`.

As a result, **user-defined providers registered later are evaluated before the default provider**. Likewise, when multiple custom Multi Providers of the same `kind` are registered, the most recently registered provider is evaluated first.