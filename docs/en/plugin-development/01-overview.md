---
sidebar_position: 41
---

# 01. Overview

## What Is a Plugin?

A plugin is a mechanism for extending the functionality of VC Knots.

However, the terminology used for extension points differs depending on the package.

### Issuer / Verifier Features

In the `issuer+verifier` package, extension points are called `provider`.

By replacing or adding `provider`, you can customize or extend functionality such as storage, key management, DID resolution, signing, and verification.

In other words, `provider` allow you to replace peripheral implementations or extend supported functionality without modifying the core logic of VC Knots.

For information on how to implement a custom `provider`, see [03. Creating a Custom Provider](./03-custom-provider.md).

### Wallet Features

Documentation for the extension points of the Wallet features will be added in a future release.