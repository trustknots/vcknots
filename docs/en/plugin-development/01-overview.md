---
sidebar_position: 5
---

# 01. Overview

## What Is a Plugin?

A plugin is a mechanism for extending the functionality of VC Knots.

However, the terminology used for extension points differs depending on the package.

### Issuer / Verifier Features

In the `issuer+verifier` package, extension points are called `providers`.

By replacing or adding `providers`, you can customize or extend functionality such as storage, key management, DID resolution, signing, and verification.

In other words, `providers` allow you to replace peripheral implementations or extend supported functionality without modifying the core logic of VC Knots.For more information, see [Creating a Custom Provider](./03-custom-provider.md).

### Wallet Features

Documentation for the extension points of the Wallet features will be added in a future release.