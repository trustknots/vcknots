---
sidebar_position: 44
---

# 04. Choosing a Provider

This section explains which `provider` you should replace or extend depending on the functionality you want to customize.

## Provider Kind Reference

| What you want to customize | Provider kind |
| --- | --- |
| Change how Issuer metadata is stored and retrieved | [`issuer-metadata-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20issuer-metadata-store-provider&type=code) |
| Change how Authorization Server metadata is stored and retrieved | [`authz-server-metadata-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-server-metadata-store-provider&type=code) |
| Change how Verifier metadata is stored and retrieved | [`verifier-metadata-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verifier-metadata-store-provider&type=code) |
| Change how OAuth client information is stored and retrieved | [`authz-oauth-client-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-oauth-client-store-provider&type=code) |
| Change how OAuth policies are stored and retrieved | [`authz-oauth-policy-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-oauth-policy-store-provider&type=code) |
| Change how Pre-Authorized Codes are generated | [`pre-authorized-code-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20pre-authorized-code-provider&type=code) |
| Change how Pre-Authorized Codes are stored and consumed | [`pre-authorized-code-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20pre-authorized-code-store-provider&type=code) |
| Change how Access Token payloads are generated | [`access-token-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20access-token-provider&type=code) |
| Change how the available `credential_configuration_id` values for each Access Token are stored and retrieved | [`allowed-credential-configuration-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20allowed-credential-configuration-store-provider&type=code) |
| Change how Credential Offers are generated | [`credential-offer-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20credential-offer-provider&type=code) |
| Change how `c_nonce` values are generated | [`nonce-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20nonce-provider&type=code) |
| Change how `c_nonce` values are stored, validated, expired, and consumed | [`nonce-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20nonce-store-provider&type=code) |
| Change DPoP Proof JWT verification | [`dpop-proof-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20dpop-proof-provider&type=code) |
| Change how `jti` values used for DPoP Proof replay prevention are stored | [`dpop-proof-jti-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20dpop-proof-jti-store-provider&type=code) |
| Change how `jti` values used for Client Assertion replay prevention are stored | [`oauth-client-assertion-jti-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20oauth-client-assertion-jti-store-provider&type=code) |
| Change how Issuer signing keys are stored, retrieved, and used for signing | [`issuer-signature-key-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20issuer-signature-key-store-provider&type=code) |
| Change how Authorization Server signing keys are stored, retrieved, and used for signing | [`authz-signature-key-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-signature-key-store-provider&type=code) |
| Change how Verifier signing keys are stored, retrieved, and used for signing | [`verifier-signature-key-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verifier-signature-key-store-provider&type=code) |
| Change how Issuer signing keys are generated | [`issuer-signature-key-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20issuer-signature-key-provider&type=code) |
| Change how Authorization Server signing keys are generated | [`authz-signature-key-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-signature-key-provider&type=code) |
| Change how Verifier signing keys are generated | [`verifier-signature-key-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verifier-signature-key-provider&type=code) |
| Change JWT signature verification | [`jwt-signature-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20jwt-signature-provider&type=code) |
| Add or customize DID resolution for specific DID methods | [`did-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20did-provider&type=code) |
| Add or customize proof verification for Credential Requests | [`credential-proof-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20credential-proof-provider&type=code) |
| Add or customize credential issuance for specific credential formats | [`issue-credential-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20issue-credential-provider&type=code) |
| Add or customize Verifiable Credential verification | [`verify-verifiable-credential-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verify-verifiable-credential-provider&type=code) |
| Add or customize Verifiable Presentation verification | [`verify-verifiable-presentation-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verify-verifiable-presentation-provider&type=code) |
| Change Holder Binding verification | [`holder-binding-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20holder-binding-provider&type=code) |
| Add or customize Credential Query generation | [`credential-query-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20credential-query-provider&type=code) |
| Change how Request Objects are stored, retrieved, and deleted | [`request-object-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20request-object-store-provider&type=code) |
| Change how Request Object IDs are generated | [`request-object-id-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20request-object-id-provider&type=code) |
| Add or customize JAR generation for Authorization Requests | [`authz-request-jar-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20authz-request-jar-provider&type=code) |
| Change how certificates associated with Verifiers are stored and retrieved | [`verifier-certificate-store-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20verifier-certificate-store-provider&type=code) |
| Change certificate validation or public key extraction from certificates | [`certificate-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20certificate-provider&type=code) |
| Change how Transaction Codes are generated | [`transaction-code-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20transaction-code-provider&type=code) |
| Change how Transaction Data is generated | [`transaction-data-provider`](https://github.com/search?q=repo%3Atrustknots%2Fvcknots%20transaction-data-provider&type=code) |
