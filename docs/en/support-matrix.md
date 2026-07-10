---
sidebar_position: 9
---

# VC Knots Coverage

The following tables are organized based on [OID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) and [OID4VP Draft 24](https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html).

## OID4VCI (1.0)

| Feature | Issuer | Wallet |
| --- | --- | --- |
| Pre-authorized Code flow | ✅ | ✅ |
| Authorization Code flow | ❌ | ❌ |
| Tx Code | ✅ | ✅ |
| Credential Offer | ✅ `pre-authorized_code` | ✅ `pre-authorized_code` |
| mso_mdoc format | ❌ | ❌ |
| SD-JWT-VC format (`dc+sd-jwt`) | ✅ | ✅ |
| jwt_vc_json format | ✅ | ✅ |
| Token Endpoint | ✅ | ✅ |
| Anonymous Pre-Authorized Token Request | ✅ | ✅ |
| Token Endpoint Auth Method | ✅ `private_key_jwt` | ❌ |
| Credential Endpoint | ✅ | ✅ |
| Credential Issuer Metadata | ✅ Unsigned metadata | ✅ |
| Nonce Endpoint | ✅ | ✅ |
| Deferred Credential Endpoint | ❌ | ❌ |
| Proof | ✅ JWT | ✅ |
| DPoP | ✅ | ✅ |
| Credential response encryption | ❌ | ❌ |
| Credential request encryption | ❌ | ❌ |
| Notification Endpoint | ❌ | ❌ |

## OID4VP (Draft 24)

| Feature | Verifier | Wallet |
| --- | --- | --- |
| Authorization Requests | ✅ `request_uri`, URL-encoded parameters | ✅ `request`, `request_uri`, URL-encoded parameters |
| DCQL | ✅ generate DCQL authorization requests only | ❌ |
| Presentation Exchange | ✅ | ✅ |
| Signed authorization requests (JAR) | ✅ | ✅ |
| Encrypted authorization requests (JAR) | ❌ | ❌ |
| Scoped Authorization Request | ❌ | ❌ |
| Client authentication prefixes | ✅ `redirect_uri`, `x509_san_dns`, `x509_san_uri` | ✅ `redirect_uri`, `x509_san_dns` |
| Request URI Methods | ✅ GET | ✅ GET, POST |
| Wallet metadata | ❌ | ❌ |
| Authorization Response | ✅ | ✅ |
| Authorization Error Response | ❌ | ❌ |
| Encrypted Authorization Response | ❌ | ✅ |
| Response mode | ✅ `direct_post` | ✅ `direct_post` |
| Transaction Data | ✅ | ✅ |
| Verifier Attestation JWT | ❌ | ❌ |
| Digital Credential API / DC API | ❌ | ❌ |
| SD-JWT-VC format (`dc+sd-jwt`) | ✅ | ✅ |
| SD-JWT VC Key Binding / KB-JWT | ✅ | ✅ |
| jwt_vc_json format | ✅ | ✅ |
