---
sidebar_position: 21
---

# VC Knots Coverage

The following tables are organized based on [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) and [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), and describe the current implementation scope of this repository.

`✅` means that the feature is implemented for the relevant role. `❌` means that it is not implemented or is not available end to end. Conditions for configuration-dependent features are described in the notes column. `⏳` denotes pending test confirmation.

## OpenID for Verifiable Credential Issuance 1.0

| Specification section | Functional area | Specification role / feature | Issuer | Wallet | Notes |
| --- | --- | --- | --- | --- | --- |
| [3.5](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.5) | Issuance Flow | Pre-Authorized Code Flow | Since `v0.6.0`<br />✅ | ✅ | Current standard flow. |
| [3.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.4) | Issuance Flow | Authorization Code Flow | ❌ | ❌ | Not supported end to end. |
| [4.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1) | Credential Offer | `credential_offer` (Pre-Authorized Code) | Since `v0.6.0`<br />✅ Generate | ✅ Parse | Reference-based `credential_offer_uri` is not supported. |
| [3.5](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.5) | Transaction Code | `tx_code` | Since `v0.6.0`<br />✅ Issue / validate | ✅ Send | Used in the Pre-Authorized Code Flow. |
| [A.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1) | Credential Format | `jwt_vc_json` | Since `v0.6.0`<br />✅ Issue | ✅ Receive | |
| [A.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.3) | Credential Format | `dc+sd-jwt` (SD-JWT VC) | Since `v0.6.0`<br />✅ Issue | ✅ Receive | |
| [A.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-mobile-documents-or-mdocs-i) | Credential Format | `mso_mdoc` | ❌ | ❌ | |
| [6](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6) | Token Endpoint | Access Token issuance | Since `v0.6.0`<br />✅ | ✅ | Supports the Pre-Authorized Code Flow. |
| [13.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.2) | Client Authentication | `private_key_jwt` | Since `v0.6.0`<br />✅ Validate | ✅ Send | Client authentication method for registered OAuth clients at the Token Endpoint. The wallet defaults to anonymous (`none`); it sends a client assertion only when the wallet is configured for `private_key_jwt` and the Authorization Server Metadata advertises both `private_key_jwt` and the configured signing algorithm. Related section: [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) |
| [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) | Client Authentication | Anonymous Pre-Authorized Token Request | Since `v0.6.0`<br />✅ Conditional | ✅ Send | Available only when `pre-authorized_grant_anonymous_access_supported` is `true` in the Authorization Server Metadata. Related section: [12.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.3) |
| [13.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.2) | Sender Constraint | DPoP sender-constrained Access Token | Since `v0.6.0`<br />✅ | ✅ | Configurable as `off`, `optional`, or `required`. Applied to the Token Endpoint and Credential Endpoint. Related sections: [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1), [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2), [8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2). External spec: [RFC 9449](https://www.rfc-editor.org/info/rfc9449) |
| [8](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8) | Credential Endpoint | Credential Request / Response | Since `v0.6.0`<br />✅ | ✅ |  |
| [8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2) | Credential Proof | JWT Proof | Since `v0.6.0`<br />✅ Validate | ✅ Generate | Proof of possession of the key for the Credential. Only a single Proof is currently supported. |
| [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2) | Nonce | OpenID4VCI `c_nonce` | Since `v0.6.0`<br />✅ Issue | ✅ Retrieve / use | Credential Proof nonce returned in the JSON body of `POST /nonce`. |
| [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2) | Nonce | DPoP-Nonce | Since `v0.6.0`<br />✅ Conditional | ✅ Conditional | Response header used for the DPoP challenge. It is a different value from `c_nonce`. External spec: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) |
| [12.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2) | Metadata | Credential Issuer Metadata | Since `v0.6.0`<br />✅ Unsigned JSON | ✅ Retrieve | Signed Metadata is not supported. |
| [6.1.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1.1) | Credential Selection | `authorization_details` | ❌ | ❌ | Not supported end to end in Token Requests / Responses. |
| [3.3.4](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.4) | Credential Selection | `credential_identifier` | ❌ | Partial | `credential_identifiers` integration in the Token Response is not supported. Related section: [6.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2) |
| [3.3.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.2) | Credential Issuance | Batch Credential Issuance | ❌ | ❌ |  |
| [9](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9) | Credential Issuance | Deferred Credential Endpoint | ❌ | ❌ |  |
| [10](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10) | Encryption | Credential Request encryption | ❌ | ❌ |  |
| [10](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10) | Encryption | Credential Response encryption | ❌ | ❌ |  |
| [11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11) | Notification | Notification Endpoint | ❌ | ❌ |  |

## OpenID for Verifiable Presentations 1.0

| Specification section | Functional area | Specification role / feature | Verifier | Wallet | Notes |
| --- | --- | --- | --- | --- | --- |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | Authorization Request | Since `v0.7.0`<br />✅ `request_uri`, URL-encoded parameters | ⏳ `request`, `request_uri`, URL-encoded parameters |  |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | Signed Authorization Request (JAR) | Since `v0.7.0`<br />✅ | ⏳ | Uses a Request Object. External spec: [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | Encrypted Authorization Request (JAR) | ❌ | ❌ | External spec: [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html) |
| [5.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.5) | Credential Query | Authorization Request using `scope` | ❌ | ❌ | |
| [5.9.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3) | Client Identification | Client Identifier Prefix | Since `v0.7.0`<br />✅ `redirect_uri`, `x509_san_dns` | ⏳ `redirect_uri`, `x509_san_dns` |  |
| [5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10) | Request URI | Request URI Method | Since `v0.7.0`<br />✅ GET | ⏳ GET, POST |  |
| [6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l) | Credential Query | DCQL | Since `v0.7.0`<br />✅ | ⏳ | Uses `dcql_query` parameter. |
| [8.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1) | Authorization Response | Authorization Response | Since `v0.7.0`<br />✅ | ⏳ |  |
| [8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2) | Response Mode | Response Mode | Since `v0.7.0`<br />✅ `direct_post` | ⏳ `direct_post` |  |
| [8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3) | Authorization Response | Encrypted Authorization Response | ❌ | ⏳ |  |
| [8.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4) | Transaction Data | Transaction Data | Since `v0.7.0`<br />✅ | ⏳ | Supported for `dc+sd-jwt` only. |
| [8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.5) | Authorization Response | Authorization Error Response | ❌ | ❌ | |
| [10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10) | Metadata | Wallet Metadata | ❌ | ❌ | |
| [11](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-11) | Metadata | Verifier Metadata — `client_metadata` | Since `v0.7.0`<br />✅ | ⏳ Parse |  |
| [12](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12) | Client Authentication | Verifier Attestation JWT | ❌ | ❌ | |
| [Appendix A](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A) | Digital Credentials API | Digital Credentials API / DC API | ❌ | ❌ | |
| [Appendix B.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1) | Credential Format | `jwt_vc_json` format | Since `v0.7.0`<br />✅ | ⏳ |  |
| [Appendix B.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2) | Credential Format | `mso_mdoc` (Mobile Documents / mdocs) | ❌ | ❌ | |
| [Appendix B.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3) | Credential Format | SD-JWT VC format (`dc+sd-jwt`) | Since `v0.7.0`<br />✅ | ⏳ |  |
| [Appendix B.3.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.6) | Holder Binding | SD-JWT VC Key Binding / KB-JWT | Since `v0.7.0`<br />✅ | ⏳ |  |
