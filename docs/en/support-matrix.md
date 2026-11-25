---
sidebar_position: 21
---

# VC Knots Coverage

The following tables are organized based on [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) and [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), and describe the current implementation scope of this repository.

`✅` means that the feature is implemented for the relevant role. `❌` means that it is not implemented or is not available end to end. Conditions for configuration-dependent features are described in the notes column. In the Wallet column of the OpenID for Verifiable Presentations table, `✅` marks a feature that is implemented at least in part, followed by the implemented values or properties where there are any to list, and `❌` means that nothing of the feature is implemented. Deviations from the specification, limitations and conditions are described in the notes column.

In the notes column of the OpenID for Verifiable Presentations table, a note that starts with `[Verifier]` or `[Wallet]` applies to that role only, and a note without a label applies to both roles. Longer Wallet notes are given in [Wallet notes](#oid4vp-wallet-notes) below that table, and their rows link to them.

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
| [13.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.2) | Client Authentication | `private_key_jwt` | Since `v0.6.0`<br />✅ Validate | ✅ Send | Client authentication method for registered OAuth clients at the Token Endpoint. The wallet supports only `private_key_jwt` and `none` (the default); `client_secret_basic` is not implemented, so an Authorization Server that omits `token_endpoint_auth_methods_supported` cannot be used (RFC 8414 section 2). Related section: [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) |
| [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) | Client Authentication | Anonymous Pre-Authorized Token Request | Since `v0.6.0`<br />✅ Conditional | ✅ Send | The wallet omits `client_id` only when the Authorization Server Metadata sets `pre-authorized_grant_anonymous_access_supported` to `true`, whose default is `false`. Otherwise it sends `client_id`, and returns an error before sending when none is configured. Related section: [12.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.3) |
| [13.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.2) | Sender Constraint | DPoP sender-constrained Access Token | Since `v0.6.0`<br />✅ | ✅ | Related sections: [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1), [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2), [8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2). External spec: [RFC 9449](https://www.rfc-editor.org/info/rfc9449) |
| [8](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8) | Credential Endpoint | Credential Request / Response | Since `v0.6.0`<br />✅ | ✅ |  |
| [8.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2) | Credential Proof | JWT Proof | Since `v0.6.0`<br />✅ Validate | ✅ Generate | Only a single Proof is currently supported. The wallet omits `iss` only for an anonymous Pre-Authorized Token Request. Related section: [6.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1) |
| [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2) | Nonce | OpenID4VCI `c_nonce` | Since `v0.6.0`<br />✅ Issue | ✅ Retrieve / use | Credential Proof nonce returned in the JSON body of `POST /nonce`. |
| [7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2) | Nonce | DPoP-Nonce | Since `v0.6.0`<br />✅ Conditional | ✅ Conditional | External spec: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) |
| [12.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2) | Metadata | Credential Issuer Metadata | Since `v0.6.0`<br />✅ Unsigned JSON | ✅ Retrieve | Signed Metadata is not supported. The wallet rejects metadata whose `credential_issuer` does not match the Credential Offer. |
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
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | Authorization Request | Since `v0.7.0`<br />✅ `request_uri`, URL-encoded parameters | ✅ `request`, `request_uri`, URL-encoded parameters | [Wallet] [Details](#wallet-authorization-request) |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | Signed Authorization Request (JAR) | Since `v0.7.0`<br />✅ | ✅ `request`, `request_uri` | Uses a Request Object. External spec: [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html)<br />[Wallet] [Details](#wallet-signed-request) |
| [5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5) | Authorization Request | Encrypted Authorization Request (JAR) | ❌ | ❌ | External spec: [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101.html)<br />[Wallet] An encrypted Request Object is refused, since the Wallet cannot decrypt one. |
| [5.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.5) | Credential Query | Authorization Request using `scope` | ❌ | ❌ | [Wallet] A request carrying a `scope` other than an empty string is refused with `invalid_scope`. Credentials can be requested only with `dcql_query`. |
| [5.9.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3) | Client Identification | Client Identifier Prefix | Since `v0.7.0`<br />✅ `redirect_uri`, `x509_san_dns` | ✅ `redirect_uri`, `x509_san_dns` | [Wallet] [Details](#wallet-client-identifier-prefix) |
| [5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10) | Request URI | Request URI Method | Since `v0.7.0`<br />✅ GET | ✅ GET, POST | [Wallet] [Details](#wallet-request-uri-method) |
| [6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l) | Credential Query | DCQL | Since `v0.7.0`<br />✅ | ✅ `credentials`, `credential_sets`, `claims`, `claim_sets`, `meta.vct_values` | Uses `dcql_query` parameter.<br />[Wallet] [Details](#wallet-dcql) |
| [8.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1) | Authorization Response | Authorization Response | Since `v0.7.0`<br />✅ | ✅ `vp_token`, `state` | [Wallet] [Details](#wallet-authorization-response) |
| [8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2) | Response Mode | Response Mode | Since `v0.7.0`<br />✅ `direct_post` | ✅ `direct_post` | [Wallet] [Details](#wallet-response-mode) |
| [8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3) | Authorization Response | Encrypted Authorization Response | ❌ | ✅ `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW` | [Wallet] [Details](#wallet-encrypted-response) |
| [8.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4) | Transaction Data | Transaction Data | Since `v0.7.0`<br />✅ | ✅ `dc+sd-jwt` | Supported for `dc+sd-jwt` only.<br />[Wallet] [Details](#wallet-transaction-data) |
| [8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.5) | Authorization Response | Authorization Error Response | ❌ | ✅ `invalid_request`, `invalid_scope`, `vp_formats_not_supported`, `invalid_transaction_data`, `access_denied` | [Wallet] [Details](#wallet-error-response) |
| [10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10) | Metadata | Wallet Metadata | ❌ | ❌ | [Wallet] No metadata is published, and no `wallet_metadata` is sent when a Request Object is fetched with `request_uri_method=post` (Section 5.10). |
| [11](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-11) | Metadata | Verifier Metadata — `client_metadata` | Since `v0.7.0`<br />✅ | ✅ `jwks` | [Wallet] [Details](#wallet-verifier-metadata) |
| [12](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12) | Client Authentication | Verifier Attestation JWT | ❌ | ❌ | [Wallet] A request whose Client Identifier uses the `verifier_attestation` prefix is refused. |
| [Appendix A](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A) | Digital Credentials API | Digital Credentials API / DC API | ❌ | ❌ | [Wallet] The Wallet is invoked only with an Authorization Request URI and offers no Digital Credentials API entry point. The reserved `origin` Client Identifier Prefix is refused, as Section 5.9.3 requires. |
| [Appendix B.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1) | Credential Format | `jwt_vc_json` format | Since `v0.7.0`<br />✅ | ✅ | [Wallet] [Details](#wallet-jwt-vc-json) |
| [Appendix B.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2) | Credential Format | `mso_mdoc` (Mobile Documents / mdocs) | ❌ | ❌ | [Wallet] A request containing a Credential Query for this format is refused with `vp_formats_not_supported` (see [DCQL](#wallet-dcql)). |
| [Appendix B.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3) | Credential Format | SD-JWT VC format (`dc+sd-jwt`) | Since `v0.7.0`<br />✅ | ✅ | [Verifier] Only ES256 is supported as the signing algorithm. |
| [Appendix B.3.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.6) | Holder Binding | SD-JWT VC Key Binding / KB-JWT | Since `v0.7.0`<br />✅ | ✅ | [Verifier] Only ES256 is supported as the signing algorithm.<br />[Wallet] [Details](#wallet-key-binding) |

### Wallet notes {#oid4vp-wallet-notes}

How the Wallet implements the rows that link here: deviations from the specification, limitations and conditions.

#### 5 Authorization Request {#wallet-authorization-request}

- Unrecognized parameters are ignored (Section 5), but `presentation_definition`, `presentation_definition_uri` and `presentation_submission` are refused with `invalid_request`.
- A request passed as URL-encoded parameters that repeats a parameter is refused without an error response.
- A Request Object passed with `request` or `request_uri` has to be signed with ES256 or RS256 (see [Signed Authorization Request (JAR)](#wallet-signed-request)).

#### 5 Signed Authorization Request (JAR) {#wallet-signed-request}

- A Request Object is accepted only when it is signed and uses the `x509_san_dns` Client Identifier Prefix (see [Client Identifier Prefix](#wallet-client-identifier-prefix)).
- The `typ` header has to be `oauth-authz-req+jwt`, and the `iss` claim is ignored (Section 5).
- The `x5c` certificate chain is validated, including the validity periods, against `Oid4vpPresenter.X509TrustChainRoots`, or against the system trust store when that field is unset, as it is by default. A leaf certificate whose Extended Key Usage does not include `serverAuth` is refused.
- Revocation is checked for each certificate in the chain, through the OCSP responders it names or, when it names none, through its CRL distribution points. With OCSP, the first valid and current `good` or `revoked` answer decides, and the request is refused when no responder gives one. Without OCSP, the request is refused unless every distribution point serves a current CRL signed by the issuer that does not list the certificate.
- Setting `Oid4vpPresenter.InsecureSkipX509Verify`, which is meant for testing only, skips the chain validation and the revocation check.
- The signature is verified with the leaf certificate's key. The Request Object is refused when `exp` has passed or `nbf` or `iat` lies in the future, allowing one minute of clock skew.
- The `client_id` query parameter is not compared with the Request Object's `client_id` claim, although RFC 9101 Section 6.3 requires the two to be identical, as Section 5.10.1 repeats for a Request Object fetched with `request_uri_method=post`. A Request Object sent without a `client_id` query parameter is accepted as well.

#### 5.9.3 Client Identifier Prefix {#wallet-client-identifier-prefix}

- `x509_san_dns`: a Request Object is accepted only when its Client Identifier without the prefix matches a dNSName SAN of the leaf certificate in `x5c`, and the host of its `response_uri` equals that value (Sections 5.9.3 and 8.2).
- `redirect_uri`: a Request Object whose `client_id` claim uses this prefix is refused (Section 5.9.3). With `response_mode=direct_post`, `response_uri` is required, although Section 5.9.3 lets the Verifier omit it.
- A request passed as URL-encoded parameters is not authenticated, whatever its Client Identifier Prefix.
- A `client_id` without a prefix is refused, since the Wallet has no pre-registered clients (Section 5.9.2).
- A Client Identifier using `decentralized_identifier`, `verifier_attestation`, `x509_hash`, `openid_federation` or an unrecognized prefix is refused, and so is a Request Object whose certificate or `response_uri` does not match its Client Identifier. Neither refusal is sent to the Verifier, although Section 8.5 defines `invalid_request` for both. A request passed as URL-encoded parameters with one of the four prefixes named here can still get an error response for another check (see [Authorization Error Response](#wallet-error-response)).

#### 5.10 Request URI Method {#wallet-request-uri-method}

- Without `request_uri_method`, `request_uri` is fetched with GET. With `post`, the Wallet sends a POST with an empty body, passing neither `wallet_metadata` nor `wallet_nonce` (both optional, Section 5.10).
- `request_uri` has to be an `https` URL. An `http` URL is accepted as well when `VCKNOTS_WALLET_HTTP_ALLOWED` or `VCKNOTS_WALLET_DEBUG` is `true`.
- An HTTP error response ends the request (Section 5.10.2). The content type of the response is not checked, although Section 5.10.1 requires `application/oauth-authz-req+jwt` for the response to a `post` request.
- `request_uri_method` is accepted in any letter case, and an empty value is taken as `get`, although Section 5.1 defines only `get` and `post`, both case-sensitive. Any other value is refused without `invalid_request_uri_method` (Section 8.5).

#### 6 DCQL {#wallet-dcql}

- Supported formats are `dc+sd-jwt` and `jwt_vc_json`. A request with a Credential Query for any other format, such as `mso_mdoc`, is refused with `vp_formats_not_supported`, even when the request could be answered without that query. A malformed query is refused with `invalid_request`, although `meta` is checked only for being an object, and `trusted_authorities` and the `values` of a Claims Query are not checked at all.
- The Wallet answers exactly one Credential Query with exactly one Credential, and ignores `multiple`.
- With `credential_sets`, the Wallet takes the option that lets one Credential answer every required set. An option is passed over for the next one when none of the held Credentials matching it can disclose the requested claims, or when not every transaction data entry references it. The request is refused only when no option is left: with `invalid_transaction_data` when the first option passed over was one the transaction data does not reference, and with `access_denied` otherwise. When no option was passed over and only more than one Credential could answer the request, no error response is sent (see [Authorization Response](#wallet-authorization-response)).
- For `dc+sd-jwt`, the Wallet matches `meta.vct_values` and discloses only the requested `claims`. It presents the most recently stored Credential that can deliver them, with the first `claim_sets` option that Credential can satisfy. Only a Credential that cannot disclose a requested claim is passed over for an older one. `jwt_vc_json` Credentials match on `format` alone and are presented whole.
- A `dc+sd-jwt` Credential Query without `vct_values`, which Appendix B.3.5 makes REQUIRED, matches any held `dc+sd-jwt` Credential. One whose `vct_values` is empty or not an array matches none, so a request that needs it is refused with `access_denied` rather than `invalid_request`.
- `trusted_authorities` (Section 6.1) and the `values` of a Claims Query are ignored: a requested claim is disclosed whatever its value (Section 6.4.1).
- `require_cryptographic_holder_binding` alone does not make the Wallet attach a Key Binding JWT (see [SD-JWT VC Key Binding](#wallet-key-binding)).

#### 8.1 Authorization Response {#wallet-authorization-response}

- `vp_token` is a JSON object with a single entry, keyed by the id of the Credential Query answered and holding an array of one Presentation. `state` is included when the request carried one.
- `response_type` is required, but its value is not checked. `vp_token` is returned in the Authorization Response whatever the value, so `code` and `vp_token id_token` (Section 8) are not supported.
- When answering the DCQL query takes more than one Credential, no `vp_token` is sent. An error response is sent only when the request is also refused for another reason, such as `access_denied` for a Credential the Wallet does not hold. OID4VP defines no error code for this limitation itself.

#### 8.2 Response Mode {#wallet-response-mode}

- The Authorization Response is posted to `response_uri` as `application/x-www-form-urlencoded`, and an HTTP error response is treated as a failure.
- `response_uri` has to be an `https` URL. The check is turned off when `VCKNOTS_WALLET_HTTP_ALLOWED` or `VCKNOTS_WALLET_DEBUG` is `true`.
- A request carrying `redirect_uri` alongside `response_uri` is refused with `invalid_request`.
- A `redirect_uri` the Response URI returns for a successful response is returned to the caller and passed to `PresentCredentialOptions.OnRedirect`. The Wallet does not open it itself, so the application has to redirect the user agent to it (Section 8.2).
- A `redirect_uri` returned for an Authorization Error Response is discarded, although Section 8.2 requires the Wallet to redirect the user agent to it as well.
- Other Response Modes, such as `fragment`, `query` and `direct_post.jwt`, are not supported.

#### 8.3 Encrypted Authorization Response {#wallet-encrypted-response}

- Encryption follows JARM client metadata rather than Section 8.3. The Wallet encrypts only when `client_metadata` carries `authorization_encrypted_response_alg` and `authorization_encrypted_response_enc`, JARM members that OID4VP 1.0 does not use. It then sends an unsigned JWE carrying `vp_token`, and `state` when the request carried one, in the `response` parameter.
- With `authorization_encrypted_response_alg` alone, with an `alg` the Wallet column does not list, or without a key in `client_metadata.jwks`, the presentation fails and nothing is sent.
- The JWE `alg` and `enc` are taken from those two members, not from the `alg` of the chosen JWK or from `encrypted_response_enc_values_supported`, and `A128GCM` is not applied as the default.
- The key is the first one in `client_metadata.jwks` whose `use` is `enc`, or the first key when none is, and its `kid` goes into the JWE header.
- The Response Mode `direct_post.jwt` (Section 8.3.1) is not supported.

#### 8.4 Transaction Data {#wallet-transaction-data}

- `invalid_transaction_data` is returned in these cases:
  - a type has neither an entry in `Oid4vpPresenter.SupportedTransactionDataTypes` nor a validator registered with `Oid4vpPresenter.RegisterTransactionDataType`. Both are empty by default, so every request carrying `transaction_data` is refused until the integrator declares its types;
  - an entry does not conform to the definition of its type. Section 5.1 leaves each definition to the document specifying that type, so the registered validator is what checks it. A type that is only listed is checked against the members Section 5.1 and Appendix B.3.3.1 define, compared without regard to letter case, and refused for carrying any other;
  - an entry is not base64url-encoded JSON, or carries no `credential_ids`;
  - a Credential Query an entry references does not exist, is not `dc+sd-jwt`, or sets `require_cryptographic_holder_binding` to false (Appendix B.3.3);
  - no `transaction_data_hashes_alg` is both offered by every entry and computable by the serializer (`sha-256`, `sha-384` or `sha-512`).
- A Credential Set option that not every entry references is passed over instead, and the request is refused only once no option referenced by every entry can be presented (Section 5.1). The refusal is `invalid_transaction_data` when an unreferenced option was passed over first, and `access_denied` otherwise, except that no error response is sent when no option was passed over and only more than one Credential could answer the request (see [DCQL](#wallet-dcql)).
- Although the base64url encoding the specification uses has no padding (Section 2), an entry that carries trailing `=` padding or line breaks is accepted as well, unless a line break follows the padding. The hashes are computed over the string as received (Appendix B.3.3.1), so they still match the hashes the Verifier computes over the entries it sent.
- Although Appendix B.3.3.1 defines `transaction_data_hashes_alg` as a non-empty array of strings, a `null` value is taken as absent, so `sha-256` is used, and `null` elements of the array are passed over.

#### 8.5 Authorization Error Response {#wallet-error-response}

- With `response_mode=direct_post`, the Wallet posts `error`, and `state` when the request carried one, to `response_uri`, with `error_description` except for `access_denied`, whose reason would reveal which Credentials the user holds (Section 15.9). No error response is sent with any other response mode.
- A Request Object (`request` / `request_uri`) using the `x509_san_dns` Client Identifier Prefix gets an error response for a parameter validation failure too, but only once its certificate chain (unless `Oid4vpPresenter.InsecureSkipX509Verify` is set), signature, `client_id` and response destination have all been verified. A failure found earlier is held back until then.
- A Request Object naming no verification key, such as one using the `redirect_uri` prefix, is refused outright instead and gets no error response, since it authenticates no destination to send one to.
- A refusal the Wallet attaches no code to is not sent at all. Among them are a Client Identifier Prefix the Wallet does not support, which Section 8.5 assigns to `invalid_request`, and a non-empty `request_uri_method` that is neither `get` nor `post` in any letter case: `invalid_request_uri_method` is never sent.
- In URL-encoded parameters, a request using the `decentralized_identifier`, `verifier_attestation`, `x509_hash` or `openid_federation` prefix that also fails a check carrying a code while its parameters are read, such as a missing parameter, `scope` or a malformed `dcql_query`, gets an error response with that code. The checks on each `transaction_data` entry are not reached. An unrecognized prefix, `origin` or a `client_id` without a prefix is refused before any other check and gets none.
- `vp_formats_not_supported` is returned as soon as one Credential Query names a format other than `dc+sd-jwt` or `jwt_vc_json`, even when that query is only one option of a Credential Set or belongs to an optional one. Section 8.5 defines the code for a Wallet that supports none of the requested formats, and Section 6.4.2 lets a Credential Set be satisfied with any of its options.

#### 11 Verifier Metadata — `client_metadata` {#wallet-verifier-metadata}

- `client_metadata` is accepted as a JSON object in a Request Object and as a JSON string in URL-encoded parameters.
- Of the members Section 5.1 defines, only `jwks` is used, and only for the key that encrypts the Authorization Response. No key in `client_metadata` is used to verify a signed request (Section 5.1).
- The Wallet encrypts only when `client_metadata` also carries the JARM member `authorization_encrypted_response_alg`, which is not among the members Section 5.1 lists (see [Encrypted Authorization Response](#wallet-encrypted-response)). `vp_formats_supported` and `encrypted_response_enc_values_supported` are not read.
- A request is refused when `jwks` holds a key the Wallet cannot parse, such as the `X25519` key in the example of Section 8.3. It is also refused when an RFC 7591 registration member such as `client_name` has a value of the wrong type, although Section 5.1 says that members it does not list are to be ignored.

#### Appendix B.1 `jwt_vc_json` format {#wallet-jwt-vc-json}

- A Credential Query of this format is matched on `format` alone: neither `meta` nor `claims` is applied, and the newest stored `jwt_vc_json` Credential is presented whole.
- The Credential is always presented in a Verifiable Presentation, although Appendix B.1 requires a Credential without Holder Binding when `require_cryptographic_holder_binding` is false.

#### Appendix B.3.6 SD-JWT VC Key Binding / KB-JWT {#wallet-key-binding}

- Only ES256 is supported for the KB-JWT, since the holder key has to be a P-256 key.
- A KB-JWT is attached when `sdjwtvc.SdJwtVcPresentationOptions.RequireKeyBinding` is set, which the default options leave off. It is forced on when the request carries `transaction_data`, whose hashes are returned in the KB-JWT.
- A Credential Query requiring Cryptographic Holder Binding, as `require_cryptographic_holder_binding` does by default (Section 6.1), does not by itself make the Wallet attach a KB-JWT, although Appendix B.3 then requires an SD-JWT with a KB-JWT.
