# Public Wallet API driver

This independent Go module drives the public Wallet API. It reads one JSON
operation on stdin and writes one JSON result on stdout. A protocol error exits
with code 1 and writes `{"operation": ..., "error": ...}`; invalid command or
configuration input exits with code 2.

The driver receives credentials with the OpenID4VCI 1.0 Pre-Authorized Code
Flow and Authorization Code Flow, lists the stored credentials, presents them
with OpenID4VP 1.0 through a launch URI or the W3C Digital Credentials API, and
applies the HAIP 1.0 profile on request. It uses software JWKs and makes no
hardware protection claim.

## Configure and run

Use the Go version pinned in `wallet/mise.toml` (Go 1.26.6). From this
directory:

```sh
go build -o official_driver .
```

Provide separate EC signing JWK files for the holder, DPoP and client keys. The
key files must contain private components, and the client public JWK must be
registered with the issuer. Do not use production keys for tests. Use absolute
paths in the configuration.

### Configuration fields

| Field | Type | Default | Effect |
| --- | --- | --- | --- |
| `stateDirectory` | string | required | Directory for the bbolt credential store. |
| `clientId` | string | required | `wallet.Config.ClientAuth.ClientID`. |
| `holderKeyFile` | string | required | Private JWK of the holder key (`CredentialRequest.HolderKeys`, `Presentation.Key`). |
| `dpopKeyFile` | string | required | Private JWK of `wallet.Config.DPoP.Key`. |
| `clientKeyFile` | string | required | Private JWK of the `private_key_jwt` key (`Config.ClientAuth.Key`) and of the key the client attestation binds (`Config.Attestation.ClientKey`). |
| `tlsCAFiles` | []string | `[]` | Extra PEM roots added to the system roots for TLS, also used for CRL fetches. |
| `profile` | string | `""` | `""`, `"final"` or `"haip"`. Applied to `Config.Profile` and to both plugins the driver builds. Unknown values are rejected. |
| `verifierCAFiles` | []string | `[]` | PEM trust anchors for signed Request Objects (`oid4vp.RequestObjectValidationOptions.TrustAnchors`). A file with no certificate is rejected. When empty, `RequestObjectValidation` stays nil and X.509 Request Objects are rejected. |
| `verifierAllowUnadvertisedRevocation` | bool | `false` | `RequestObjectValidationOptions.AllowUnadvertisedRevocation`. Requires `verifierCAFiles`. |
| `walletAudience` | []string | `[]` | `RequestObjectValidationOptions.WalletAudience`. Requires `verifierCAFiles`. |
| `issuerCAFiles` | []string | `[]` | PEM issuer trust anchors for credential `x5c` chains (`acceptance.IssuerX509TrustOptions.TrustAnchors`). |
| `issuerAllowUnadvertisedRevocation` | bool | `false` | `acceptance.IssuerX509TrustOptions.AllowUnadvertisedRevocation`. Requires `issuerCAFiles`. |
| `issuerJWKSFiles` | []string | `[]` | JWKS files of public issuer keys for credentials without `x5c`. Sets `acceptance.Policy.ResolveIssuerKeys`, which returns every configured key. Private keys are rejected. |
| `requireHolderBinding` | bool | `false` | `acceptance.Policy.RequireHolderBinding`. |
| `redirectUri` | string | `""` | `Config.Issuance.RedirectURI`. Required by `receive-code` and `receive-code-wallet-initiated`. |
| `authorizationRequestType` | string | `""` | `IssuanceRequest.AuthorizationRequestType`: `""`, `"scope"` or `"authorization_details"`. HAIP accepts `scope` only. |
| `attesterKeyFile` | string | `""` | Private JWK of a test-only `attestation.StaticClientAttester` (`Config.Attestation.Client`). Its `x5c` chain, when present, becomes the attestation's `x5c`; HAIP requires one. Set together with `attesterIssuer`. |
| `attesterIssuer` | string | `""` | `iss` of the static client attester. |
| `keyAttesterKeyFile` | string | `""` | Private JWK of a test-only `attestation.StaticKeyAttester` (`Config.Attestation.Key`). Set together with `keyAttesterIssuer`. |
| `keyAttesterIssuer` | string | `""` | `iss` of the static key attester. |
| `includeKeyAttestation` | bool | `false` | `CredentialRequest.IncludeKeyAttestation`: send a key attestation although the issuer does not require one. |
| `deferredPollAttempts` | int | `10` | How many Deferred Credential Requests the driver sends while the issuance is pending. Zero or negative selects 10. |
| `credentialResponseEncryption` | bool | `false` | Sets `Config.Issuance.CredentialEncryption.Response` to `CredentialEncryptionRequired`; an issuer that offers no response encryption is refused. The response key is ephemeral. |
| `additionalHolderKeys` | int | `0` | Extra ephemeral P-256 holder keys for a batch request in `receive-code` and `receive-code-wallet-initiated`. |
| `followRedirect` | bool | `true` | Whether `present` opens the returned `redirect_uri`. |

`Config.CredentialAcceptance` is always set, because the OpenID4VCI 1.0 methods
refuse to run without it. With `issuerCAFiles` or `issuerJWKSFiles` the policy
authenticates the issuer key; with neither, the driver sets
`acceptance.Policy.UnverifiedIssuer`, so a run against a test issuer whose key
the driver cannot authenticate says so in one place. Under HAIP an SD-JWT VC
still requires `issuerCAFiles`. `requireHolderBinding` applies in both cases.

The TLS-configured HTTP client is the plugins' `HTTPClient` and the CRL client
of `IssuerX509TrustOptions` and `RequestObjectValidationOptions`, so CRL
fetches honour `tlsCAFiles`. Inconsistent options (an
`*AllowUnadvertisedRevocation` flag without its CA files, `walletAudience`
without `verifierCAFiles`, an attester key without its issuer) and an
authorization code operation without `redirectUri` are rejected before any
operation runs.

`StaticClientAttester` and `StaticKeyAttester` self-issue attestations with a
locally held attester key. They exist for tests and single-operator
deployments: a production wallet obtains attestations from a remote attester
and never holds the attester's private key.

Example configuration:

```json
{
  "stateDirectory": "/path/to/isolated-wallet-state",
  "tlsCAFiles": ["/path/to/test-transport-ca.pem"],
  "verifierCAFiles": ["/path/to/verifier-trust-anchor.pem"],
  "verifierAllowUnadvertisedRevocation": false,
  "walletAudience": ["https://self-issued.me/v2"],
  "issuerCAFiles": ["/path/to/issuer-trust-anchor.pem"],
  "issuerAllowUnadvertisedRevocation": false,
  "issuerJWKSFiles": ["/path/to/issuer-jwks.json"],
  "requireHolderBinding": true,
  "profile": "final",
  "holderKeyFile": "/path/to/holder.jwk",
  "dpopKeyFile": "/path/to/dpop.jwk",
  "clientKeyFile": "/path/to/client.jwk",
  "clientId": "registered-wallet-client",
  "redirectUri": "https://wallet.example/callback",
  "authorizationRequestType": "",
  "attesterKeyFile": "/path/to/attester.jwk",
  "attesterIssuer": "https://attester.example",
  "keyAttesterKeyFile": "/path/to/key-attester.jwk",
  "keyAttesterIssuer": "https://attester.example",
  "includeKeyAttestation": false,
  "deferredPollAttempts": 10,
  "credentialResponseEncryption": false
}
```

Transport verification uses the system roots plus `tlsCAFiles`. The driver does
not disable TLS or X.509 checks. Credentials are stored with the library's bbolt
local storage plugin.

### Operations and output

```sh
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"public-keys"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"receive-preauth","uri":"openid-credential-offer://?credential_offer=...","txCode":"issuer-supplied-code"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"receive-code","uri":"openid-credential-offer://?credential_offer_uri=..."}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"receive-code-wallet-initiated","credentialIssuer":"https://issuer.example/","credentialConfigurationId":"eudi_pid"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"list"}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"present","uri":"openid4vp://?client_id=...&request_uri=..."}
JSON
./official_driver -config /path/to/config.json <<'JSON'
{"operation":"present-dcapi","dcapiRequest":{"protocol":"openid4vp-v1-unsigned","data":{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"...","client_metadata":{...},"dcql_query":{...}}},"origin":"https://localhost:33513"}
JSON
```

`public-keys` returns the public JWKs of the holder, DPoP and client keys.

`receive-preauth` parses the by-value offer with `wallet.ParseCredentialOfferURL`,
calls `AuthorizePreAuthorizedIssuance` with `txCode` as `tx_code`, and then
`RequestCredential` with the holder key. The token request names the client with
`clientId`, carries a DPoP proof, and, with `attesterKeyFile`, the client
attestation headers.

`receive-code` resolves the offer URI with `ResolveCredentialOffer`
(`credential_offer_uri` is fetched), calls `BeginIssuance`, and opens the
returned authorization URL itself: it sends a GET with the TLS-configured client,
follows redirects within the authorization server (at most five), and takes the
first `Location` that leaves it as the redirect. This works for a test issuer
that answers without user interaction; a wallet with a user opens the URL in the
system browser instead. The driver then calls `AuthorizeIssuance` with that
redirect and `RequestCredential` with the holder key and any
`additionalHolderKeys`.

`receive-code-wallet-initiated` runs the same flow without a Credential Offer
(OpenID4VCI 1.0 §5). It takes `credentialIssuer` and `credentialConfigurationId`
instead of `uri`.

After `RequestCredential`, the three receive operations poll a pending issuance
themselves: they wait the interval the issuer named (at least one second, at
most one minute) and call `RequestDeferredCredential`, up to
`deferredPollAttempts` times. They then report the outcome with `NotifyIssuer`:
`credential_accepted` after the credentials were stored, `credential_failure`
when they were refused. A notification failure after storage is reported as an
error. The output is `credentialIds`, a `verification` array in credential order
(`acceptance.Verification`), `notificationId` when the issuer asked for
notifications, and `transactionId` with `pending: true` when the issuance was
still pending after the last poll.

`present` calls `PresentCredential` with the holder key: the request is parsed
and admitted, the stored credentials that satisfy the DCQL query are chosen, and
the response is sent. It returns `redirectUri`, `redirectFollowed` and
`redirectStatus` (`0` when the redirect was not opened). With `followRedirect`
enabled, the driver opens a returned `redirect_uri` as a same-device browser
would: a GET with the TLS-configured client, `Accept: text/html,*/*`,
`User-Agent: official_driver`, a 15 s timeout and at most five followed
redirects. The fragment is never sent. A final status outside 2xx and 3xx is an
error.

`present-dcapi` answers a W3C Digital Credentials API invocation.
`dcapiRequest` is the platform request entry (`protocol` and the protocol `data`
object) and `origin` the platform-authenticated calling origin. The driver calls
`ParseDCAPIRequest`, `SelectCredentials` and `SubmitPresentation` and prints
`SubmitResult.DCAPIResponse`: `{"protocol":...,"data":{"vp_token":{...}}}` for
`dc_api`, or `{"protocol":...,"data":{"response":"<JWE>"}}` for `dc_api.jwt`. It
makes no HTTP call. The Key Binding JWT `aud` is `origin:<origin>` (OpenID4VP
1.0 Appendix A.4).

`list` returns `credentialIds` and `total`.

Each invocation is a new process, so listing and presenting use the persisted
credentials. Pass the issuer's or verifier's launch URI unchanged. The driver
does not repair requests, retry protocol failures, or build presentation
responses itself.

### additionalHolderKeys

`additionalHolderKeys` makes the authorization code operations send that many
extra key proofs with ephemeral P-256 keys, so an issuer that advertises
`batch_credential_issuance` returns several credentials (OpenID4VCI 1.0 §8.2).
The ephemeral keys are discarded after the run; the resulting credentials are
stored but cannot be presented later. Use it only to exercise batch issuance.
