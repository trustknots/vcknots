import { pack } from '@sd-jwt/core'
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs'
import { base64url } from 'jose'
import type { JWK } from 'jose'
import { raise } from '../errors/vcknots.error'

// SD-JWT VC issuance.
//
// Unlike the W3C JWT VC path, an SD-JWT VC keeps the actual claim values out of
// the signed JWT body. Each selectively-disclosable claim becomes a "disclosure"
// (`base64url(JSON([salt, key, value]))`) and only its salted hash digest is kept
// in the signed payload under `_sd`. The encoded form is:
//
//   <issuer-signed JWT>~<disclosure>~<disclosure>~...~
//
// Disclosure framing and digest calculation are delegated to `@sd-jwt`'s `pack`
// with the very same `digest` hasher the verifier uses, so the credential we emit
// round-trips through `verify-presentation-dc-sd-jwt.provider`. Signing reuses the
// issuer key store (`sign`) exactly like the JWT VC path, so no private key
// material leaves the key store.

// SD-JWT VC header `typ` as expected by the verifier (`dc+sd-jwt`).
export const SD_JWT_VC_TYP = 'dc+sd-jwt'

// Digest algorithm advertised in `_sd_alg`. Must match the hasher used below.
const SD_ALG = 'sha-256'

// signSdJwt signs the issuer JWT part and returns its base64url signature.
// It mirrors `IssuerSignatureKeyStoreProvider.sign`, so the caller can pass that
// method directly.
export type SignSdJwt = (
  payload: Record<string, unknown>,
  header: Record<string, unknown>
) => Promise<string | null>

export type BuildSdJwtCredentialArgs = {
  /** Credential Issuer identifier, used as `iss`. */
  issuer: string
  /** SD-JWT VC type, used as `vct`. */
  vct: string
  /** Signing algorithm, e.g. `ES256`. */
  alg: string
  /** Key id placed in the JWT header; must match a key in the issuer JWKS. */
  kid: string
  /** Holder public key for key binding, placed in `cnf.jwk`. */
  holderJwk: JWK
  /** Selectively-disclosable claims (each becomes a disclosure). */
  claims: Record<string, unknown>
  /** Issued-at, in seconds since epoch. Defaults to now. */
  iat?: number
  /** Signing callback, typically the issuer key store's `sign`. */
  sign: SignSdJwt
}

// buildSdJwtCredential assembles a signed SD-JWT VC in combined issuance format.
export const buildSdJwtCredential = async (args: BuildSdJwtCredentialArgs): Promise<string> => {
  const disclosableKeys = Object.keys(args.claims)

  // `pack` replaces each disclosable claim with a salted-hash digest under `_sd`
  // and returns the corresponding disclosures. Using the verifier's `digest`
  // hasher guarantees the digests it later recomputes match.
  // `{ _sd: [...] }` marks the top-level claims as selectively disclosable. The
  // cast keeps us off `@sd-jwt/types` (not a direct dependency) while matching the
  // runtime shape `pack` expects.
  const disclosureFrame = { _sd: disclosableKeys } as Parameters<typeof pack>[1]
  const { packedClaims, disclosures } = await pack(
    { ...args.claims },
    disclosureFrame,
    { alg: SD_ALG, hasher: digest },
    generateSalt
  )

  const iat = args.iat ?? Math.floor(Date.now() / 1000)
  const payload = {
    ...(packedClaims as Record<string, unknown>),
    vct: args.vct,
    iss: args.issuer,
    iat,
    cnf: { jwk: args.holderJwk },
    _sd_alg: SD_ALG,
  }
  const header = {
    alg: args.alg,
    typ: SD_JWT_VC_TYP,
    kid: args.kid,
  }

  const signature = await args.sign(payload, header)
  if (!signature) {
    throw raise('INTERNAL_SERVER_ERROR', {
      message: 'Cannot sign SD-JWT credential.',
    })
  }

  const encode = (x: unknown) => base64url.encode(JSON.stringify(x))
  const issuerJwt = `${encode(header)}.${encode(payload)}.${signature}`

  // Combined issuance format always terminates with `~` (no key binding JWT yet).
  const encodedDisclosures = disclosures.map((d) => d.encode())
  return [issuerJwt, ...encodedDisclosures, ''].join('~')
}
