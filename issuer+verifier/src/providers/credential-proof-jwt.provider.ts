import {
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  importSPKI,
  jwtVerify,
  type JWSHeaderParameters,
} from 'jose'
import { ProofJwt } from '../credential.types'
import { raise } from '../errors/vcknots.error'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'
import type { CredentialProofJwtVerifyContext } from '../credential-proof-jwt.types'
import type { CredentialProofProvider } from './provider.types'
import { selectProvider } from './provider.utils'
import { DiVpProof } from '../proofs.types'
import type { ProviderRegistry } from './provider.registry'

const DEFAULT_PROOF_JWT_MAX_TOKEN_AGE_SECONDS = 300
const DEFAULT_PROOF_JWT_CLOCK_TOLERANCE_SECONDS = 60
const PROOF_JWT_MUTUALLY_EXCLUSIVE_HEADER_MESSAGE =
  'Proof JWT header: kid, jwk, and x5c are mutually exclusive (OID4VCI 1.0 §F.1).'
const PROOF_JWT_MISSING_KEY_REFERENCE_MESSAGE =
  'Proof JWT header must contain one of kid, jwk, or x5c (OID4VCI 1.0 §F.1).'

/** OID4VCI §F.1 — JWT proof JOSE header `typ` (explicit typing per RFC 8725 §3.11). */
export const OID4VCI_JWT_PROOF_TYP = 'openid4vci-proof+jwt'

/** OID4VCI §F.1 — `alg` MUST NOT be `none` or an IANA symmetric (HMAC) JWS algorithm. */
function isProhibitedProofJwtAlg(alg: string): boolean {
  const trimmed = alg.trim()
  if (trimmed.length === 0) return true
  if (trimmed.toLowerCase() === 'none') return true
  // JWA HMAC family: HS256, HS384, HS512, HS512/256, …
  return /^hs/i.test(trimmed)
}

function resolveProofBindingMethod(header: JWSHeaderParameters): 'kid' | 'jwk' | 'x5c' {
  const hasKid = typeof header.kid === 'string' && header.kid.trim().length > 0
  const hasJwk = header.jwk !== undefined
  const hasX5c = Array.isArray(header.x5c) && header.x5c.length > 0
  const present = [hasKid, hasJwk, hasX5c].filter(Boolean).length

  if (present === 0) {
    throw raise('invalid_proof', {
      message: PROOF_JWT_MISSING_KEY_REFERENCE_MESSAGE,
    })
  }
  if (present > 1) {
    throw raise('invalid_proof', {
      message: PROOF_JWT_MUTUALLY_EXCLUSIVE_HEADER_MESSAGE,
    })
  }
  if (hasKid) return 'kid'
  if (hasJwk) return 'jwk'
  return 'x5c'
}

function derBase64ToPem(derBase64: string): string {
  const body =
    derBase64
      .replace(/\s+/g, '')
      .match(/.{1,64}/g)
      ?.join('\n') ?? derBase64
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`
}

async function resolveDidPublicKeyJwk(
  providers: ProviderRegistry,
  kid: string
): Promise<JsonWebKey> {
  const didSplit = kid.split(':')
  if (didSplit.length < 3 || didSplit[0] !== 'did') {
    throw raise('invalid_proof', {
      message: `Invalid DID format: ${kid}`,
    })
  }

  const didProvider$ = providers.get('did-provider')
  if (!didProvider$ || didProvider$.length === 0) {
    throw raise('invalid_proof', {
      message: 'No kid or unsupported did type detected.',
    })
  }
  const didProvider = selectProvider(didProvider$, didSplit[1])

  const did = kid.split('#')[0] ?? kid
  let didDoc = await didProvider.resolveDid(kid).catch(() => null)
  if (!didDoc && did !== kid) {
    didDoc = await didProvider.resolveDid(did).catch(() => null)
  }

  const verificationMethod =
    didDoc?.verificationMethod?.find((it) => it.id === kid) ??
    didDoc?.verificationMethod?.find((it) => it.publicKeyJwk !== undefined)

  if (!verificationMethod?.publicKeyJwk) {
    throw raise('invalid_proof', {
      message: 'Unsupported did type detected.',
    })
  }

  return verificationMethod.publicKeyJwk
}

async function resolveHeaderPublicKey(
  providers: ProviderRegistry,
  proofJwtHeader: JWSHeaderParameters,
  proofAlg: string
): Promise<CryptoKey | Uint8Array> {
  const bindingMethod = resolveProofBindingMethod(proofJwtHeader)

  if (bindingMethod === 'kid') {
    const publicKeyJwk = await resolveDidPublicKeyJwk(providers, proofJwtHeader.kid as string)
    return await importJWK(publicKeyJwk, proofAlg)
  }

  if (bindingMethod === 'jwk') {
    const jwk = proofJwtHeader.jwk
    if (jwk === null || typeof jwk !== 'object' || Array.isArray(jwk)) {
      throw raise('invalid_proof', {
        message: 'Proof JWT header jwk must be a JSON object.',
      })
    }
    if ('d' in jwk && jwk.d !== undefined) {
      throw raise('invalid_proof', {
        message: 'Proof JWT header jwk must contain a public key only.',
      })
    }
    try {
      return await importJWK(jwk as JsonWebKey, proofAlg)
    } catch (e) {
      throw raise('invalid_proof', {
        message: `Failed to import proof JWT jwk: ${e instanceof Error ? e.message : String(e)}`,
        cause: e,
      })
    }
  }

  if (bindingMethod === 'x5c') {
    const x5c = proofJwtHeader.x5c
    if (!Array.isArray(x5c) || x5c.length === 0) {
      throw raise('invalid_proof', {
        message: 'Proof JWT header x5c must contain at least one certificate.',
      })
    }

    const certificate$ = providers.get('certificate-provider')
    const certificateChain = x5c.map(derBase64ToPem)
    const certValid = await certificate$.validate(certificateChain)
    if (!certValid) {
      throw raise('invalid_proof', {
        message: 'x5c certificate chain is invalid.',
      })
    }

    const publicKeyPem = certificate$.getPublicKey(certificateChain[0])
    if (!publicKeyPem) {
      throw raise('invalid_proof', {
        message: 'Unable to extract public key from x5c certificate chain.',
      })
    }

    try {
      return await importSPKI(publicKeyPem, proofAlg)
    } catch (e) {
      throw raise('invalid_proof', {
        message: `Failed to import proof JWT x5c public key: ${e instanceof Error ? e.message : String(e)}`,
        cause: e,
      })
    }
  }

  throw raise('invalid_proof', {
    message: `Unsupported proof binding method: ${bindingMethod satisfies never}`,
  })
}

/** Options for {@link credentialProofJWT} (proof JWT `iat` validation per OID4VCI 1.0 §F.1). */
export type CredentialProofJwtFactoryOptions = {
  /** Maximum age of proof JWT `iat` in seconds. Default: 300 (5 minutes). */
  maxTokenAgeSeconds?: number
  /** Clock skew tolerance in seconds for time-based claims. Default: 60. */
  clockToleranceSeconds?: number
}

export const credentialProofJWT = (
  factoryOptions?: CredentialProofJwtFactoryOptions
): CredentialProofProvider & WithProviderRegistry => {
  const maxTokenAge = factoryOptions?.maxTokenAgeSeconds ?? DEFAULT_PROOF_JWT_MAX_TOKEN_AGE_SECONDS
  const clockTolerance =
    factoryOptions?.clockToleranceSeconds ?? DEFAULT_PROOF_JWT_CLOCK_TOLERANCE_SECONDS

  return {
    kind: 'credential-proof-provider',
    name: 'default-credential-proof-jwt-provider',
    single: false,

    ...withProviderRegistry,

    async verifyProof(
      proof: string | DiVpProof,
      verificationContext?: CredentialProofJwtVerifyContext
    ): Promise<ProofJwt | null> {
      if (typeof proof !== 'string') {
        throw raise('invalid_proof', {
          message: 'Unsupported proof type.',
        })
      }
      let decoded: ReturnType<typeof decodeJwt>
      try {
        decoded = decodeJwt(proof)
      } catch (e) {
        throw raise('invalid_proof', {
          message: `Failed to decode proof JWT: ${e instanceof Error ? e.message : String(e)}`,
          cause: e,
        })
      }
      if (typeof decoded.payload === 'string') {
        throw raise('invalid_proof', {
          message: 'Unsupported jwt payload type.',
        })
      }
      const proofJwtHeader = decodeProtectedHeader(proof)
      const proofAlg = proofJwtHeader.alg
      if (typeof proofAlg !== 'string') {
        throw raise('invalid_proof', {
          message: 'Unsupported Proof Header alg value.',
        })
      }
      if (isProhibitedProofJwtAlg(proofAlg)) {
        throw raise('invalid_proof', {
          message: 'Proof JWT alg must not be "none" or a symmetric (MAC) algorithm.',
        })
      }
      if (proofJwtHeader.typ !== OID4VCI_JWT_PROOF_TYP) {
        throw raise('invalid_proof', {
          message: `Proof JWT header typ must be "${OID4VCI_JWT_PROOF_TYP}".`,
        })
      }
      const verificationKey = await resolveHeaderPublicKey(this.providers, proofJwtHeader, proofAlg)
      const protectedProof = await jwtVerify(proof, verificationKey, {
        algorithms: [proofAlg],
        maxTokenAge,
        clockTolerance,
      }).catch((e: unknown) => {
        const code =
          e !== null && typeof e === 'object' && 'code' in e
            ? String((e as { code: unknown }).code)
            : undefined
        if (code === 'ERR_JWT_EXPIRED' || code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
          throw raise('invalid_proof', {
            message: 'Proof JWT is outside the allowed issuance time window.',
            cause: e,
          })
        }
        throw raise('invalid_proof', {
          message: `Proof JWT verification failed: ${e instanceof Error ? e.message : String(e)}`,
          cause: e,
        })
      })

      if (
        typeof protectedProof.payload.aud !== 'string' ||
        typeof protectedProof.payload.iat !== 'number'
      ) {
        throw raise('invalid_proof', {
          message: 'Unsupported Proof Payload.',
        })
      }

      if (!verificationContext) {
        throw raise('invalid_proof', {
          message:
            'Credential proof verification requires credentialIssuer and usePreAuth (OID4VCI). Pass CredentialProofJwtVerifyContext as the second argument to verifyProof().',
        })
      }

      const ctx = verificationContext

      const payloadClaims = protectedProof.payload
      const hasIss = Object.prototype.hasOwnProperty.call(payloadClaims, 'iss')
      const issValue = payloadClaims.iss

      if (ctx.usePreAuth) {
        // OID4VCI separates the pre-authorized_code grant from anonymous access.
        // Only access tokens obtained via anonymous access must omit `iss`.
        if (!ctx.clientId) {
          if (hasIss) {
            throw raise('invalid_proof', {
              message:
                'iss claim must be omitted when using an access token obtained through anonymous access.',
            })
          }
        } else if (hasIss) {
          if (typeof issValue !== 'string' || issValue !== ctx.clientId) {
            throw raise('invalid_proof', {
              message:
                'iss claim must match the client_id of the Client making the Credential request.',
            })
          }
        }
      } else {
        // Non pre-authorized_code flows keep the existing rule: if `iss` is present,
        // it must identify either the requesting client or the credential issuer.
        if (hasIss) {
          if (typeof issValue !== 'string') {
            throw raise('invalid_proof', {
              message:
                'iss claim must be the client_id of the Client making the Credential request or the Credential Issuer Identifier.',
            })
          }
          if (issValue !== ctx.clientId && issValue !== ctx.credentialIssuer) {
            throw raise('invalid_proof', {
              message:
                'iss claim must be the client_id of the Client making the Credential request or the Credential Issuer Identifier.',
            })
          }
        }
      }
      if (protectedProof.payload.aud !== ctx.credentialIssuer) {
        throw raise('invalid_proof', {
          message: 'aud claim must be the Credential Issuer Identifier.',
        })
      }

      const iss =
        typeof protectedProof.payload.iss === 'string' ? protectedProof.payload.iss : undefined
      const nonce =
        typeof protectedProof.payload.nonce === 'string' ? protectedProof.payload.nonce : undefined
      const proofJwtPayload = {
        iss,
        aud: protectedProof.payload.aud,
        iat: protectedProof.payload.iat,
        nonce,
      }
      return {
        header: {
          ...proofJwtHeader,
          alg: proofAlg,
        },
        payload: proofJwtPayload,
      }
    },

    canHandle(proofType: string): boolean {
      return proofType === 'jwt'
    },
  }
}
