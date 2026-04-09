import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose'
import { ProofJwt } from '../credential.types'
import { raise } from '../errors/vcknots.error'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'
import type { CredentialProofJwtVerifyContext } from '../credential-proof-jwt.types'
import type { CredentialProofProvider } from './provider.types'
import { selectProvider } from './provider.utils'
import { DiVpProof } from '../proofs.types'

const DEFAULT_PROOF_JWT_MAX_TOKEN_AGE_SECONDS = 300
const DEFAULT_PROOF_JWT_CLOCK_TOLERANCE_SECONDS = 60

/** Options for {@link credentialProofJWT} (proof JWT `iat` window per OID4VCI §7.2.2). */
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
        throw raise('INVALID_PROOF', {
          message: 'Unsupported proof type.',
        })
      }
      let decoded: ReturnType<typeof decodeJwt>
      try {
        decoded = decodeJwt(proof)
      } catch (e) {
        throw raise('INVALID_PROOF', {
          message: `Failed to decode proof JWT: ${e instanceof Error ? e.message : String(e)}`,
          cause: e,
        })
      }
      if (typeof decoded.payload === 'string') {
        throw raise('INVALID_PROOF', {
          message: 'Unsupported jwt payload type.',
        })
      }
      const proofJwtHeader = decodeProtectedHeader(proof)
      const proofAlg = proofJwtHeader.alg
      if (typeof proofAlg !== 'string') {
        throw raise('INVALID_PROOF', {
          message: 'Unsupported Proof Header alg value.',
        })
      }
      let publicKeyJwk: JsonWebKey
      if (proofJwtHeader.kid) {
        const didSplit = proofJwtHeader.kid.split(':')
        if (didSplit.length < 3 || didSplit[0] !== 'did') {
          throw raise('INVALID_PROOF', {
            message: `Invalid DID format: ${proofJwtHeader.kid}`,
          })
        }
        const didProvider$ = this.providers.get('did-provider')
        if (!didProvider$ || didProvider$.length === 0) {
          throw raise('INVALID_PROOF', {
            message: 'No kid or unsupported did type detected.',
          })
        }
        const didProvider = selectProvider(didProvider$, didSplit[1])
        const didDoc = await didProvider.resolveDid(proofJwtHeader.kid)
        if (!didDoc || !didDoc.verificationMethod || !didDoc.verificationMethod[0].publicKeyJwk) {
          throw raise('INVALID_PROOF', {
            message: 'Unsupported did type detected.',
          })
        }
        publicKeyJwk = didDoc.verificationMethod[0].publicKeyJwk
      } else {
        throw raise('INVALID_PROOF', {
          message: 'Unsupported Proof Header.',
        })
      }

      const keyJwk = await importJWK(publicKeyJwk, proofAlg)
      const protectedProof = await jwtVerify(proof, keyJwk, {
        algorithms: [proofAlg],
        maxTokenAge,
        clockTolerance,
      }).catch((e: unknown) => {
        const code =
          e !== null && typeof e === 'object' && 'code' in e
            ? String((e as { code: unknown }).code)
            : undefined
        if (code === 'ERR_JWT_EXPIRED' || code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
          throw raise('INVALID_PROOF', {
            message: 'Proof JWT is outside the allowed issuance time window.',
            cause: e,
          })
        }
        throw e
      })

      if (
        typeof protectedProof.payload.aud !== 'string' ||
        typeof protectedProof.payload.iat !== 'number'
      ) {
        throw raise('INVALID_PROOF', {
          message: 'Unsupported Proof Payload.',
        })
      }

      if (!verificationContext) {
        throw raise('INVALID_PROOF', {
          message:
            'Credential proof verification requires credentialIssuer and usePreAuth (OID4VCI). Pass CredentialProofJwtVerifyContext as the second argument to verifyProof().',
        })
      }

      const ctx = verificationContext

      const payloadClaims = protectedProof.payload
      const hasIss = Object.prototype.hasOwnProperty.call(payloadClaims, 'iss')
      const issValue = payloadClaims.iss

      if (ctx.usePreAuth) {
        if (hasIss) {
          throw raise('INVALID_PROOF', {
            message: 'iss claim must be omitted when using Pre-Authorized Code Flow.',
          })
        }
      } else {
        // OID4VCI JWT proof: iss claim must the client_id of the Client making the Credential request.
        // OID4VCI JWT proof: iss claim must be omitted using case Pre-Authorized Code Flow.
        // TODO:check auth-code flow
        if (hasIss) {
          if (typeof issValue !== 'string') {
            throw raise('INVALID_PROOF', {
              message:
                'iss claim must be the client_id of the Client making the Credential request or the Credential Issuer Identifier.',
            })
          }
          if (issValue !== ctx.clientId && issValue !== ctx.credentialIssuer) {
            throw raise('INVALID_PROOF', {
              message:
                'iss claim must be the client_id of the Client making the Credential request or the Credential Issuer Identifier.',
            })
          }
        }
      }
      if (protectedProof.payload.aud !== ctx.credentialIssuer) {
        throw raise('INVALID_PROOF', {
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
