import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose'
import { ProofJwt } from '../credential.types'
import { raise } from '../errors/vcknots.error'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'
import { CredentialProofProvider } from './provider.types'
import { selectProvider } from './provider.utils'

export type CredentialProofProviderOptions =
  | {
      usePreAuth: false
      clientId?: string
      credentialIssuer: string
    }
  | {
      usePreAuth: true
      credentialIssuer: string
    }

export const credentialProofJWT = (
  options?: CredentialProofProviderOptions
): CredentialProofProvider & WithProviderRegistry => {
  return {
    kind: 'credential-proof-provider',
    name: 'default-credential-proof-jwt-provider',
    single: false,

    ...withProviderRegistry,

    async verifyProof(proof: string): Promise<ProofJwt | null> {
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

      const proofTyp = proofJwtHeader.typ
      if (proofTyp !== 'openid4vci-proof+jwt') {
        throw raise('INVALID_PROOF', {
          message: 'Invalid Proof Header typ value.',
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
      })

      if (
        typeof protectedProof.payload.aud !== 'string' ||
        typeof protectedProof.payload.iat !== 'number'
      ) {
        throw raise('INVALID_PROOF', {
          message: 'Unsupported Proof Payload.',
        })
      }
      if (options) {
        if (options.usePreAuth && typeof protectedProof.payload.iss === 'string') {
          throw raise('INVALID_PROOF', {
            message: 'iss claim must omitted using case Pre-Authorized Code Flow.',
          })
        }
        if (
          !options.usePreAuth &&
          typeof protectedProof.payload.iss === 'string' &&
          protectedProof.payload.iss !== options.clientId
        ) {
          throw raise('INVALID_PROOF', {
            message: 'iss claim must the client_id of the Client making the Credential request.',
          })
        }
        if (protectedProof.payload.aud !== options.credentialIssuer) {
          throw raise('INVALID_PROOF', {
            message: 'aud claim must be the Credential Issuer Identifier.',
          })
        }
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
