import base64url from 'base64url'
import * as jwt from 'jsonwebtoken'
import { err } from '../errors/vcknots.error'
import { VerifyVerifiablePresentationProvider } from './provider.types'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'
import { VerifiableCredential, parseVerifiableCredentialBase } from '../credential.types'
import { selectProvider } from './provider.utils'
import { jwtVpJsonPayloadSchema, VpTokenPayload } from '../presentation.types'
import { z } from 'zod'
import { Nonce } from '../nonce.types'

export const verifyVerifiablePresentation = (): VerifyVerifiablePresentationProvider &
  WithProviderRegistry => {
  return {
    kind: 'verify-verifiable-presentation-provider',
    name: 'verifier-verifiable-presentation-jwt-vp-json-provider',
    single: false,

    ...withProviderRegistry,

    async verify(vp, options): Promise<VpTokenPayload> {
      if (!options || options.kind !== 'jwt_vp_json') {
        throw err('illegal_argument', {
          message: options?.kind
            ? `${options.kind} is not supported.`
            : 'verify options are required.',
        })
      }
      const { expectedAud } = options
      // TODO: review where the processing is located
      const credentials: [
        VerifiableCredential,
        string /* jwt_vc（It is originally the role of the Provider）*/,
      ][] = []
      const decodedVp = jwt.decode(vp, { complete: true })
      if (!decodedVp) {
        throw err('invalid_vp_token', {
          message: `Invalid vp_token: ${vp}`,
        })
      }
      let rawPayload: unknown
      if (typeof decodedVp.payload === 'string') {
        try {
          rawPayload = JSON.parse(decodedVp.payload)
        } catch {
          throw err('invalid_vp_token', {
            message: 'VP token payload is not valid JSON.',
          })
        }
      } else {
        rawPayload = decodedVp.payload
      }
      const parseResult = jwtVpJsonPayloadSchema(z.record(z.string(), z.unknown())).safeParse(
        rawPayload
      )
      if (!parseResult.success) {
        throw err('invalid_vp_token', {
          message: `VP token payload does not match expected schema: ${parseResult.error.message}`,
        })
      }
      const vpPayload = parseResult.data

      const nonce = Nonce({ nonce: vpPayload.nonce })
      const nonceStore$ = this.providers.get('nonce-store-provider')
      const aud = vpPayload.aud
      const audMatches =
        typeof aud === 'string'
          ? aud === expectedAud
          : Array.isArray(aud) && aud.some((a) => typeof a === 'string' && a === expectedAud)
      if (!audMatches) {
        throw err('invalid_vp_token', {
          message:
            aud === undefined
              ? 'VP token is missing aud claim required for client binding.'
              : 'VP token aud does not match expected client_id.',
        })
      }
      const nonceValid = await nonceStore$.validate(nonce)
      if (!nonceValid) {
        throw err('invalid_nonce', {
          message: 'nonce is not valid.',
        })
      }
      const revoked = await nonceStore$.revoke(nonce)
      if (!revoked) {
        throw err('invalid_nonce', {
          message: 'Nonce could not be revoked.',
        })
      }

      const vcs = vpPayload.vp.verifiableCredential
      if (Array.isArray(vcs)) {
        for (const vc of vcs) {
          if (typeof vc === 'string') {
            const parts = vc.split('.')
            const vcPayload = parts[1]
            if (parts.length !== 3 || !vcPayload) {
              throw err('invalid_credential', {
                message: 'VC JWT format is invalid.',
              })
            }
            let decoded: Record<string, unknown>
            try {
              decoded = JSON.parse(base64url.decode(vcPayload)) as Record<string, unknown>
            } catch {
              throw err('invalid_credential', {
                message: 'VC JWT payload is not valid JSON.',
              })
            }
            const credential = decoded.vc ? decoded.vc : decoded
            if (parseVerifiableCredentialBase(credential)) {
              credentials.push([credential, vc])
            }
          } else {
            throw err('illegal_argument', {
              message: 'VC represented as object is not supported.',
            })
          }
        }
      }
      if (!Array.isArray(credentials) || credentials.length === 0) {
        throw err('invalid_credential', {
          message: 'No credentials is included',
        })
      }
      const credential$ = this.providers.get('verify-verifiable-credential-provider')

      for (const [, vcJwt] of credentials) {
        const vcValid = await credential$.verify(vcJwt)
        if (!vcValid) {
          throw err('invalid_credential', {
            message: 'One or more credentials are not valid.',
          })
        }
      }

      if (!decodedVp.header.kid) {
        throw err('invalid_vp_token', {
          message: `Missing key id in the header: ${JSON.stringify(decodedVp.header)}`,
        })
      }
      const kid = decodedVp.header.kid
      const didSplit = kid.split(':')
      if (didSplit.length < 3 || didSplit[0] !== 'did') {
        throw err('invalid_proof', {
          message: `Invalid DID format: ${kid}`,
        })
      }
      const did$ = this.providers.get('did-provider')
      const didDoc = await selectProvider(did$, didSplit[1]).resolveDid(kid)
      if (!didDoc || !didDoc.verificationMethod) {
        throw err('invalid_vp_token', {
          message: `Cannot resolve DID: ${decodedVp.header.kid}`,
        })
      }

      const vm = didDoc.verificationMethod.find(
        // FIXME: this is a hacky way to find the verification method and only works for did:key
        (it) => it.id.startsWith(`${decodedVp.header.kid}`)
      )
      if (!vm || !vm.publicKeyJwk) {
        throw err('invalid_vp_token', {
          message: `Cannot find verification method: ${decodedVp.header.kid}`,
        })
      }
      const publicKey = vm.publicKeyJwk
      const jwtSignature$ = this.providers.get('jwt-signature-provider')
      const JwtValid = await jwtSignature$.verify(vp, publicKey)
      if (!JwtValid) {
        throw err('invalid_proof', {
          message: 'jwt is not valid.',
        })
      }
      const holderBinding$ = this.providers.get('holder-binding-provider')
      const holderBindingValid = await holderBinding$.verify(
        credentials.map(([it]) => it),
        publicKey
      )
      if (!holderBindingValid) {
        throw err('holder_binding_failed', {
          message: 'Holder binding verification failed.',
        })
      }

      return vpPayload
    },
    canHandle(format: string): boolean {
      return format === 'jwt_vp_json'
    },
  }
}
