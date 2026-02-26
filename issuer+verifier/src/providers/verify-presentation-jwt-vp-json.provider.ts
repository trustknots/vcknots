import base64url from 'base64url'
import * as jwt from 'jsonwebtoken'
import { err } from '../errors/vcknots.error'
import { VerifyVerifiablePresentationProvider } from './provider.types'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'
import { VerifiableCredential, parseVerifiableCredentialBase } from '../credential.types'
import { selectProvider } from './provider.utils'
import { jwtVpJsonPayloadSchema, VpTokenPayload } from '../presentation.types'
import { z } from 'zod'
import { Cnonce } from '../cnonce.types'

export const verifyVerifiablePresentation = (): VerifyVerifiablePresentationProvider &
  WithProviderRegistry => {
  return {
    kind: 'verify-verifiable-presentation-provider',
    name: 'verifier-verifiable-presentation-jwt-vp-json-provider',
    single: false,

    ...withProviderRegistry,

    async verify(vp, options): Promise<VpTokenPayload> {
      if (options && options.kind !== 'jwt_vp_json') {
        throw err('ILLEGAL_ARGUMENT', {
          message: `${options.kind} is not supported.`,
        })
      }
      // TODO: review where the processing is located
      const credentials: [
        VerifiableCredential,
        string /* jwt_vc（It is originally the role of the Provider）*/,
      ][] = []
      const decodedVp = jwt.decode(vp, { complete: true })
      if (!decodedVp) {
        throw err('INVALID_VP_TOKEN', {
          message: `Invalid vp_token: ${vp}`,
        })
      }
      let rawPayload: unknown
      if (typeof decodedVp.payload === 'string') {
        try {
          rawPayload = JSON.parse(decodedVp.payload)
        } catch {
          throw err('INVALID_VP_TOKEN', {
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
        throw err('INVALID_VP_TOKEN', {
          message: `VP token payload does not match expected schema: ${parseResult.error.message}`,
        })
      }
      const vpPayload = parseResult.data

      const nonce = Cnonce(vpPayload.nonce)
      const nonceStore$ = this.providers.get('cnonce-store-provider')
      const nonceValid = await nonceStore$.validate(nonce)
      if (!nonceValid) {
        throw err('INVALID_NONCE', {
          message: 'nonce is not valid.',
        })
      }
      await nonceStore$.revoke(nonce)

      const vcs = vpPayload.vp.verifiableCredential
      if (Array.isArray(vcs)) {
        for (const vc of vcs) {
          if (typeof vc === 'string') {
            const parts = vc.split('.')
            const vcPayload = parts[1]
            if (parts.length !== 3 || !vcPayload) {
              throw err('INVALID_CREDENTIAL', {
                message: 'VC JWT format is invalid.',
              })
            }
            let decoded: Record<string, unknown>
            try {
              decoded = JSON.parse(base64url.decode(vcPayload)) as Record<string, unknown>
            } catch {
              throw err('INVALID_CREDENTIAL', {
                message: 'VC JWT payload is not valid JSON.',
              })
            }
            const credential = decoded.vc ? decoded.vc : decoded
            if (parseVerifiableCredentialBase(credential)) {
              credentials.push([credential, vc])
            }
          } else {
            throw err('ILLEGAL_ARGUMENT', {
              message: 'VC represented as object is not supported.',
            })
          }
        }
      }
      if (!Array.isArray(credentials) || credentials.length === 0) {
        throw err('INVALID_CREDENTIAL', {
          message: 'No credentials is included',
        })
      }

      const credential$ = this.providers.get('verify-verifiable-credential-provider')
      const vcValid = await credential$.verify(credentials[0][1])
      if (!vcValid) {
        throw err('INVALID_CREDENTIAL', {
          message: 'credential is not valid.',
        })
      }

      if (!decodedVp.header.kid) {
        throw err('INVALID_VP_TOKEN', {
          message: `Missing key id in the header: ${JSON.stringify(decodedVp.header)}`,
        })
      }
      const kid = decodedVp.header.kid
      const didSplit = kid.split(':')
      if (didSplit.length < 3 || didSplit[0] !== 'did') {
        throw err('INVALID_PROOF', {
          message: `Invalid DID format: ${kid}`,
        })
      }
      const did$ = this.providers.get('did-provider')
      const didDoc = await selectProvider(did$, didSplit[1]).resolveDid(kid)
      if (!didDoc || !didDoc.verificationMethod) {
        throw err('INVALID_VP_TOKEN', {
          message: `Cannot resolve DID: ${decodedVp.header.kid}`,
        })
      }

      const vm = didDoc.verificationMethod.find(
        // FIXME: this is a hacky way to find the verification method and only works for did:key
        (it) => it.id.startsWith(`${decodedVp.header.kid}`)
      )
      if (!vm || !vm.publicKeyJwk) {
        throw err('INVALID_VP_TOKEN', {
          message: `Cannot find verification method: ${decodedVp.header.kid}`,
        })
      }
      const publicKey = vm.publicKeyJwk
      const jwtSignature$ = this.providers.get('jwt-signature-provider')
      const JwtValid = await jwtSignature$.verify(vp, publicKey)
      if (!JwtValid) {
        throw err('INVALID_PROOF', {
          message: 'jwt is not valid.',
        })
      }
      const holderBinding$ = this.providers.get('holder-binding-provider')
      const holderBindingValid = await holderBinding$.verify(
        credentials.map(([it]) => it),
        publicKey
      )
      if (!holderBindingValid) {
        throw err('HOLDER_BINDING_FAILED', {
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
