import base64url from 'base64url'
import * as jwt from 'jsonwebtoken'
import { err } from '../errors/vcknots.error'
import { VerifyVerifiablePresentationProvider } from './provider.types'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'
import { VerifiableCredential, parseVerifiableCredentialBase } from '../credential.types'
import { selectProvider } from './provider.utils'

export const verifyVerifiablePresentation = (): VerifyVerifiablePresentationProvider &
  WithProviderRegistry => {
  return {
    kind: 'verify-verifiable-presentation-provider',
    name: 'verifier-verifiable-presentation-jwt-vp-json-provider',
    single: false,

    ...withProviderRegistry,

    async verify(vp, options): Promise<boolean> {
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
      const payload =
        typeof decodedVp.payload === 'string' ? JSON.parse(decodedVp.payload) : decodedVp.payload

      const nonce = payload.nonce
      const nonceStore$ = this.providers.get('cnonce-store-provider')
      const nonceValid = await nonceStore$.validate(nonce)
      if (!nonceValid) {
        throw err('INVALID_NONCE', {
          message: 'nonce is not valid.',
        })
      }
      await nonceStore$.revoke(nonce)
      console.log('Decoded VP payload:', payload)

      const vcs = payload.vp.verifiableCredential
      if (Array.isArray(vcs)) {
        for (const vc of vcs) {
          if (typeof vc === 'string') {
            const parts = vc.split('.')
            const payload = parts[1]
            const decoded = JSON.parse(base64url.decode(payload))
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
      if (!didDoc.id.startsWith('did:key:')) {
        throw err('INVALID_VP_TOKEN', {
          message: `Unsupported DID method: ${didDoc.id}`,
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

      return true
    },
    canHandle(format: string): boolean {
      return format === 'jwt_vp_json'
    },
  }
}
