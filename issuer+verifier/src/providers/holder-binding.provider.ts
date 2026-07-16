import { HolderBindingProvider } from './provider.types'
import { err, raise } from '../errors/vcknots.error'
import { createPublicKey } from 'node:crypto'
import { Jwk } from '../jwk.type'
import { selectProvider } from './provider.utils'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'

export const holderBinding = (): HolderBindingProvider & WithProviderRegistry => {
  return {
    kind: 'holder-binding-provider',
    name: 'default-holder-binding-provider',
    single: true,

    ...withProviderRegistry,

    async verify(credentials, publicKey): Promise<boolean> {
      for (const vc of credentials) {
        if (!vc.credentialSubject) {
          throw err('invalid_credential', {
            message: `Missing credentialSubject in VC: ${vc.id}`,
          })
        }

        if (!vc.credentialSubject.id) {
          throw err('invalid_credential', {
            message: `Missing credentialSubject.id in VC: ${vc.id}`,
          })
        }

        const didSplit = vc.credentialSubject.id.split(':')
        if (didSplit.length < 3 || didSplit[0] !== 'did') {
          throw raise('invalid_proof', {
            message: `Invalid DID format: ${vc.credentialSubject.id}`,
          })
        }
        const didProvider$ = this.providers.get('did-provider')
        if (!didProvider$ || didProvider$.length === 0) {
          throw raise('invalid_proof', {
            message: 'No kid or unsupported did type detected.',
          })
        }
        const didProvider = selectProvider(didProvider$, didSplit[1])
        const didDoc = await didProvider.resolveDid(vc.credentialSubject.id)

        if (!didDoc || !didDoc.verificationMethod) {
          throw err('invalid_credential', {
            message: `Cannot resolve DID: ${vc.credentialSubject.id}`,
          })
        }

        let success = false
        for (const vm of didDoc.verificationMethod) {
          if (!vm.publicKeyJwk) {
            throw err('invalid_credential', {
              message: `Missing publicKeyJwk in DID: ${vc.credentialSubject.id}`,
            })
          }

          function convertJwkToPem(jwk: Jwk): string {
            const key = createPublicKey({ key: jwk, format: 'jwk' })
            const e = key.export({ format: 'pem', type: 'spki' })
            return e.toString()
          }

          const subPubKey = convertJwkToPem(vm.publicKeyJwk as Jwk)
          const _pubKeyBase64 = convertJwkToPem(publicKey as Jwk)
          if (_pubKeyBase64 === subPubKey) {
            success = true
            break
          }
        }

        if (!success) {
          throw err('invalid_credential', {
            message: `Binding verification failed for VC: ${vc.id}`,
          })
        }
      }

      return true
    },
  }
}
