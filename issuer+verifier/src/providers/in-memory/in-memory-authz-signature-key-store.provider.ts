import { AuthorizationServerIssuer } from '../../authorization-server.types'
import { raise } from '../../errors/vcknots.error'
import { SignatureKeyEntry } from '../../signature-key.types'
import { AuthzSignatureKeyStoreProvider } from '../provider.types'
import { WithProviderRegistry, withProviderRegistry } from '../provider.registry'
import { selectProvider } from '../provider.utils'
import { CompactSign, importJWK, importPKCS8, importSPKI } from 'jose'

export const inMemoryAuthzSignatureKeyStore = (option?: {
  key_alg?: string
}): AuthzSignatureKeyStoreProvider & WithProviderRegistry => {
  const map = new Map<AuthorizationServerIssuer, SignatureKeyEntry[]>()

  return {
    kind: 'authz-signature-key-store-provider',
    name: 'in-memory-authz-signature-key-store-provider',
    single: true,

    ...withProviderRegistry,

    async save(authz, keyAlg, pair) {
      const current = map.get(authz) ?? []
      let pairToSave: SignatureKeyEntry
      if (!pair) {
        const signatureKey$ = this.providers.get('authz-signature-key-provider')
        const keyPair = await selectProvider(signatureKey$, keyAlg).generate()
        pairToSave = {
          ...keyPair,
          format: 'jwk',
          declaredAlg: keyAlg,
        }
      } else {
        if (pair.declaredAlg !== keyAlg) {
          throw raise('ILLEGAL_ARGUMENT', {
            message: `The provided key pair algorithm ${pair.declaredAlg} does not match the requested key algorithm ${keyAlg}.`,
          })
        }
        pairToSave = pair
      }
      const values = current.filter((c) => c.declaredAlg !== keyAlg)
      map.set(authz, [...values, pairToSave])
    },

    async fetch(authz, alg) {
      const pairs = map.get(authz)
      if (!pairs) return null
      const value = pairs.find((c) => c.declaredAlg === alg) ?? null
      if (value) {
        const publicKey = value.publicKey
        if (publicKey && value.format === 'jwk' && typeof publicKey !== 'string') {
          const key = await importJWK(publicKey, value.declaredAlg)
          return key instanceof Uint8Array ? null : key
        }
        if (publicKey && typeof publicKey === 'string') {
          const key = await importSPKI(publicKey, value.declaredAlg)
          return key
        }
      }
      return null
    },

    async sign(authz, keyAlg, jwtPayload, jwtHeader) {
      try {
        let privateKey = null
        const pairs = map.get(authz)
        if (!pairs) return null
        const value = pairs.find((c) => c.declaredAlg === keyAlg) ?? null
        if (!value) return null
        if (value.privateKey && value.format === 'jwk' && typeof value.privateKey !== 'string') {
          const key = await importJWK(value.privateKey, value.declaredAlg)
          privateKey = key instanceof Uint8Array ? null : key
        }
        if (value.privateKey && typeof value.privateKey === 'string') {
          const key = await importPKCS8(value.privateKey, value.declaredAlg)
          privateKey = key
        }
        if (!privateKey) {
          throw raise('AUTHZ_VERIFIER_KEY_NOT_FOUND', {
            message: 'Verifier private key not found.',
          })
        }
        const signer = new CompactSign(new TextEncoder().encode(JSON.stringify(jwtPayload)))
        signer.setProtectedHeader({ ...jwtHeader })
        const jws = await signer.sign(privateKey)
        const [, , signature] = jws.split('.')
        return signature
      } catch (error) {
        if (error instanceof Error && error.name === 'AUTHZ_VERIFIER_KEY_NOT_FOUND') {
          throw error
        }
        throw raise('INTERNAL_SERVER_ERROR', { message: `sign error: ${error}` })
      }
    },
  }
}
