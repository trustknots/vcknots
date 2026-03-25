import { CompactSign, importJWK, importPKCS8, importSPKI } from 'jose'
import { TmpVerifierSignatureKeyPair } from '../../signature-key.types'
import { VerifierSignatureKeyStoreProvider } from '../provider.types'
import { raise } from '../../errors'

export const inMemoryVerifierSignatureKeyStore = (): VerifierSignatureKeyStoreProvider => {
  const map = new Map<string, TmpVerifierSignatureKeyPair[]>()

  return {
    kind: 'verifier-signature-key-store-provider',
    name: 'in-memory-verifier-signature-key-store-provider',
    single: true,

    async save(verifier, pairs) {
      const current = map.get(verifier) ?? []
      const values = current.filter((c) => !pairs.some((p) => c.declaredAlg === p.declaredAlg))
      map.set(verifier, [...values, ...pairs])
    },

    async fetch(verifier, alg) {
      const pairs = map.get(verifier)
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

    async sign(verifier, keyAlg, jwtPayload, jwtHeader) {
      try {
        let privateKey = null
        const pairs = map.get(verifier)
        if (!pairs) return null
        const value = pairs.find((c) => c.declaredAlg === keyAlg) ?? null
        if (value) {
          if (value.privateKey && value.format === 'jwk' && typeof value.privateKey !== 'string') {
            const key = await importJWK(value.privateKey, value.declaredAlg)
            privateKey = key instanceof Uint8Array ? null : key
          }
          if (value.privateKey && typeof value.privateKey === 'string') {
            const key = await importPKCS8(value.privateKey, value.declaredAlg)
            privateKey = key
          }
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
        throw raise('INTERNAL_SERVER_ERROR', { message: `sign error: ${error}` })
      }
    },
  }
}
