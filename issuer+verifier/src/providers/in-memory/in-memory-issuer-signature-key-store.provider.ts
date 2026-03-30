import { CredentialIssuer } from '../../credential-issuer.types'
import { SignatureKeyEntry } from '../../signature-key.types'
import { IssuerSignatureKeyStoreProvider } from '../provider.types'
import { WithProviderRegistry, withProviderRegistry } from '../provider.registry'
import { selectProvider } from '../provider.utils'
import { raise } from '../../errors'
import { CompactSign, importJWK, importPKCS8, importSPKI } from 'jose'

export const inMemoryIssuerSignatureKeyStore = (): IssuerSignatureKeyStoreProvider &
  WithProviderRegistry => {
  const map = new Map<CredentialIssuer, SignatureKeyEntry[]>()

  return {
    kind: 'issuer-signature-key-store-provider',
    name: 'in-memory-issuer-signature-key-store-provider',
    single: true,

    ...withProviderRegistry,

    async save(issuer, keyAlg, pair) {
      const current = map.get(issuer) ?? []
      let pairToSave: SignatureKeyEntry
      if (!pair) {
        const signatureKey$ = this.providers.get('issuer-signature-key-provider')
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
      map.set(issuer, [...values, pairToSave])
    },

    async fetch(issuer, alg) {
      const pairs = map.get(issuer)
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

    async sign(issuer, keyAlg, jwtPayload, jwtHeader) {
      let privateKey = null
      const pairs = map.get(issuer)
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
        throw raise('AUTHZ_ISSUER_KEY_NOT_FOUND', {
          message: 'Issuer private key not found.',
        })
      }
      try {
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
