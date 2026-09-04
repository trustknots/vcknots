import { WithProviderRegistry, withProviderRegistry } from '../provider.registry'
import { EncryptionKeyEntry } from '../../encryption-key.types'
import { VerifierEncryptionKeyStoreProvider } from '../provider.types'
import { selectProvider } from '../provider.utils'

export const inMemoryVerifierEncryptionKeyStore = (): VerifierEncryptionKeyStoreProvider &
  WithProviderRegistry => {
  const map = new Map<string, EncryptionKeyEntry[]>()

  return {
    kind: 'verifier-encryption-key-store-provider',
    name: 'in-memory-verifier-encryption-key-store-provider',
    single: true,

    ...withProviderRegistry,

    async save(verifier, keyAlg) {
      const current = map.get(verifier) ?? []
      const encryptionKey$ = this.providers.get('verifier-encryption-key-provider')
      const keyPair = await selectProvider(encryptionKey$, keyAlg).generate()

      const pairToSave: EncryptionKeyEntry = {
        ...keyPair,
        declaredAlg: keyAlg,
      }
      const values = current.filter((c) => c.declaredAlg !== keyAlg)

      map.set(verifier, [...values, pairToSave])
    },
    async fetch(verifier, keyAlg) {
      const pairs = map.get(verifier)
      if (!pairs) return null

      const value = pairs.find((c) => c.declaredAlg === keyAlg) ?? null

      if (!value) return null

      return value.publicKey
    },
  }
}
