import { DPoPProofJtiStoreProvider } from '../provider.types'

const DEFAULT_DPOP_PROOF_JTI_TTL_MS = 6 * 60 * 1000

export const inMemoryDpopProofJtiStore = (): DPoPProofJtiStoreProvider => {
  const usedJtis = new Map<string, number>()

  const toKey = (jwkThumbprint: string, jti: string) => `${jwkThumbprint}:${jti}`

  return {
    kind: 'dpop-proof-jti-store-provider',
    name: 'in-memory-dpop-proof-jti-store-provider',
    single: true,

    async saveIfAbsent(jwkThumbprint, jti, options): Promise<boolean> {
      const key = toKey(jwkThumbprint, jti)
      const now = Date.now()
      const currentExpiresAt = usedJtis.get(key)
      if (currentExpiresAt !== undefined) {
        if (now <= currentExpiresAt) {
          return false
        }
        usedJtis.delete(key)
      }

      usedJtis.set(key, now + (options?.ttlMs ?? DEFAULT_DPOP_PROOF_JTI_TTL_MS))
      return true
    },
  }
}
