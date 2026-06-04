import { CredentialIssuanceStoreEntry } from '../../credential-issuance-context.types'
import { IssuanceContextStoreProvider } from '../provider.types'

export const inMemoryIssuanceContextStore = (): IssuanceContextStoreProvider => {
  const contexts = new Map<string, CredentialIssuanceStoreEntry>()

  return {
    kind: 'issuance-context-store-provider',
    name: 'in-memory-issuance-context-store-provider',
    single: true,

    async save(jti, credential_configuration_ids, ttl) {
      const ttlSecRaw = Number(ttl ?? 300)
      const ttlSecCandidate = Math.floor(ttlSecRaw)
      const ttlSec = Number.isFinite(ttlSecRaw) && ttlSecCandidate > 0 ? ttlSecCandidate : 300
      const expiresAt = new Date().getTime() + ttlSec * 1000
      contexts.set(jti, { credential_configuration_ids, expires_at: expiresAt })
    },

    async fetch(jti) {
      const context = contexts.get(jti)
      if (!context) {
        return null
      }
      if (context.expires_at && context.expires_at < new Date().getTime()) {
        contexts.delete(jti)
        return null
      }
      return context.credential_configuration_ids
    },

    async delete(jti) {
      contexts.delete(jti)
    },
  }
}
