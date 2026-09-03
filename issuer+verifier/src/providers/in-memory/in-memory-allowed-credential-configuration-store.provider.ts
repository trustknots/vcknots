import { AllowedCredentialConfigurationStoreEntry } from '../../allowed-credential-configuration.types'
import { AllowedCredentialConfigurationStoreProvider } from '../provider.types'

export const inMemoryAllowedCredentialConfigurationStore = (): AllowedCredentialConfigurationStoreProvider => {
  const allowedCredentialConfigurations = new Map<
    string,
    AllowedCredentialConfigurationStoreEntry
  >()

  return {
    kind: 'allowed-credential-configuration-store-provider',
    name: 'in-memory-allowed-credential-configuration-store-provider',
    single: true,

    async save(accessTokenHash, credential_configuration_ids, ttl) {
      const ttlSecRaw = Number(ttl ?? 300)
      const ttlSecCandidate = Math.floor(ttlSecRaw)
      const ttlSec = Number.isFinite(ttlSecRaw) && ttlSecCandidate > 0 ? ttlSecCandidate : 300
      const expiresAt = new Date().getTime() + ttlSec * 1000
      allowedCredentialConfigurations.set(accessTokenHash, {
        credential_configuration_ids,
        expires_at: expiresAt,
      })
    },

    async fetch(accessTokenHash) {
      const entry = allowedCredentialConfigurations.get(accessTokenHash)
      if (!entry) {
        return null
      }
      if (entry.expires_at && entry.expires_at < new Date().getTime()) {
        allowedCredentialConfigurations.delete(accessTokenHash)
        return null
      }
      return entry.credential_configuration_ids
    },

    async delete(accessTokenHash) {
      allowedCredentialConfigurations.delete(accessTokenHash)
    },
  }
}
