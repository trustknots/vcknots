import { CredentialConfigurationId } from '../../credential-issuer.types'
import { PreAuthorizedCode } from '../../pre-authorized-code.types'
import { PreAuthorizedCodeStoreProvider } from '../provider.types'

export const inMemoryPreAuthorizedCodeStore = (): PreAuthorizedCodeStoreProvider => {
  // const codes = new Set<PreAuthorizedCode>()
  const codes = new Map<PreAuthorizedCode, CredentialConfigurationId[]>()

  return {
    kind: 'pre-authorized-code-store-provider',
    name: 'in-memory-pre-authorized-code-provider',
    single: true,

    async save(code, credentialConfigurationIds) {
      codes.set(code, credentialConfigurationIds)
      return
    },

    async validate(code) {
      return codes.get(code) ?? null
    },

    async delete(code) {
      codes.delete(code)
    },
  }
}
