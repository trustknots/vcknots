import { PreAuthorizedCode } from '../../pre-authorized-code.types'
import { PreAuthorizedCodeStoreProvider } from '../provider.types'

export const inMemoryPreAuthorizedCodeStore = (): PreAuthorizedCodeStoreProvider => {
  const codes = new Set<PreAuthorizedCode>()

  return {
    kind: 'pre-authorized-code-store-provider',
    name: 'in-memory-pre-authorized-code-provider',
    single: true,

    async save(code) {
      codes.add(code)
      return
    },

    async validate(code) {
      return codes.has(code)
    },

    async delete(code) {
      codes.delete(code)
    },
  }
}
