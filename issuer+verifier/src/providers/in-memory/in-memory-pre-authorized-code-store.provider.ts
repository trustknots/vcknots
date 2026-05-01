import { PreAuthorizedCode, PreAuthorizedCodeStoreEntry } from '../../pre-authorized-code.types'
import { PreAuthorizedCodeStoreProvider } from '../provider.types'

export const inMemoryPreAuthorizedCodeStore = (): PreAuthorizedCodeStoreProvider => {
  const codes = new Map<PreAuthorizedCode, PreAuthorizedCodeStoreEntry>()
  const toNumericCode = (value: string | number): number | null => {
    if (typeof value === 'number') {
      return Number.isInteger(value) && value >= 0 ? value : null
    }
    if (!/^\d+$/.test(value)) {
      return null
    }
    const parsed = Number(value)
    return Number.isSafeInteger(parsed) ? parsed : null
  }

  return {
    kind: 'pre-authorized-code-store-provider',
    name: 'in-memory-pre-authorized-code-provider',
    single: true,

    async save(code, tx_code, options) {
      const ttlSec = options?.ttlSec ?? 300
      const tx_code_input_mode = options?.tx_code_input_mode ?? 'numeric'
      const expiresAt = new Date().getTime() + ttlSec * 1000
      codes.set(code, { code, tx_code, tx_code_input_mode, expires_at: expiresAt })
      return
    },

    async validate(code, tx_code) {
      const entry = codes.get(code)
      if (!entry) {
        return false
      }
      if (entry.expires_at && entry.expires_at < new Date().getTime()) {
        codes.delete(code)
        return false
      }
      if (entry.tx_code !== undefined) {
        if (entry.tx_code_input_mode !== 'text') {
          if (tx_code === undefined) {
            return false
          }
          const expected = toNumericCode(entry.tx_code)
          const actual = toNumericCode(tx_code)
          if (expected === null || actual === null || expected !== actual) {
            return false
          }
        } else {
          if (entry.tx_code !== tx_code) {
            return false
          }
        }
        return true
      }
      return codes.has(code)
    },

    async delete(code) {
      codes.delete(code)
    },
  }
}
