import { raise } from '../../errors'
import { PreAuthorizedCode, PreAuthorizedCodeStoreEntry } from '../../pre-authorized-code.types'
import { PreAuthorizedCodeStoreProvider } from '../provider.types'

export const inMemoryPreAuthorizedCodeStore = (): PreAuthorizedCodeStoreProvider => {
  const codes = new Map<PreAuthorizedCode, PreAuthorizedCodeStoreEntry>()
  const toDigitString = (value: string | number): string | null => {
    if (typeof value === 'number') {
      return Number.isSafeInteger(value) && value >= 0 ? value.toString() : null
    }
    return /^\d+$/.test(value) ? value : null
  }

  return {
    kind: 'pre-authorized-code-store-provider',
    name: 'in-memory-pre-authorized-code-provider',
    single: true,

    async save(code, tx_code, options) {
      const ttlSecRaw = Number(options?.ttlSec ?? 300)
      const ttlSecCandidate = Math.floor(ttlSecRaw)
      const ttlSec = Number.isFinite(ttlSecRaw) && ttlSecCandidate > 0 ? ttlSecCandidate : 300
      const tx_code_input_mode = options?.tx_code_input_mode ?? 'numeric'
      const expiresAt = new Date().getTime() + ttlSec * 1000
      codes.set(code, { code, tx_code, tx_code_input_mode, expires_at: expiresAt })
      return
    },

    async validate(code, tx_code) {
      const entry = codes.get(code)
      if (!entry) {
        throw raise('INVALID_GRANT', {
          message: 'Pre-authorized code not found',
        })
      }
      if (entry.expires_at && entry.expires_at < new Date().getTime()) {
        codes.delete(code)
        throw raise('INVALID_GRANT', {
          message: 'Pre-authorized code has expired',
        })
      }
      if (entry.tx_code !== undefined) {
        if (tx_code === undefined) {
          throw raise('INVALID_REQUEST', {
            message: 'tx_code is required for this pre-authorized code',
          })
        }
        if (entry.tx_code_input_mode !== 'text') {
          const expected = toDigitString(entry.tx_code)
          const actual = toDigitString(tx_code)
          if (expected === null || actual === null || expected !== actual) {
            throw raise('INVALID_GRANT', {
              message: 'Invalid tx_code provided',
            })
          }
        } else {
          if (entry.tx_code !== tx_code) {
            throw raise('INVALID_GRANT', {
              message: 'Invalid tx_code provided',
            })
          }
        }
        return true
      }
      if (tx_code !== undefined) {
        throw raise('INVALID_REQUEST', {
          message: 'tx_code should not be provided for this pre-authorized code',
        })
      }
      return codes.has(code)
    },

    async delete(code) {
      codes.delete(code)
    },
  }
}
