import { raise } from '../../errors'
import { PreAuthorizedCode, PreAuthorizedCodeStoreEntry } from '../../pre-authorized-code.types'
import { PreAuthorizedCodeStoreProvider } from '../provider.types'

export type InMemoryPreAuthorizedCodeStoreOptions = {
  /**
   * Number of failed `tx_code` attempts allowed per pre-authorized code before it
   * is invalidated (brute-force lockout). Defaults to 5.
   */
  maxTxCodeAttempts?: number
}

type InMemoryPreAuthorizedCodeEntry = PreAuthorizedCodeStoreEntry & {
  /** Number of failed `tx_code` attempts so far (brute-force lockout counter). */
  attempts?: number
}

const DEFAULT_MAX_TX_CODE_ATTEMPTS = 5
const LOCKED_MESSAGE = 'Pre-authorized code is invalid, consumed, or locked'

export const inMemoryPreAuthorizedCodeStore = (
  options?: InMemoryPreAuthorizedCodeStoreOptions
): PreAuthorizedCodeStoreProvider => {
  const codes = new Map<PreAuthorizedCode, InMemoryPreAuthorizedCodeEntry>()
  const maxTxCodeAttemptsRaw = options?.maxTxCodeAttempts ?? DEFAULT_MAX_TX_CODE_ATTEMPTS
  const maxTxCodeAttempts = Number.isFinite(maxTxCodeAttemptsRaw)
    ? Math.max(1, Math.floor(maxTxCodeAttemptsRaw))
    : DEFAULT_MAX_TX_CODE_ATTEMPTS

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

    async save(code, credentialConfigurationIds, tx_code, saveOptions) {
      const ttlSecRaw = Number(saveOptions?.ttlSec ?? 300)
      const ttlSecCandidate = Math.floor(ttlSecRaw)
      const ttlSec = Number.isFinite(ttlSecRaw) && ttlSecCandidate > 0 ? ttlSecCandidate : 300
      const tx_code_input_mode = saveOptions?.tx_code_input_mode ?? 'numeric'
      const expiresAt = new Date().getTime() + ttlSec * 1000

      let storedTxCode = tx_code
      if (tx_code !== undefined && tx_code_input_mode !== 'text') {
        const canonical = toDigitString(tx_code)
        if (canonical === null) {
          raise('invalid_tx_code', {
            message: 'tx_code must be a non-negative integer for numeric input mode',
          })
        } else {
          // Keep the canonical digit-string so leading zeros survive round-trips.
          storedTxCode = canonical
        }
      }

      codes.set(code, {
        code,
        credential_configuration_ids: credentialConfigurationIds,
        tx_code: storedTxCode,
        tx_code_input_mode,
        expires_at: expiresAt,
      })
      return
    },

    // validate and fetch credential configuration ids
    async consume(code, tx_code) {
      // Count-first admission gate (brute-force lockout): increment `attempts`
      // only while the code still exists AND the per-code limit hasn't been reached,
      // then compare the tx_code. Once the limit is hit, every further attempt
      // (including the correct PIN) is rejected before the tx_code is compared.
      const entry = codes.get(code)
      if (!entry) {
        throw raise('invalid_grant', { message: LOCKED_MESSAGE })
      }
      const currentAttempts = entry.attempts ?? 0
      if (currentAttempts >= maxTxCodeAttempts) {
        throw raise('invalid_grant', { message: LOCKED_MESSAGE })
      }
      const attempts = currentAttempts + 1
      const item: InMemoryPreAuthorizedCodeEntry = { ...entry, attempts }
      codes.set(code, item)

      const lockoutIfExhausted = (): void => {
        if ((item.attempts ?? 0) >= maxTxCodeAttempts) {
          codes.delete(code)
          raise('invalid_grant', { message: LOCKED_MESSAGE })
        }
      }

      if (item.expires_at && item.expires_at < new Date().getTime()) {
        codes.delete(code)
        throw raise('invalid_grant', {
          message: 'Pre-authorized code has expired',
        })
      }

      if (item.tx_code !== undefined) {
        if (tx_code === undefined) {
          lockoutIfExhausted()
          throw raise('invalid_request', {
            message: 'tx_code is required for this pre-authorized code',
          })
        }
        if (item.tx_code_input_mode !== 'text') {
          const expected = toDigitString(item.tx_code)
          const actual = toDigitString(tx_code)
          if (expected === null || actual === null || expected !== actual) {
            lockoutIfExhausted()
            throw raise('invalid_grant', {
              message: 'Invalid tx_code provided',
            })
          }
        } else {
          if (item.tx_code !== tx_code) {
            lockoutIfExhausted()
            throw raise('invalid_grant', {
              message: 'Invalid tx_code provided',
            })
          }
        }
      } else if (tx_code !== undefined) {
        lockoutIfExhausted()
        throw raise('invalid_request', {
          message: 'tx_code should not be provided for this pre-authorized code',
        })
      }

      // Delete to prevent the code from being consumed twice.
      codes.delete(code)
      return item.credential_configuration_ids
    },
  }
}
