import { PreAuthorizedCodeStoreProvider } from '@trustknots/vcknots/providers'
import { PreAuthorizedCodeStoreEntry } from '@trustknots/vcknots'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'
import { hashTxCode } from './hash.utils'
import { raise } from '@trustknots/vcknots/errors'

export type FirestorePreAuthorizedCodeStoreOptions = FirestoreProviderOptions & {
  /**
   * Number of failed `tx_code` attempts allowed per pre-authorized code before it
   * is invalidated (brute-force lockout). Defaults to 5.
   */
  maxTxCodeAttempts?: number
}

type FirestorePreAuthorizedCodeDoc = Omit<PreAuthorizedCodeStoreEntry, 'tx_code' | 'expires_at'> & {
  expires_at: Timestamp
  tx_code_hash?: string
  /** Number of failed `tx_code` attempts so far (brute-force lockout counter). */
  attempts?: number
}

const DEFAULT_MAX_TX_CODE_ATTEMPTS = 5
const LOCKED_MESSAGE = 'Pre-authorized code is invalid, consumed, or locked'

export const firestorePreAuthorizedCodeStore = (
  options?: FirestorePreAuthorizedCodeStoreOptions
): PreAuthorizedCodeStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'
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
    name: 'firestore-pre-authorized-code-store-provider',
    single: true,

    async save(code, credentialConfigurationIds, tx_code, saveOptions) {
      const ttlSecRaw = Number(saveOptions?.ttlSec ?? 300)
      const ttlSecCandidate = Math.floor(ttlSecRaw)
      const ttlSec = Number.isFinite(ttlSecRaw) && ttlSecCandidate > 0 ? ttlSecCandidate : 300
      const tx_code_input_mode = saveOptions?.tx_code_input_mode ?? 'numeric'
      const expiresAt = Timestamp.fromMillis(Date.now() + ttlSec * 1000)
      const docRef = firestore.doc(`${ns}/v1/preCodes/${code}`)

      const data: FirestorePreAuthorizedCodeDoc = {
        code,
        credential_configuration_ids: credentialConfigurationIds,
        tx_code_input_mode,
        expires_at: expiresAt,
      }

      if (tx_code !== undefined) {
        if (tx_code_input_mode !== 'text') {
          const canonical = toDigitString(tx_code)
          if (canonical === null) {
            raise('invalid_tx_code', {
              message: 'tx_code must be a non-negative integer for numeric input mode',
            })
          }
          data.tx_code_hash = hashTxCode(canonical)
        } else {
          data.tx_code_hash = hashTxCode(tx_code)
        }
      }

      await docRef.set(data)
    },

    async consume(code, tx_code) {
      // Count-first admission gate (brute-force lockout): atomically increment `attempts`
      // only while the code still exists AND the per-code limit hasn't been reached, then
      // read the item back to compare the tx_code. Firestore transactions serialize writes
      // per document, so even a highly concurrent burst admits at most `maxTxCodeAttempts`
      // guesses — once the limit is hit, every further attempt (including the correct PIN)
      // is rejected before the tx_code is ever compared.
      const docRef = firestore.doc(`${ns}/v1/preCodes/${code}`)
      const item = await firestore.runTransaction(async (transaction) => {
        const doc = await transaction.get(docRef)
        if (!doc.exists) {
          // Not found, already consumed, or locked out after too many tx_code attempts.
          throw raise('invalid_grant', { message: LOCKED_MESSAGE })
        }
        const data = doc.data() as FirestorePreAuthorizedCodeDoc
        const currentAttempts = data.attempts ?? 0
        if (currentAttempts >= maxTxCodeAttempts) {
          throw raise('invalid_grant', { message: LOCKED_MESSAGE })
        }
        const attempts = currentAttempts + 1
        transaction.set(docRef, { attempts }, { merge: true })
        return { ...data, attempts }
      })

      const lockoutIfExhausted = async (): Promise<void> => {
        if ((item.attempts ?? 0) >= maxTxCodeAttempts) {
          await docRef.delete()
          raise('invalid_grant', { message: LOCKED_MESSAGE })
        }
      }

      if (item.expires_at.toMillis() <= Date.now()) {
        await docRef.delete()
        throw raise('invalid_grant', {
          message: 'Pre-authorized code has expired',
        })
      }

      if (item.tx_code_hash) {
        if (tx_code === undefined) {
          await lockoutIfExhausted()
          throw raise('invalid_request', {
            message: 'tx_code is required for this pre-authorized code',
          })
        }
        const inputMode = item.tx_code_input_mode ?? 'numeric'
        if (inputMode !== 'text') {
          const actual = toDigitString(tx_code)
          if (actual === null || item.tx_code_hash !== hashTxCode(actual)) {
            await lockoutIfExhausted()
            throw raise('invalid_grant', {
              message: 'Invalid tx_code provided',
            })
          }
        } else {
          if (typeof tx_code !== 'string' || item.tx_code_hash !== hashTxCode(tx_code)) {
            await lockoutIfExhausted()
            throw raise('invalid_grant', {
              message: 'Invalid tx_code provided',
            })
          }
        }
      } else if (tx_code !== undefined) {
        await lockoutIfExhausted()
        throw raise('invalid_request', {
          message: 'tx_code should not be provided for this pre-authorized code',
        })
      }

      // Delete to prevent the code from being consumed twice.
      await docRef.delete()

      return item.credential_configuration_ids ?? null
    },
  }
}
