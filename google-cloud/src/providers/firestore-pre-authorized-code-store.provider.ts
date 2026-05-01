import { PreAuthorizedCodeStoreProvider } from '@trustknots/vcknots/providers'
import { PreAuthorizedCodeStoreEntry } from '@trustknots/vcknots'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'
import { hashTxCode } from './hash.utils'
import { raise } from '@trustknots/vcknots/errors'

type FirestorePreAuthorizedCodeDoc = Omit<PreAuthorizedCodeStoreEntry, 'tx_code'> & {
  tx_code_hash?: string
}

export const firestorePreAuthorizedCodeStore = (
  options?: FirestoreProviderOptions & { expiresIn?: number }
): PreAuthorizedCodeStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'
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

    async save(code, tx_code, options) {
      const ttlSec = options?.ttlSec ?? 300
      const tx_code_input_mode = options?.tx_code_input_mode ?? 'numeric'
      const expiresAt = new Date().getTime() + ttlSec * 1000
      const docRef = firestore.doc(`${ns}/v1/preCodes/${code}`)

      const data: FirestorePreAuthorizedCodeDoc = {
        code,
        tx_code_input_mode,
        expires_at: expiresAt,
      }

      if (tx_code !== undefined) {
        if (tx_code_input_mode !== 'text') {
          const canonical = toDigitString(tx_code)
          if (canonical === null) {
            raise('INVALID_TX_CODE', {
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
    async validate(code, tx_code) {
      const doc = await firestore.doc(`${ns}/v1/preCodes/${code}`).get()
      if (!doc.exists) {
        throw raise('INVALID_GRANT', {
          message: 'Pre-authorized code not found',
        })
      }
      const data = doc.data() as FirestorePreAuthorizedCodeDoc

      if (data.expires_at && data.expires_at < new Date().getTime()) {
        await firestore.doc(`${ns}/v1/preCodes/${code}`).delete()
        throw raise('INVALID_GRANT', {
          message: 'Pre-authorized code has expired',
        })
      }

      if (data.tx_code_hash) {
        if (tx_code === undefined) {
          throw raise('INVALID_REQUEST', {
            message: 'tx_code is required for this pre-authorized code',
          })
        }
        const inputMode = data.tx_code_input_mode ?? 'numeric'
        if (inputMode !== 'text') {
          const actual = toDigitString(tx_code)
          if (actual === null || data.tx_code_hash !== hashTxCode(actual)) {
            throw raise('INVALID_GRANT', {
              message: 'Invalid tx_code provided',
            })
          }
        } else {
          if (typeof tx_code !== 'string' || data.tx_code_hash !== hashTxCode(tx_code)) {
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

      return true
    },
    async delete(code) {
      await firestore.doc(`${ns}/v1/preCodes/${code}`).delete()
    },
  }
}
