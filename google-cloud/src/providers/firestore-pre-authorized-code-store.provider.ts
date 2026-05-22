import { PreAuthorizedCodeStoreProvider } from '@trustknots/vcknots/providers'
import { PreAuthorizedCodeStoreEntry } from '@trustknots/vcknots'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'
import { hashTxCode } from './hash.utils'
import { raise } from '@trustknots/vcknots/errors'

type FirestorePreAuthorizedCodeDoc = Omit<PreAuthorizedCodeStoreEntry, 'tx_code' | 'expires_at'> & {
  expires_at: Timestamp
  tx_code_hash?: string
}

export const firestorePreAuthorizedCodeStore = (
  options?: FirestoreProviderOptions
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
      const docRef = firestore.doc(`${ns}/v1/preCodes/${code}`)
      const result = await firestore.runTransaction(async (transaction) => {
        const doc = await transaction.get(docRef)
        if (!doc.exists) {
          throw raise('invalid_grant', {
            message: 'Pre-authorized code not found',
          })
        }
        const data = doc.data() as FirestorePreAuthorizedCodeDoc

        if (data.expires_at.toMillis() <= Date.now()) {
          transaction.delete(docRef)
          return { expired: true, credential_configuration_ids: null }
        }
        if (data.tx_code_hash) {
          if (tx_code === undefined) {
            throw raise('invalid_request', {
              message: 'tx_code is required for this pre-authorized code',
            })
          }
          const inputMode = data.tx_code_input_mode ?? 'numeric'
          if (inputMode !== 'text') {
            const actual = toDigitString(tx_code)
            if (actual === null || data.tx_code_hash !== hashTxCode(actual)) {
              throw raise('invalid_grant', {
                message: 'Invalid tx_code provided',
              })
            }
          } else {
            if (typeof tx_code !== 'string' || data.tx_code_hash !== hashTxCode(tx_code)) {
              throw raise('invalid_grant', {
                message: 'Invalid tx_code provided',
              })
            }
          }
          transaction.delete(docRef)
          return {
            expired: false,
            credential_configuration_ids: data.credential_configuration_ids ?? null,
          }
        }
        if (tx_code !== undefined) {
          throw raise('invalid_request', {
            message: 'tx_code should not be provided for this pre-authorized code',
          })
        }

        transaction.delete(docRef)
        return {
          expired: false,
          credential_configuration_ids: data.credential_configuration_ids ?? null,
        }
      })
      if (result.expired) {
        throw raise('invalid_grant', {
          message: 'Pre-authorized code has expired',
        })
      }

      return result.credential_configuration_ids
    },
  }
}
