import { Transaction } from '@trustknots/vcknots'
import { VerifierTransactionDataStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

const ensureSafeTransactionId = (transactionId: string): string => {
  if (!/^[A-Za-z0-9_-]+$/.test(transactionId)) {
    throw new Error('Invalid transaction ID')
  }
  return transactionId
}

export const firestoreVerifierTransactionDataStore = (
  options?: FirestoreProviderOptions & { transaction_data_expire_in?: number }
): VerifierTransactionDataStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'

  return {
    kind: 'verifier-transaction-data-store-provider',
    name: 'firestore-verifier-transaction-data-store-provider',
    single: true,

    async save(transactionId, record) {
      const safeTransactionId = ensureSafeTransactionId(transactionId)
      const expiresAt = Timestamp.fromMillis(
        new Date().getTime() + (options?.transaction_data_expire_in ?? 60 * 5 * 1000)
      )

      const docRef = firestore.doc(`${ns}/v1/verifierTransactions/${safeTransactionId}`)
      await docRef.set({
        transaction_id: transactionId,
        transaction_data_expires_at: expiresAt,
        dcqlQuery: record.dcqlQuery,
        clientId: record.clientId,
        ...(record.state !== undefined ? { state: record.state } : {}),
        ...(record.nonce !== undefined ? { nonce: record.nonce } : {}),
      })
    },

    async fetch(transactionId) {
      const safeTransactionId = ensureSafeTransactionId(transactionId)
      const doc = await firestore.doc(`${ns}/v1/verifierTransactions/${safeTransactionId}`).get()
      if (!doc.exists) {
        return null
      }

      const data = doc.data() as {
        transaction_id: string
        transaction_data_expires_at: Timestamp
        dcqlQuery: Transaction['dcqlQuery']
        clientId: Transaction['clientId']
        state?: string
        nonce?: string
      }

      if (new Date().getTime() > data.transaction_data_expires_at.toMillis()) {
        await doc.ref.delete()
        return null
      }

      return Transaction({
        transaction_id: transactionId,
        transaction_data_expires_at: data.transaction_data_expires_at.toMillis(),
        dcqlQuery: data.dcqlQuery,
        clientId: data.clientId,
        state: data.state,
        nonce: data.nonce,
      })
    },

    async delete(transactionId) {
      const safeTransactionId = ensureSafeTransactionId(transactionId)
      await firestore.doc(`${ns}/v1/verifierTransactions/${safeTransactionId}`).delete()
    },
  }
}
