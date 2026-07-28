import { Transaction } from '@trustknots/vcknots'
import { VerifierTransactionDataStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

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
      const expiresAt = Timestamp.fromMillis(
        new Date().getTime() + (options?.transaction_data_expire_in ?? 60 * 5 * 1000)
      )

      const docRef = firestore.doc(`${ns}/v1/verifierTransactions/${transactionId}`)
      await docRef.set({
        transaction_id: transactionId,
        transaction_data_expires_at: expiresAt,
        dcqlQuery: record.dcqlQuery,
      })
    },

    async fetch(transactionId) {
      const doc = await firestore.doc(`${ns}/v1/verifierTransactions/${transactionId}`).get()
      if (!doc.exists) {
        return null
      }

      const data = doc.data() as {
        transaction_id: string
        transaction_data_expires_at: Timestamp
        dcqlQuery: Transaction['dcqlQuery']
      }

      if (new Date().getTime() > data.transaction_data_expires_at.toMillis()) {
        await doc.ref.delete()
        return null
      }

      return Transaction({
        transaction_id: transactionId,
        transaction_data_expires_at: data.transaction_data_expires_at.toMillis(),
        dcqlQuery: data.dcqlQuery,
      })
    },

    async delete(transactionId) {
      await firestore.doc(`${ns}/v1/verifierTransactions/${transactionId}`).delete()
    },
  }
}
