import { VerifierTransactionDataStoreProvider } from '../provider.types'
import { Transaction, TransactionRecord } from '../../transaction-id.types'

const DEFAULT_TRANSACTION_EXPIRE_IN_MS = 5 * 60 * 1000 // 5 minutes

export const inMemoryVerifierTransactionDataStore = (option?: {
  transaction_data_expire_in?: number
}): VerifierTransactionDataStoreProvider => {
  const transactionDataStates = new Map<string, Transaction>()

  return {
    kind: 'verifier-transaction-store-provider',
    name: 'in-memory-transaction-data-provider',
    single: true,

    async save(transactionId, record: TransactionRecord): Promise<void> {
      const expiresAt =
        new Date().getTime() +
        (option?.transaction_data_expire_in ?? DEFAULT_TRANSACTION_EXPIRE_IN_MS)
      transactionDataStates.set(transactionId, {
        transaction_id: transactionId,
        transaction_data_expires_at: expiresAt,
        dcqlQuery: record.dcqlQuery,
        clientId: record.clientId,
        verifierId: record.verifierId,
        state: record.state,
        nonce: record.nonce,
      })
      return
    },

    async fetch(transactionId): Promise<Transaction | null> {
      const transactionDataState = transactionDataStates.get(transactionId)
      if (!transactionDataState) {
        return null
      }
      if (new Date().getTime() > transactionDataState.transaction_data_expires_at) {
        transactionDataStates.delete(transactionId)
        return null
      }
      return transactionDataState
    },

    async delete(transactionId): Promise<void> {
      transactionDataStates.delete(transactionId)
      return
    },
  }
}
