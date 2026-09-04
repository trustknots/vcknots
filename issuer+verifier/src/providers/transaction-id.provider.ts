import { randomUUID } from 'node:crypto'
import { TransactionId } from '../transaction-id.types'
import { TransactionIdProvider } from './provider.types'

export const transactionId = (): TransactionIdProvider => {
  return {
    kind: 'transaction-id-provider',
    name: 'default-transaction-id-provider',
    single: true,

    async generate(): Promise<TransactionId> {
      return TransactionId(randomUUID().replaceAll('-', ''))
    },
  }
}
