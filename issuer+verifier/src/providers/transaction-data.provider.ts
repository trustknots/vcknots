import base64url from 'base64url'
import { TransactionDataProvider } from './provider.types'

export const transactionData = (): TransactionDataProvider => {
  return {
    kind: 'transaction-data-provider',
    name: 'default-transaction-data-provider',
    single: true,

    generate(
      type: string,
      credential_ids: string[],
      transaction_data_hashes_alg?: string[]
    ): string {
      const data = {
        type,
        credential_ids,
        transaction_data_hashes_alg: transaction_data_hashes_alg || ['sha256'],
      }
      return base64url.encode(JSON.stringify(data))
    },
  }
}
