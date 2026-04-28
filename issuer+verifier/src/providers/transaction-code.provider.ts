import { err } from '../errors'
import { TransactionCodeProvider } from './provider.types'

export const transactionCode = (): TransactionCodeProvider => {
  return {
    kind: 'transaction-code-provider',
    name: 'default-transaction-code-provider',
    single: true,

    generate(
      input_mode?: 'numeric' | 'text',
      length?: number,
      description?: string
    ): string | number {
      const len = length ?? 6
      if (len >= 10) {
        throw err('INVALID_TX_CODE_OPTIONS', {
          message: 'Length must be less than 10',
        })
      }
      if (description?.length && description.length > 300) {
        throw err('INVALID_TX_CODE_OPTIONS', {
          message: 'Description must be less than 300 characters',
        })
      }

      if (input_mode === 'numeric') {
        const min = 10 ** (len - 1)
        const max = 10 ** len - 1
        return Math.floor(Math.random() * (max - min + 1)) + min
      }

      if (input_mode === 'text') {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        let result = ''
        for (let i = 0; i < len; i++) {
          result += chars.charAt(Math.floor(Math.random() * chars.length))
        }
        return result
      }

      const min = 100000
      const max = 999999
      return Math.floor(Math.random() * (max - min + 1)) + min
    },
  }
}
