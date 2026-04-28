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
      if (input_mode === 'numeric') {
        const len = length ?? 6
        const min = 10 ** (len - 1)
        const max = 10 ** len - 1
        return Math.floor(Math.random() * (max - min + 1)) + min
      }

      if (input_mode === 'text') {
        const len = length ?? 8
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
