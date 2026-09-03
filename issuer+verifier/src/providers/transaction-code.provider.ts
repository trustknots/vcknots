import { randomInt } from 'node:crypto'
import { err } from '../errors'
import { TransactionCodeProvider } from './provider.types'

const MIN_TX_CODE_LENGTH = 4
const MAX_TX_CODE_LENGTH = 9
// Exclude easily confusable characters: 0, O, I, l, etc.
const TEXT_TX_CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'

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
      if (len < MIN_TX_CODE_LENGTH || len > MAX_TX_CODE_LENGTH) {
        throw err('invalid_tx_code_options', {
          message: `Length must be between ${MIN_TX_CODE_LENGTH} and ${MAX_TX_CODE_LENGTH}`,
        })
      }
      if (description?.length && description.length > 300) {
        throw err('invalid_tx_code_options', {
          message: 'Description must be less than 300 characters',
        })
      }

      if (input_mode === 'numeric') {
        const min = 10 ** (len - 1)
        const maxExclusive = 10 ** len
        return randomInt(min, maxExclusive)
      }

      if (input_mode === 'text') {
        let result = ''
        for (let i = 0; i < len; i++) {
          result += TEXT_TX_CODE_CHARS.charAt(randomInt(0, TEXT_TX_CODE_CHARS.length))
        }
        return result
      }

      const min = 10 ** (len - 1)
      const maxExclusive = 10 ** len
      return randomInt(min, maxExclusive)
    },
  }
}
