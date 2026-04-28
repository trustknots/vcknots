import { createHash } from 'node:crypto'

export const hashTxCode = (txCode: string | number): string => {
  const input = typeof txCode === 'number' ? txCode.toString() : txCode
  return createHash('sha256').update(input).digest('hex')
}
