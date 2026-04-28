import { createHmac } from 'node:crypto'

const PEPPER = process.env.TX_CODE_PEPPER
if (!PEPPER) {
  throw new Error('TX_CODE_PEPPER environment variable is required')
}

export const hashTxCode = (txCode: string | number): string => {
  const input = typeof txCode === 'number' ? txCode.toString() : txCode
  return createHmac('sha256', PEPPER).update(input).digest('hex')
}
