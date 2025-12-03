import { describe, it } from 'node:test'
import assert from 'node:assert'
import base64url from 'base64url'
import { transactionData } from '../../src/providers/transaction-data.provider'

describe('transactionData', () => {
  const provider = transactionData()

  it('should have correct properties', () => {
    assert.strictEqual(provider.kind, 'transaction-data-provider')
    assert.strictEqual(provider.name, 'default-transaction-data-provider')
    assert.strictEqual(provider.single, true)
  })

  it('should generate a base64url encoded string with default hash algorithm', () => {
    const type = 'test_type'
    const credential_ids = ['cred1', 'cred2']
    const result = provider.generate(type, credential_ids)

    const decoded = JSON.parse(base64url.decode(result))

    assert.deepStrictEqual(decoded, {
      type,
      credential_ids,
      transaction_data_hashes_alg: ['sha256'],
    })
  })
})
