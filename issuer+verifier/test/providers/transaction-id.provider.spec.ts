import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { TransactionIdProvider } from '../../src/providers/provider.types'
import { transactionId } from '../../src/providers/transaction-id.provider'

describe('TransactionIdProvider', () => {
  const provider: TransactionIdProvider = transactionId()

  it('should be a TransactionIdProvider', () => {
    assert.ok(provider, 'Provider instance should be created')
    assert.equal(typeof provider.generate, 'function', 'Provider should have a generate function')
  })

  it('should have correct kind, name, and single properties', () => {
    assert.equal(provider.kind, 'transaction-id-provider')
    assert.equal(provider.name, 'default-transaction-id-provider')
    assert.strictEqual(provider.single, true)
  })

  describe('generate()', () => {
    it('should generate a TransactionId string', async () => {
      const id = await provider.generate()
      assert.equal(typeof id, 'string')
      assert.equal(id.length, 32, 'Generated id should have 32 characters (UUID without hyphens)')
    })

    it('should generate different ids on subsequent calls', async () => {
      const [id1, id2] = await Promise.all([provider.generate(), provider.generate()])
      assert.notEqual(id1, id2, 'Generated ids should be different to ensure randomness')
    })

    it('should contain only hexadecimal characters', async () => {
      const id = await provider.generate()
      const hex32 = /^[0-9a-fA-F]{32}$/
      assert.ok(hex32.test(id), 'Generated id should consist of 32 hexadecimal characters')
    })

    it('should not include hyphens', async () => {
      const id = await provider.generate()
      assert.ok(!id.includes('-'), 'Generated id should not contain hyphens')
    })
  })
})
