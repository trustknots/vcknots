import assert from 'node:assert'
import { describe, it } from 'node:test'
import { transactionCode } from '../../src/providers/transaction-code.provider'
import { TransactionCodeProvider } from '../../src/providers/provider.types'

describe('transactionCode', () => {
  const provider: TransactionCodeProvider = transactionCode()

  it('should have correct properties', () => {
    assert.strictEqual(provider.kind, 'transaction-code-provider')
    assert.strictEqual(provider.name, 'default-transaction-code-provider')
    assert.strictEqual(provider.single, true)
  })

  it('should generate a default numeric transaction code', () => {
    const result = provider.generate()

    assert.strictEqual(typeof result, 'number')
    assert.ok(Number.isInteger(result), 'Result should be an integer')
    assert.ok(
      result >= 100000 && result <= 999999,
      'Default transaction code should be a 6-digit number'
    )
  })

  it('should generate a numeric transaction code with custom length and description', () => {
    const result = provider.generate('numeric', 4, 'example')

    assert.strictEqual(typeof result, 'number')
    assert.ok(Number.isInteger(result), 'Result should be an integer')
    assert.ok(result >= 1000 && result <= 9999, 'Transaction code should be a 4-digit number')
  })

  it('should generate a text transaction code with the default length', () => {
    const result = provider.generate('text')

    assert.strictEqual(typeof result, 'string')
    assert.strictEqual(result.length, 6)
    assert.match(
      result,
      /^[A-HJ-NP-Za-km-z2-9]{6}$/,
      'Text transaction code should exclude ambiguous characters'
    )
  })

  it('should generate a text transaction code with custom length', () => {
    const result = provider.generate('text', 8, 'example')

    assert.strictEqual(typeof result, 'string')
    assert.strictEqual(result.length, 8)
    assert.match(
      result,
      /^[A-HJ-NP-Za-km-z2-9]{8}$/,
      'Text transaction code should exclude ambiguous characters'
    )
  })

  it('should throw when length is less than 4', () => {
    assert.throws(
      () => provider.generate('numeric', 3),
      (e: unknown) => {
        assert.strictEqual((e as { name?: string }).name, 'invalid_tx_code_options')
        return true
      }
    )
    assert.throws(
      () => provider.generate('text', 1),
      (e: unknown) => {
        assert.strictEqual((e as { name?: string }).name, 'invalid_tx_code_options')
        return true
      }
    )
  })

  it('should throw when length is 10 or more', () => {
    assert.throws(
      () => provider.generate('numeric', 10),
      (e: unknown) => {
        assert.strictEqual((e as { name?: string }).name, 'invalid_tx_code_options')
        return true
      }
    )
    assert.throws(
      () => provider.generate('text', 15),
      (e: unknown) => {
        assert.strictEqual((e as { name?: string }).name, 'invalid_tx_code_options')
        return true
      }
    )
  })

  it('should throw when description exceeds 300 characters', () => {
    const longDescription = 'a'.repeat(301)
    assert.throws(
      () => provider.generate('numeric', 4, longDescription),
      (e: unknown) => {
        assert.strictEqual((e as { name?: string }).name, 'invalid_tx_code_options')
        return true
      }
    )
  })
})
