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
    assert.strictEqual(result.length, 8)
    assert.match(
      result,
      /^[A-Za-z0-9]{8}$/,
      'Text transaction code should contain only alphanumeric characters'
    )
  })

  it('should generate a text transaction code with custom length', () => {
    const result = provider.generate('text', 12, 'example')

    assert.strictEqual(typeof result, 'string')
    assert.strictEqual(result.length, 12)
    assert.match(
      result,
      /^[A-Za-z0-9]{12}$/,
      'Text transaction code should contain only alphanumeric characters'
    )
  })
})
