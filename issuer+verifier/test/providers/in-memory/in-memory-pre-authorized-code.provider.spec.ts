import assert from 'node:assert/strict'
import { afterEach, beforeEach, describe, it, mock } from 'node:test'
import { PreAuthorizedCode } from '../../../src/pre-authorized-code.types'
import { inMemoryPreAuthorizedCodeStore } from '../../../src/providers/in-memory/in-memory-pre-authorized-code-store.provider'
import { CredentialConfigurationId } from '../../../src/credential-issuer.types'

describe('inMemoryPreAuthorizedCode', () => {
  let provider: ReturnType<typeof inMemoryPreAuthorizedCodeStore>
  const sampleCode: PreAuthorizedCode = PreAuthorizedCode('test_code_123_abc')
  const anotherSampleCode: PreAuthorizedCode = PreAuthorizedCode('another_code_456_def')
  const configurations: CredentialConfigurationId[] = [
    CredentialConfigurationId('University_Degree'),
  ]

  beforeEach(() => {
    provider = inMemoryPreAuthorizedCodeStore()
  })

  afterEach(() => {
    mock.timers.reset()
  })

  it('should have kind, name, and single properties correctly set', () => {
    assert.strictEqual(provider.kind, 'pre-authorized-code-store-provider')
    assert.strictEqual(provider.name, 'in-memory-pre-authorized-code-provider')
    assert.strictEqual(provider.single, true)
  })

  describe('save and consume', () => {
    it('should save a pre-authorized code and validate it successfully', async () => {
      await provider.save(sampleCode, configurations)
      const isValid = await provider.consume(sampleCode)
      assert.strictEqual(isValid, configurations)
    })

    it('should save a pre-authorized code with tx_code (numeric) and validate it', async () => {
      await provider.save(sampleCode, configurations, 123, { tx_code_input_mode: 'numeric' })
      const isValid = await provider.consume(sampleCode, 123)
      assert.strictEqual(isValid, configurations)
    })

    it('should save a pre-authorized code with tx_code (text) and validate it', async () => {
      await provider.save(sampleCode, configurations, 'abc123', { tx_code_input_mode: 'text' })
      const isValid = await provider.consume(sampleCode, 'abc123')
      assert.strictEqual(isValid, configurations)
    })

    it('should throw invalid_grant when validating with incorrect tx_code', async () => {
      await provider.save(sampleCode, configurations, 123, { tx_code_input_mode: 'numeric' })
      await assert.rejects(provider.consume(sampleCode, 456), { name: 'invalid_grant' })
    })

    it('should allow string numeric tx_code in numeric mode', async () => {
      await provider.save(sampleCode, configurations, 123, { tx_code_input_mode: 'numeric' })
      const isValid = await provider.consume(sampleCode, '123')
      assert.strictEqual(isValid, configurations)
    })

    it('should throw invalid_grant when tx_code is not numeric in numeric mode', async () => {
      await provider.save(sampleCode, configurations, 123, { tx_code_input_mode: 'numeric' })
      await assert.rejects(provider.consume(sampleCode, '12a3'), { name: 'invalid_grant' })
    })

    it('should preserve leading zeros in numeric mode', async () => {
      await provider.save(sampleCode, configurations, '0123', { tx_code_input_mode: 'numeric' })
      const isValid = await provider.consume(sampleCode, '0123')
      assert.strictEqual(isValid, configurations)
    })

    it('should throw invalid_grant when leading-zero digit-string is validated as number', async () => {
      await provider.save(sampleCode, configurations, '0123', { tx_code_input_mode: 'numeric' })
      await assert.rejects(provider.consume(sampleCode, 123), { name: 'invalid_grant' })
    })

    it('should throw invalid_grant when validating a non-existent code', async () => {
      await assert.rejects(provider.consume(sampleCode), { name: 'invalid_grant' }) // sampleCode is not saved yet
    })

    it('should handle multiple codes correctly', async () => {
      await provider.save(sampleCode, configurations)
      await provider.save(anotherSampleCode, configurations)

      assert.strictEqual(await provider.consume(sampleCode), configurations)
      assert.strictEqual(await provider.consume(anotherSampleCode), configurations)
    })
  })

  describe('edge cases', () => {
    it('validate should throw invalid_grant when the store is empty', async () => {
      await assert.rejects(provider.consume(sampleCode), { name: 'invalid_grant' })
    })

    it('save should not return a value (void promise)', async () => {
      const result = await provider.save(sampleCode, configurations)
      assert.strictEqual(result, undefined)
    })

    it('should use default ttlSec when not specified', async () => {
      await provider.save(sampleCode, configurations)
      // This test just ensures no error is thrown with default values
      const isValid = await provider.consume(sampleCode)
      assert.strictEqual(isValid, configurations)
    })

    it('should fall back to default ttlSec when saveOptions.ttlSec is invalid', async () => {
      mock.timers.enable({ apis: ['Date'] })
      await provider.save(sampleCode, configurations, undefined, { ttlSec: NaN })
      mock.timers.tick(299_000)
      assert.strictEqual(await provider.consume(sampleCode), configurations)
      mock.timers.tick(2_000)
      await assert.rejects(provider.consume(sampleCode), { name: 'invalid_grant' })
    })

    it('should floor fractional ttlSec values', async () => {
      mock.timers.enable({ apis: ['Date'] })
      await provider.save(sampleCode, configurations, undefined, { ttlSec: 1.9 })
      mock.timers.tick(500)
      assert.strictEqual(await provider.consume(sampleCode), configurations)
      mock.timers.tick(600)
      await assert.rejects(provider.consume(sampleCode), { name: 'invalid_grant' })
    })

    it('should fall back to default ttlSec when fractional ttlSec floors to zero', async () => {
      mock.timers.enable({ apis: ['Date'] })
      await provider.save(sampleCode, configurations, undefined, { ttlSec: 0.1 })
      mock.timers.tick(299_000)
      assert.strictEqual(await provider.consume(sampleCode), configurations)
      mock.timers.tick(2_000)
      await assert.rejects(provider.consume(sampleCode), { name: 'invalid_grant' })
    })

    it('should throw invalid_tx_code when saving a non-numeric tx_code in numeric mode', async () => {
      await assert.rejects(
        provider.save(sampleCode, configurations, 'abc', { tx_code_input_mode: 'numeric' }),
        { name: 'invalid_tx_code' }
      )
    })

    it('should throw invalid_request when tx_code is required but missing', async () => {
      await provider.save(sampleCode, configurations, 1234, { tx_code_input_mode: 'numeric' })
      await assert.rejects(provider.consume(sampleCode), {
        name: 'invalid_request',
        message: 'tx_code is required for this pre-authorized code',
      })
    })

    it('should throw invalid_request when tx_code is provided for a code without tx_code', async () => {
      await provider.save(sampleCode, configurations)
      await assert.rejects(provider.consume(sampleCode, 1234), {
        name: 'invalid_request',
        message: 'tx_code should not be provided for this pre-authorized code',
      })
    })

    it('should throw invalid_grant for incorrect tx_code in text mode', async () => {
      await provider.save(sampleCode, configurations, 'secret', { tx_code_input_mode: 'text' })
      await assert.rejects(provider.consume(sampleCode, 'wrong'), {
        name: 'invalid_grant',
        message: 'Invalid tx_code provided',
      })
    })

    it('should throw invalid_grant with expired message for an expired code', async () => {
      mock.timers.enable({ apis: ['Date'] })
      await provider.save(sampleCode, configurations, undefined, { ttlSec: 1 })
      mock.timers.tick(1001)
      await assert.rejects(provider.consume(sampleCode), {
        name: 'invalid_grant',
        message: 'Pre-authorized code has expired',
      })
    })
  })

  describe('tx_code brute-force lockout (count-first gate)', () => {
    const LOCKED_MESSAGE = 'Pre-authorized code is invalid, consumed, or locked'
    const INVALID_TX_CODE_MESSAGE = 'Invalid tx_code provided'

    const saveWithTxCode = async (
      store: ReturnType<typeof inMemoryPreAuthorizedCodeStore>,
      code: PreAuthorizedCode
    ) => {
      await store.save(code, configurations, 1234, { tx_code_input_mode: 'numeric' })
    }

    it('increments attempts before comparing tx_code and keeps the code under the limit', async () => {
      const store = inMemoryPreAuthorizedCodeStore()
      await saveWithTxCode(store, sampleCode)

      await assert.rejects(store.consume(sampleCode, 9999), {
        name: 'invalid_grant',
        message: INVALID_TX_CODE_MESSAGE,
      })

      // Still admit another attempt under the default limit.
      await assert.rejects(store.consume(sampleCode, 9999), {
        name: 'invalid_grant',
        message: INVALID_TX_CODE_MESSAGE,
      })
    })

    it('rejects a locked/exhausted code before comparing the tx_code', async () => {
      const store = inMemoryPreAuthorizedCodeStore({ maxTxCodeAttempts: 2 })
      await saveWithTxCode(store, sampleCode)

      await assert.rejects(store.consume(sampleCode, 9999), {
        name: 'invalid_grant',
        message: INVALID_TX_CODE_MESSAGE,
      })
      await assert.rejects(store.consume(sampleCode, 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })

      // Even the correct PIN is rejected once the code is locked/gone.
      await assert.rejects(store.consume(sampleCode, 1234), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })

    it('falls back to the default limit when maxTxCodeAttempts is NaN', async () => {
      const store = inMemoryPreAuthorizedCodeStore({ maxTxCodeAttempts: Number.NaN })
      await saveWithTxCode(store, sampleCode)

      for (let i = 0; i < 4; i++) {
        await assert.rejects(store.consume(sampleCode, 9999), {
          name: 'invalid_grant',
          message: INVALID_TX_CODE_MESSAGE,
        })
      }

      await assert.rejects(store.consume(sampleCode, 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      await assert.rejects(store.consume(sampleCode, 1234), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })

    it('falls back to the default limit when maxTxCodeAttempts is Infinity', async () => {
      const store = inMemoryPreAuthorizedCodeStore({
        maxTxCodeAttempts: Number.POSITIVE_INFINITY,
      })
      await saveWithTxCode(store, sampleCode)

      for (let i = 0; i < 4; i++) {
        await assert.rejects(store.consume(sampleCode, 9999), {
          name: 'invalid_grant',
          message: INVALID_TX_CODE_MESSAGE,
        })
      }

      await assert.rejects(store.consume(sampleCode, 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })

    it('clamps a maxTxCodeAttempts below 1 up to a single attempt', async () => {
      const store = inMemoryPreAuthorizedCodeStore({ maxTxCodeAttempts: 0 })
      await saveWithTxCode(store, sampleCode)

      await assert.rejects(store.consume(sampleCode, 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      await assert.rejects(store.consume(sampleCode, 1234), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })

    it('enforces a custom maxTxCodeAttempts and deletes when exhausted', async () => {
      const store = inMemoryPreAuthorizedCodeStore({ maxTxCodeAttempts: 2 })
      await saveWithTxCode(store, sampleCode)

      await assert.rejects(store.consume(sampleCode, 9999), {
        name: 'invalid_grant',
        message: INVALID_TX_CODE_MESSAGE,
      })
      await assert.rejects(store.consume(sampleCode, 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })

    it('deletes the code once a failed attempt exhausts the default limit', async () => {
      const store = inMemoryPreAuthorizedCodeStore()
      await saveWithTxCode(store, sampleCode)

      for (let i = 0; i < 4; i++) {
        await assert.rejects(store.consume(sampleCode, 9999), {
          name: 'invalid_grant',
          message: INVALID_TX_CODE_MESSAGE,
        })
      }

      await assert.rejects(store.consume(sampleCode, 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })

    it('admits and consumes the correct tx_code through the same gate', async () => {
      const store = inMemoryPreAuthorizedCodeStore()
      await saveWithTxCode(store, sampleCode)

      const result = await store.consume(sampleCode, 1234)
      assert.deepStrictEqual(result, configurations)
      await assert.rejects(store.consume(sampleCode, 1234), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })

    it('uses LOCKED_MESSAGE for unknown codes (parity with DynamoDB/Firestore)', async () => {
      const store = inMemoryPreAuthorizedCodeStore()
      await assert.rejects(store.consume(sampleCode, 1234), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })

    it('locks out when tx_code is required but missing on the final attempt', async () => {
      const store = inMemoryPreAuthorizedCodeStore({ maxTxCodeAttempts: 1 })
      await saveWithTxCode(store, sampleCode)
      await assert.rejects(store.consume(sampleCode), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })
  })
})
