import assert from 'node:assert/strict'
import { afterEach, describe, it, mock } from 'node:test'
import { CredentialConfigurationId, PreAuthorizedCode } from '@trustknots/vcknots'
import { firestorePreAuthorizedCodeStore } from '../../src/providers/firestore-pre-authorized-code-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestorePreAuthorizedCodeStore', () => {
  afterEach(() => {
    store.clear()
    mock.timers.reset()
  })
  const configurations: CredentialConfigurationId[] = [
    CredentialConfigurationId('University_Degree'),
  ]

  it('should have correct provider metadata', () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    assert.equal(provider.kind, 'pre-authorized-code-store-provider')
    assert.equal(provider.name, 'firestore-pre-authorized-code-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and consume a code', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-123'), configurations)
    const valid = await provider.consume(PreAuthorizedCode('test-code-123'))
    assert.deepStrictEqual(valid, configurations)
  })

  it('should save and validate a code with tx_code (numeric)', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-numeric'), configurations, 123, {
      tx_code_input_mode: 'numeric',
    })
    const valid = await provider.consume(PreAuthorizedCode('test-code-numeric'), 123)
    assert.deepStrictEqual(valid, configurations)
  })

  it('should save and validate a code with tx_code (text)', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-text'), configurations, 'abc123', {
      tx_code_input_mode: 'text',
    })
    const valid = await provider.consume(PreAuthorizedCode('test-code-text'), 'abc123')
    assert.deepStrictEqual(valid, configurations)
  })

  it('should throw invalid_tx_code when saving a non-numeric tx_code in numeric mode', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await assert.rejects(
      provider.save(PreAuthorizedCode('save-invalid-numeric'), configurations, 'abc', {
        tx_code_input_mode: 'numeric',
      }),
      { name: 'invalid_tx_code' }
    )
    assert.ok(!store.has('vcknots/v1/preCodes/save-invalid-numeric'))
  })

  it('should throw invalid_tx_code when saving a negative number in numeric mode', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await assert.rejects(
      provider.save(PreAuthorizedCode('save-negative-numeric'), configurations, -1, {
        tx_code_input_mode: 'numeric',
      }),
      { name: 'invalid_tx_code' }
    )
  })

  it('should throw invalid_grant for incorrect tx_code', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-wrong'), configurations, 123, {
      tx_code_input_mode: 'numeric',
    })
    await assert.rejects(provider.consume(PreAuthorizedCode('test-code-wrong'), 456), {
      name: 'invalid_grant',
      message: 'Invalid tx_code provided',
    })
    const doc = store.get('vcknots/v1/preCodes/test-code-wrong')
    assert.ok(doc)
    assert.equal(doc.attempts, 1)
  })

  it('should allow string numeric tx_code in numeric mode', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-type'), configurations, 123, {
      tx_code_input_mode: 'numeric',
    })
    const valid = await provider.consume(PreAuthorizedCode('test-code-type'), '123')
    assert.deepStrictEqual(valid, configurations)
  })

  it('should throw invalid_grant for non-numeric string tx_code in numeric mode', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(
      PreAuthorizedCode('test-code-invalid-numeric-string'),
      configurations,
      123,
      {
        tx_code_input_mode: 'numeric',
      }
    )
    await assert.rejects(
      provider.consume(PreAuthorizedCode('test-code-invalid-numeric-string'), '12a3'),
      { name: 'invalid_grant' }
    )
  })

  it('should preserve leading zeros in numeric mode', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-leading-zero'), configurations, '0123', {
      tx_code_input_mode: 'numeric',
    })
    const valid = await provider.consume(PreAuthorizedCode('test-code-leading-zero'), '0123')
    assert.deepStrictEqual(valid, configurations)
  })

  it('should throw invalid_grant when leading-zero digit-string is validated as number', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(
      PreAuthorizedCode('test-code-leading-zero-mismatch'),
      configurations,
      '0123',
      {
        tx_code_input_mode: 'numeric',
      }
    )
    await assert.rejects(
      provider.consume(PreAuthorizedCode('test-code-leading-zero-mismatch'), 123),
      { name: 'invalid_grant' }
    )
  })

  it('should store hashed tx_code in Firestore', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('hashed-code'), configurations, 123, {
      tx_code_input_mode: 'numeric',
    })

    const doc = store.get('vcknots/v1/preCodes/hashed-code')
    assert.ok(doc)
    assert.ok(doc.tx_code_hash)
    assert.equal(doc.tx_code_input_mode, 'numeric')
    assert.equal(typeof doc.tx_code_hash, 'string')
    assert.equal(doc.tx_code_hash.length, 64) // SHA-256 hex length
  })

  it('should use default numeric mode when not specified', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('default-mode'), configurations, 456)

    const doc = store.get('vcknots/v1/preCodes/default-mode')
    assert.ok(doc)
    assert.equal(doc.tx_code_input_mode, 'numeric')
  })

  it('should store expires_at as Firestore Timestamp', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('timestamp-check'), configurations, undefined, {
      ttlSec: 1,
    })

    const doc = store.get('vcknots/v1/preCodes/timestamp-check') as {
      expires_at?: { toMillis: () => number }
    }
    assert.ok(doc)
    assert.ok(doc.expires_at)
    assert.equal(typeof doc.expires_at?.toMillis, 'function')
    assert.equal(doc.expires_at?.toMillis(), 1000)
  })

  it('should fall back to default ttlSec when saveOptions.ttlSec is invalid', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('invalid-ttl-fallback'), configurations, undefined, {
      ttlSec: NaN,
    })

    const doc = store.get('vcknots/v1/preCodes/invalid-ttl-fallback') as {
      expires_at?: { toMillis: () => number }
    }
    assert.ok(doc?.expires_at)
    assert.equal(doc.expires_at?.toMillis(), 300 * 1000)
  })

  it('should floor fractional ttlSec values', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('fractional-ttl'), configurations, undefined, {
      ttlSec: 1.9,
    })

    const doc = store.get('vcknots/v1/preCodes/fractional-ttl') as {
      expires_at?: { toMillis: () => number }
    }
    assert.ok(doc?.expires_at)
    assert.equal(doc.expires_at?.toMillis(), 1000)
  })

  it('should fall back to default ttlSec when fractional ttlSec floors to zero', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('fractional-ttl-zero'), configurations, undefined, {
      ttlSec: 0.1,
    })

    const doc = store.get('vcknots/v1/preCodes/fractional-ttl-zero') as {
      expires_at?: { toMillis: () => number }
    }
    assert.ok(doc?.expires_at)
    assert.equal(doc.expires_at?.toMillis(), 300 * 1000)
  })

  it('should throw invalid_grant for an unknown code', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await assert.rejects(provider.consume(PreAuthorizedCode('unknown-code'), undefined), {
      name: 'invalid_grant',
    })
  })

  it('should throw invalid_grant and delete an expired code', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('expiring-code'), configurations, undefined, {
      ttlSec: 1,
    })

    mock.timers.tick(1001)

    await assert.rejects(provider.consume(PreAuthorizedCode('expiring-code'), undefined), {
      name: 'invalid_grant',
      message: 'Pre-authorized code has expired',
    })
    assert.ok(!store.has('vcknots/v1/preCodes/expiring-code'))
  })

  it('should throw invalid_request when tx_code is required but missing', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('tx-required'), configurations, 1234, {
      tx_code_input_mode: 'numeric',
    })
    await assert.rejects(provider.consume(PreAuthorizedCode('tx-required')), {
      name: 'invalid_request',
      message: 'tx_code is required for this pre-authorized code',
    })
    assert.equal(store.get('vcknots/v1/preCodes/tx-required')?.attempts, 1)
  })

  it('should lock out when tx_code is required but missing on the final attempt', async () => {
    const LOCKED_MESSAGE = 'Pre-authorized code is invalid, consumed, or locked'
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp, maxTxCodeAttempts: 1 })
    await provider.save(PreAuthorizedCode('tx-required-lock'), configurations, 1234, {
      tx_code_input_mode: 'numeric',
    })
    await assert.rejects(provider.consume(PreAuthorizedCode('tx-required-lock')), {
      name: 'invalid_grant',
      message: LOCKED_MESSAGE,
    })
    assert.ok(!store.has('vcknots/v1/preCodes/tx-required-lock'))
  })

  it('should throw invalid_request when tx_code is provided for a code without tx_code', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('tx-unexpected'), configurations)
    await assert.rejects(provider.consume(PreAuthorizedCode('tx-unexpected'), 1234), {
      name: 'invalid_request',
      message: 'tx_code should not be provided for this pre-authorized code',
    })
    assert.equal(store.get('vcknots/v1/preCodes/tx-unexpected')?.attempts, 1)
  })

  it('should throw invalid_grant for incorrect tx_code in text mode', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('text-wrong'), configurations, 'secret', {
      tx_code_input_mode: 'text',
    })
    await assert.rejects(provider.consume(PreAuthorizedCode('text-wrong'), 'wrong'), {
      name: 'invalid_grant',
      message: 'Invalid tx_code provided',
    })
    assert.equal(store.get('vcknots/v1/preCodes/text-wrong')?.attempts, 1)
  })

  it('should use default expiration of 5 minutes', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('default-expiry'), configurations)

    // Still valid before 5 minutes
    mock.timers.tick(4 * 60 * 1000)
    const validBefore = await provider.consume(PreAuthorizedCode('default-expiry'), undefined)
    assert.equal(validBefore, configurations)

    // Expired after 5 minutes
    mock.timers.tick(2 * 60 * 1000)
    await assert.rejects(provider.consume(PreAuthorizedCode('default-expiry'), undefined), {
      name: 'invalid_grant',
    })
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('my-code'), configurations)
    assert.ok(store.has('vcknots/v1/preCodes/my-code'))
  })

  it('should use a custom namespace', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp, namespace: 'custom' })
    await provider.save(PreAuthorizedCode('my-code'), configurations)
    assert.ok(store.has('custom/v1/preCodes/my-code'))
    assert.ok(!store.has('vcknots/v1/preCodes/my-code'))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp, namespace: 'foo/bar/baz' })
    await provider.save(PreAuthorizedCode('my-code'), configurations)
    assert.ok(store.has('foobarbaz/v1/preCodes/my-code'))
    assert.ok(!store.has('foo/bar/baz/v1/preCodes/my-code'))
  })

  it('should strip leading and trailing slashes from namespace', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp, namespace: '/my/ns/' })
    await provider.save(PreAuthorizedCode('my-code'), configurations)
    assert.ok(store.has('myns/v1/preCodes/my-code'))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp, namespace: '///' })
    await provider.save(PreAuthorizedCode('my-code'), configurations)
    assert.ok(store.has('vcknots/v1/preCodes/my-code'))
  })

  it('should persist credential_configuration_ids in Firestore document', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    const code = PreAuthorizedCode('stored-config-code')

    await provider.save(code, configurations)

    const doc = store.get('vcknots/v1/preCodes/stored-config-code')
    assert.ok(doc)
    assert.deepStrictEqual(doc.credential_configuration_ids, configurations)
  })

  describe('tx_code brute-force lockout (count-first gate)', () => {
    const LOCKED_MESSAGE = 'Pre-authorized code is invalid, consumed, or locked'
    const INVALID_TX_CODE_MESSAGE = 'Invalid tx_code provided'

    const saveWithTxCode = async (
      provider: ReturnType<typeof firestorePreAuthorizedCodeStore>,
      code: string
    ) => {
      await provider.save(PreAuthorizedCode(code), configurations, 1234, {
        tx_code_input_mode: 'numeric',
      })
    }

    it('increments attempts before comparing tx_code and keeps the code under the limit', async () => {
      const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
      await saveWithTxCode(provider, 'bf-under')

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-under'), 9999), {
        name: 'invalid_grant',
        message: INVALID_TX_CODE_MESSAGE,
      })

      const doc = store.get('vcknots/v1/preCodes/bf-under')
      assert.ok(doc)
      assert.equal(doc.attempts, 1)
    })

    it('rejects a locked/exhausted code before comparing the tx_code', async () => {
      const provider = firestorePreAuthorizedCodeStore({ app: mockApp, maxTxCodeAttempts: 2 })
      await saveWithTxCode(provider, 'bf-locked')

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-locked'), 9999), {
        name: 'invalid_grant',
        message: INVALID_TX_CODE_MESSAGE,
      })
      await assert.rejects(provider.consume(PreAuthorizedCode('bf-locked'), 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      assert.ok(!store.has('vcknots/v1/preCodes/bf-locked'))

      // Even the correct PIN is rejected once the code is locked/gone.
      await assert.rejects(provider.consume(PreAuthorizedCode('bf-locked'), 1234), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })

    it('falls back to the default limit when maxTxCodeAttempts is NaN', async () => {
      const provider = firestorePreAuthorizedCodeStore({
        app: mockApp,
        maxTxCodeAttempts: Number.NaN,
      })
      await saveWithTxCode(provider, 'bf-nan')

      for (let i = 0; i < 4; i++) {
        await assert.rejects(provider.consume(PreAuthorizedCode('bf-nan'), 9999), {
          name: 'invalid_grant',
          message: INVALID_TX_CODE_MESSAGE,
        })
      }
      assert.equal(store.get('vcknots/v1/preCodes/bf-nan')?.attempts, 4)

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-nan'), 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      assert.ok(!store.has('vcknots/v1/preCodes/bf-nan'))
    })

    it('falls back to the default limit when maxTxCodeAttempts is Infinity', async () => {
      const provider = firestorePreAuthorizedCodeStore({
        app: mockApp,
        maxTxCodeAttempts: Number.POSITIVE_INFINITY,
      })
      await saveWithTxCode(provider, 'bf-inf')

      for (let i = 0; i < 4; i++) {
        await assert.rejects(provider.consume(PreAuthorizedCode('bf-inf'), 9999), {
          name: 'invalid_grant',
          message: INVALID_TX_CODE_MESSAGE,
        })
      }

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-inf'), 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      assert.ok(!store.has('vcknots/v1/preCodes/bf-inf'))
    })

    it('clamps a maxTxCodeAttempts below 1 up to a single attempt', async () => {
      const provider = firestorePreAuthorizedCodeStore({ app: mockApp, maxTxCodeAttempts: 0 })
      await saveWithTxCode(provider, 'bf-zero')

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-zero'), 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      assert.ok(!store.has('vcknots/v1/preCodes/bf-zero'))
    })

    it('enforces a custom maxTxCodeAttempts and deletes when exhausted', async () => {
      const provider = firestorePreAuthorizedCodeStore({ app: mockApp, maxTxCodeAttempts: 2 })
      await saveWithTxCode(provider, 'bf-custom')

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-custom'), 9999), {
        name: 'invalid_grant',
        message: INVALID_TX_CODE_MESSAGE,
      })
      assert.equal(store.get('vcknots/v1/preCodes/bf-custom')?.attempts, 1)

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-custom'), 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      assert.ok(!store.has('vcknots/v1/preCodes/bf-custom'))
    })

    it('deletes the code once a failed attempt exhausts the default limit', async () => {
      const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
      await saveWithTxCode(provider, 'bf-exhaust')

      for (let i = 0; i < 4; i++) {
        await assert.rejects(provider.consume(PreAuthorizedCode('bf-exhaust'), 9999), {
          name: 'invalid_grant',
          message: INVALID_TX_CODE_MESSAGE,
        })
      }

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-exhaust'), 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      assert.ok(!store.has('vcknots/v1/preCodes/bf-exhaust'))
    })

    it('admits and consumes the correct tx_code through the same gate', async () => {
      const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
      await saveWithTxCode(provider, 'bf-ok')

      const result = await provider.consume(PreAuthorizedCode('bf-ok'), 1234)
      assert.deepStrictEqual(result, configurations)
      assert.ok(!store.has('vcknots/v1/preCodes/bf-ok'))
    })

    it('allows only one concurrent successful consume of the same code', async () => {
      const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
      await saveWithTxCode(provider, 'bf-race')

      const outcomes = await Promise.allSettled([
        provider.consume(PreAuthorizedCode('bf-race'), 1234),
        provider.consume(PreAuthorizedCode('bf-race'), 1234),
      ])

      const fulfilled = outcomes.filter((o) => o.status === 'fulfilled')
      const rejected = outcomes.filter((o) => o.status === 'rejected')
      assert.equal(fulfilled.length, 1)
      assert.equal(rejected.length, 1)
      assert.deepStrictEqual(
        (fulfilled[0] as PromiseFulfilledResult<typeof configurations>).value,
        configurations
      )
      assert.equal((rejected[0] as PromiseRejectedResult).reason?.name, 'invalid_grant')
      assert.equal(
        (rejected[0] as PromiseRejectedResult).reason?.message,
        'Pre-authorized code has already been consumed'
      )
      assert.ok(!store.has('vcknots/v1/preCodes/bf-race'))
    })

    it('uses LOCKED_MESSAGE for unknown codes (parity with DynamoDB gate)', async () => {
      const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
      await assert.rejects(provider.consume(PreAuthorizedCode('bf-missing'), 1234), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
    })

    it('rejects before comparing tx_code when a remaining doc already has attempts >= max', async () => {
      const provider = firestorePreAuthorizedCodeStore({ app: mockApp, maxTxCodeAttempts: 2 })
      await saveWithTxCode(provider, 'bf-seeded-max')

      const path = 'vcknots/v1/preCodes/bf-seeded-max'
      const existing = store.get(path)
      assert.ok(existing)
      store.set(path, { ...existing, attempts: 2 })

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-seeded-max'), 1234), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      // Gate rejects without deleting; attempts stay at the seeded max.
      assert.ok(store.has(path))
      assert.equal(store.get(path)?.attempts, 2)
    })
  })
})
