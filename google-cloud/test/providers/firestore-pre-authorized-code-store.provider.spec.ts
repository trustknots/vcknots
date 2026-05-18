import assert from 'node:assert/strict'
import { afterEach, describe, it, mock } from 'node:test'
import { PreAuthorizedCode } from '@trustknots/vcknots'
import { firestorePreAuthorizedCodeStore } from '../../src/providers/firestore-pre-authorized-code-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestorePreAuthorizedCodeStore', () => {
  afterEach(() => {
    store.clear()
    mock.timers.reset()
  })

  it('should have correct provider metadata', () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    assert.equal(provider.kind, 'pre-authorized-code-store-provider')
    assert.equal(provider.name, 'firestore-pre-authorized-code-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and validate a code', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-123'))
    const valid = await provider.validate(PreAuthorizedCode('test-code-123'))
    assert.equal(valid, true)
  })

  it('should save and validate a code with tx_code (numeric)', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-numeric'), 123, {
      tx_code_input_mode: 'numeric',
    })
    const valid = await provider.validate(PreAuthorizedCode('test-code-numeric'), 123)
    assert.equal(valid, true)
  })

  it('should save and validate a code with tx_code (text)', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-text'), 'abc123', {
      tx_code_input_mode: 'text',
    })
    const valid = await provider.validate(PreAuthorizedCode('test-code-text'), 'abc123')
    assert.equal(valid, true)
  })

  it('should throw invalid_grant for incorrect tx_code', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-wrong'), 123, {
      tx_code_input_mode: 'numeric',
    })
    await assert.rejects(provider.validate(PreAuthorizedCode('test-code-wrong'), 456), {
      name: 'invalid_grant',
    })
  })

  it('should allow string numeric tx_code in numeric mode', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-type'), 123, { tx_code_input_mode: 'numeric' })
    const valid = await provider.validate(PreAuthorizedCode('test-code-type'), '123')
    assert.equal(valid, true)
  })

  it('should throw invalid_grant for non-numeric string tx_code in numeric mode', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-invalid-numeric-string'), 123, {
      tx_code_input_mode: 'numeric',
    })
    await assert.rejects(
      provider.validate(PreAuthorizedCode('test-code-invalid-numeric-string'), '12a3'),
      { name: 'invalid_grant' }
    )
  })

  it('should preserve leading zeros in numeric mode', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-leading-zero'), '0123', {
      tx_code_input_mode: 'numeric',
    })
    const valid = await provider.validate(PreAuthorizedCode('test-code-leading-zero'), '0123')
    assert.equal(valid, true)
  })

  it('should throw invalid_grant when leading-zero digit-string is validated as number', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('test-code-leading-zero-mismatch'), '0123', {
      tx_code_input_mode: 'numeric',
    })
    await assert.rejects(
      provider.validate(PreAuthorizedCode('test-code-leading-zero-mismatch'), 123),
      { name: 'invalid_grant' }
    )
  })

  it('should store hashed tx_code in Firestore', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('hashed-code'), 123, { tx_code_input_mode: 'numeric' })

    const doc = store.get('vcknots/v1/preCodes/hashed-code')
    assert.ok(doc)
    assert.ok(doc.tx_code_hash)
    assert.equal(doc.tx_code_input_mode, 'numeric')
    assert.equal(typeof doc.tx_code_hash, 'string')
    assert.equal(doc.tx_code_hash.length, 64) // SHA-256 hex length
  })

  it('should use default numeric mode when not specified', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('default-mode'), 456)

    const doc = store.get('vcknots/v1/preCodes/default-mode')
    assert.ok(doc)
    assert.equal(doc.tx_code_input_mode, 'numeric')
  })

  it('should store expires_at as Firestore Timestamp', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('timestamp-check'), undefined, { ttlSec: 1 })

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
    await provider.save(PreAuthorizedCode('invalid-ttl-fallback'), undefined, { ttlSec: NaN })

    const doc = store.get('vcknots/v1/preCodes/invalid-ttl-fallback') as {
      expires_at?: { toMillis: () => number }
    }
    assert.ok(doc?.expires_at)
    assert.equal(doc.expires_at?.toMillis(), 300 * 1000)
  })

  it('should floor fractional ttlSec values', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('fractional-ttl'), undefined, { ttlSec: 1.9 })

    const doc = store.get('vcknots/v1/preCodes/fractional-ttl') as {
      expires_at?: { toMillis: () => number }
    }
    assert.ok(doc?.expires_at)
    assert.equal(doc.expires_at?.toMillis(), 1000)
  })

  it('should fall back to default ttlSec when fractional ttlSec floors to zero', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('fractional-ttl-zero'), undefined, { ttlSec: 0.1 })

    const doc = store.get('vcknots/v1/preCodes/fractional-ttl-zero') as {
      expires_at?: { toMillis: () => number }
    }
    assert.ok(doc?.expires_at)
    assert.equal(doc.expires_at?.toMillis(), 300 * 1000)
  })

  it('should throw invalid_grant for an unknown code', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await assert.rejects(provider.validate(PreAuthorizedCode('unknown-code')), {
      name: 'invalid_grant',
    })
  })

  it('should delete a code and throw invalid_grant when validating it afterwards', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('delete-me'))
    await provider.delete(PreAuthorizedCode('delete-me'))
    await assert.rejects(provider.validate(PreAuthorizedCode('delete-me')), {
      name: 'invalid_grant',
    })
  })

  it('should throw invalid_grant and delete an expired code', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('expiring-code'), undefined, { ttlSec: 1 })

    mock.timers.tick(1001)

    await assert.rejects(provider.validate(PreAuthorizedCode('expiring-code')), {
      name: 'invalid_grant',
    })
    assert.ok(!store.has('vcknots/v1/preCodes/expiring-code'))
  })

  it('should use default expiration of 5 minutes', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('default-expiry'))

    // Still valid before 5 minutes
    mock.timers.tick(4 * 60 * 1000)
    const validBefore = await provider.validate(PreAuthorizedCode('default-expiry'))
    assert.equal(validBefore, true)

    // Expired after 5 minutes
    mock.timers.tick(2 * 60 * 1000)
    await assert.rejects(provider.validate(PreAuthorizedCode('default-expiry')), {
      name: 'invalid_grant',
    })
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('my-code'))
    assert.ok(store.has('vcknots/v1/preCodes/my-code'))
  })

  it('should use a custom namespace', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp, namespace: 'custom' })
    await provider.save(PreAuthorizedCode('my-code'))
    assert.ok(store.has('custom/v1/preCodes/my-code'))
    assert.ok(!store.has('vcknots/v1/preCodes/my-code'))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp, namespace: 'foo/bar/baz' })
    await provider.save(PreAuthorizedCode('my-code'))
    assert.ok(store.has('foobarbaz/v1/preCodes/my-code'))
    assert.ok(!store.has('foo/bar/baz/v1/preCodes/my-code'))
  })

  it('should strip leading and trailing slashes from namespace', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp, namespace: '/my/ns/' })
    await provider.save(PreAuthorizedCode('my-code'))
    assert.ok(store.has('myns/v1/preCodes/my-code'))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp, namespace: '///' })
    await provider.save(PreAuthorizedCode('my-code'))
    assert.ok(store.has('vcknots/v1/preCodes/my-code'))
  })
})
