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

  it('should return false for an unknown code', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    const valid = await provider.validate(PreAuthorizedCode('unknown-code'))
    assert.equal(valid, false)
  })

  it('should delete a code', async () => {
    const provider = firestorePreAuthorizedCodeStore({ app: mockApp })
    await provider.save(PreAuthorizedCode('delete-me'))
    await provider.delete(PreAuthorizedCode('delete-me'))
    const valid = await provider.validate(PreAuthorizedCode('delete-me'))
    assert.equal(valid, false)
  })

  it('should return false and delete an expired code', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestorePreAuthorizedCodeStore({ app: mockApp, expiresIn: 1000 })
    await provider.save(PreAuthorizedCode('expiring-code'))

    mock.timers.tick(1001)

    const valid = await provider.validate(PreAuthorizedCode('expiring-code'))
    assert.equal(valid, false)
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
    const validAfter = await provider.validate(PreAuthorizedCode('default-expiry'))
    assert.equal(validAfter, false)
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
