import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'
import { firestoreNonceStore } from '../../src/providers/firestore-nonce-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestoreNonceStore', () => {
  const nonce = { nonce: 'test-nonce-123', nonce_expires_in: 300_000 }

  afterEach(() => {
    store.clear()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreNonceStore({ app: mockApp })
    assert.equal(provider.kind, 'nonce-store-provider')
    assert.equal(provider.name, 'firestore-nonce-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and validate a nonce', async () => {
    const provider = firestoreNonceStore({ app: mockApp })
    await provider.save(nonce)
    const valid = await provider.validate(nonce)
    assert.equal(valid, true)
  })

  it('should return false when validating an unknown nonce', async () => {
    const provider = firestoreNonceStore({ app: mockApp })
    const valid = await provider.validate({ nonce: 'unknown-nonce' })
    assert.equal(valid, false)
  })

  it('should throw when saving a nonce without nonce_expires_in', async () => {
    const provider = firestoreNonceStore({ app: mockApp })
    await assert.rejects(() => provider.save({ nonce: 'no-expiry' }), {
      message: 'nonce_expires_in is required when saving nonce',
    })
  })

  it('should return false and delete when validating an expired nonce', async () => {
    const provider = firestoreNonceStore({ app: mockApp })
    const expired = { nonce: 'expired-nonce', nonce_expires_in: -1 }
    await provider.save(expired)
    const valid = await provider.validate(expired)
    assert.equal(valid, false)
    assert.ok(!store.has('vcknots/v1/nonces/expired-nonce'))
  })

  it('should revoke a nonce', async () => {
    const provider = firestoreNonceStore({ app: mockApp })
    await provider.save(nonce)
    const revoked = await provider.revoke(nonce)
    assert.equal(revoked, true)
    assert.ok(!store.has(`vcknots/v1/nonces/${nonce.nonce}`))
  })

  it('should return false when revoking an unknown nonce', async () => {
    const provider = firestoreNonceStore({ app: mockApp })
    const revoked = await provider.revoke({ nonce: 'unknown-nonce' })
    assert.equal(revoked, false)
  })

  it('should consume a nonce', async () => {
    const provider = firestoreNonceStore({ app: mockApp })
    await provider.save(nonce)
    const consumed = await provider.consume(nonce)
    assert.equal(consumed, true)
    assert.ok(!store.has(`vcknots/v1/nonces/${nonce.nonce}`))
  })

  it('should return false when consuming an unknown nonce', async () => {
    const provider = firestoreNonceStore({ app: mockApp })
    const consumed = await provider.consume({ nonce: 'unknown-nonce' })
    assert.equal(consumed, false)
  })

  it('should return false and delete when consuming an expired nonce', async () => {
    const provider = firestoreNonceStore({ app: mockApp })
    const expired = { nonce: 'expired-consume-nonce', nonce_expires_in: -1 }
    await provider.save(expired)
    const consumed = await provider.consume(expired)
    assert.equal(consumed, false)
    assert.ok(!store.has('vcknots/v1/nonces/expired-consume-nonce'))
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestoreNonceStore({ app: mockApp })
    await provider.save(nonce)
    assert.ok(store.has(`vcknots/v1/nonces/${nonce.nonce}`))
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreNonceStore({ app: mockApp, namespace: 'custom' })
    await provider.save(nonce)
    assert.ok(store.has(`custom/v1/nonces/${nonce.nonce}`))
    assert.ok(!store.has(`vcknots/v1/nonces/${nonce.nonce}`))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestoreNonceStore({ app: mockApp, namespace: 'foo/bar/baz' })
    await provider.save(nonce)
    assert.ok(store.has(`foobarbaz/v1/nonces/${nonce.nonce}`))
    assert.ok(!store.has(`foo/bar/baz/v1/nonces/${nonce.nonce}`))
  })

  it('should strip leading and trailing slashes from namespace', async () => {
    const provider = firestoreNonceStore({ app: mockApp, namespace: '/my/ns/' })
    await provider.save(nonce)
    assert.ok(store.has(`myns/v1/nonces/${nonce.nonce}`))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestoreNonceStore({ app: mockApp, namespace: '///' })
    await provider.save(nonce)
    assert.ok(store.has(`vcknots/v1/nonces/${nonce.nonce}`))
  })
})
