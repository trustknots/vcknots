import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'
import { Cnonce } from '@trustknots/vcknots'
import { firestoreCnonceStore } from '../../src/providers/firestore-cnonce-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestoreCnonceStore', () => {
  const cnonce = Cnonce('test-cnonce-123')

  afterEach(() => {
    store.clear()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreCnonceStore({ app: mockApp })
    assert.equal(provider.kind, 'cnonce-store-provider')
    assert.equal(provider.name, 'firestore-cnonce-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and validate a cnonce', async () => {
    const provider = firestoreCnonceStore({ app: mockApp })
    await provider.save(cnonce)
    const valid = await provider.validate(cnonce)
    assert.equal(valid, true)
  })

  it('should return false when validating an unknown cnonce', async () => {
    const provider = firestoreCnonceStore({ app: mockApp })
    const valid = await provider.validate(Cnonce('unknown-cnonce'))
    assert.equal(valid, false)
  })

  it('should return false and delete when validating an expired cnonce', async () => {
    const provider = firestoreCnonceStore({ app: mockApp, c_nonce_expire_in: -1 })
    await provider.save(cnonce)
    const valid = await provider.validate(cnonce)
    assert.equal(valid, false)
    assert.ok(!store.has(`vcknots/v1/nonces/${cnonce}`))
  })

  it('should revoke a cnonce', async () => {
    const provider = firestoreCnonceStore({ app: mockApp })
    await provider.save(cnonce)
    await provider.revoke(cnonce)
    assert.ok(!store.has(`vcknots/v1/nonces/${cnonce}`))
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestoreCnonceStore({ app: mockApp })
    await provider.save(cnonce)
    assert.ok(store.has(`vcknots/v1/nonces/${cnonce}`))
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreCnonceStore({ app: mockApp, namespace: 'custom' })
    await provider.save(cnonce)
    assert.ok(store.has(`custom/v1/nonces/${cnonce}`))
    assert.ok(!store.has(`vcknots/v1/nonces/${cnonce}`))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestoreCnonceStore({ app: mockApp, namespace: 'foo/bar/baz' })
    await provider.save(cnonce)
    assert.ok(store.has(`foobarbaz/v1/nonces/${cnonce}`))
    assert.ok(!store.has(`foo/bar/baz/v1/nonces/${cnonce}`))
  })

  it('should strip leading and trailing slashes from namespace', async () => {
    const provider = firestoreCnonceStore({ app: mockApp, namespace: '/my/ns/' })
    await provider.save(cnonce)
    assert.ok(store.has(`myns/v1/nonces/${cnonce}`))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestoreCnonceStore({ app: mockApp, namespace: '///' })
    await provider.save(cnonce)
    assert.ok(store.has(`vcknots/v1/nonces/${cnonce}`))
  })
})
