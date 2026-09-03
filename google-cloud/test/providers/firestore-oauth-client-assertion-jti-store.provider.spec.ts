import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it, mock } from 'node:test'
import { Timestamp } from 'firebase-admin/firestore'
import { firestoreOAuthClientAssertionJtiStore } from '../../src/providers/firestore-oauth-client-assertion-jti-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

const createDocumentId = (clientId: string, jti: string): string =>
  createHash('sha256').update(JSON.stringify([clientId, jti])).digest('hex')

describe('firestoreOAuthClientAssertionJtiStore', () => {
  afterEach(() => {
    store.clear()
    mock.timers.reset()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreOAuthClientAssertionJtiStore({ app: mockApp })
    assert.equal(provider.kind, 'oauth-client-assertion-jti-store-provider')
    assert.equal(provider.name, 'firestore-oauth-client-assertion-jti-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save an unused jti and reject the same jti until it expires', async () => {
    const provider = firestoreOAuthClientAssertionJtiStore({ app: mockApp })

    const first = await provider.saveIfAbsent('client-1', 'jti-1')
    const second = await provider.saveIfAbsent('client-1', 'jti-1')

    assert.equal(first, true)
    assert.equal(second, false)
  })

  it('should treat different clients or jtis as different replay keys', async () => {
    const provider = firestoreOAuthClientAssertionJtiStore({ app: mockApp })

    assert.equal(await provider.saveIfAbsent('client-1', 'jti-1'), true)
    assert.equal(await provider.saveIfAbsent('client-2', 'jti-1'), true)
    assert.equal(await provider.saveIfAbsent('client-1', 'jti-2'), true)
  })

  it('should allow saving the same replay key after expiration', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreOAuthClientAssertionJtiStore({ app: mockApp, expiresIn: 1000 })

    assert.equal(await provider.saveIfAbsent('client-1', 'jti-1'), true)
    assert.equal(await provider.saveIfAbsent('client-1', 'jti-1'), false)

    mock.timers.tick(1001)

    assert.equal(await provider.saveIfAbsent('client-1', 'jti-1'), true)
  })

  it('should prefer per-call ttlMs over provider expiresIn', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreOAuthClientAssertionJtiStore({
      app: mockApp,
      expiresIn: 60_000,
    })

    assert.equal(await provider.saveIfAbsent('client-1', 'jti-1', { ttlMs: 1000 }), true)

    mock.timers.tick(1001)

    assert.equal(await provider.saveIfAbsent('client-1', 'jti-1'), true)
  })

  it('should store replay entries under a hashed document id', async () => {
    const provider = firestoreOAuthClientAssertionJtiStore({ app: mockApp })

    await provider.saveIfAbsent('client/with/slash', 'jti/with/slash')

    const docId = createDocumentId('client/with/slash', 'jti/with/slash')
    const path = `vcknots/v1/oauthClientAssertionJtis/${docId}`
    assert.ok(store.has(path))
    assert.ok(!store.has('vcknots/v1/oauthClientAssertionJtis/client/with/slash:jti/with/slash'))
  })

  it('should avoid delimiter collisions when building replay keys', async () => {
    const provider = firestoreOAuthClientAssertionJtiStore({ app: mockApp })

    assert.equal(await provider.saveIfAbsent('client:a', 'b'), true)
    assert.equal(await provider.saveIfAbsent('client', 'a:b'), true)
  })

  it('should store replay entry fields', async () => {
    const provider = firestoreOAuthClientAssertionJtiStore({ app: mockApp })

    await provider.saveIfAbsent('client-1', 'jti-1')

    const docId = createDocumentId('client-1', 'jti-1')
    const data = store.get(`vcknots/v1/oauthClientAssertionJtis/${docId}`)

    assert.equal(data?.client_id, 'client-1')
    assert.equal(data?.jti, 'jti-1')
    assert.ok(data?.created_at instanceof Timestamp)
    assert.ok(data?.expires_at instanceof Timestamp)
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreOAuthClientAssertionJtiStore({ app: mockApp, namespace: 'custom' })

    await provider.saveIfAbsent('client-1', 'jti-1')

    const docId = createDocumentId('client-1', 'jti-1')
    assert.ok(store.has(`custom/v1/oauthClientAssertionJtis/${docId}`))
    assert.ok(!store.has(`vcknots/v1/oauthClientAssertionJtis/${docId}`))
  })

  it('should strip slashes from namespace', async () => {
    const provider = firestoreOAuthClientAssertionJtiStore({
      app: mockApp,
      namespace: 'foo/bar',
    })

    await provider.saveIfAbsent('client-1', 'jti-1')

    const docId = createDocumentId('client-1', 'jti-1')
    assert.ok(store.has(`foobar/v1/oauthClientAssertionJtis/${docId}`))
  })
})
