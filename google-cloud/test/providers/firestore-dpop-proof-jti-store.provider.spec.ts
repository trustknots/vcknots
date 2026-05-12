import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it, mock } from 'node:test'
import { Timestamp } from 'firebase-admin/firestore'
import { firestoreDpopProofJtiStore } from '../../src/providers/firestore-dpop-proof-jti-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

const createDocumentId = (jwkThumbprint: string, jti: string): string =>
  createHash('sha256').update(`${jwkThumbprint}:${jti}`).digest('hex')

describe('firestoreDpopProofJtiStore', () => {
  afterEach(() => {
    store.clear()
    mock.timers.reset()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreDpopProofJtiStore({ app: mockApp })
    assert.equal(provider.kind, 'dpop-proof-jti-store-provider')
    assert.equal(provider.name, 'firestore-dpop-proof-jti-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save an unused jti and reject the same jti until it expires', async () => {
    const provider = firestoreDpopProofJtiStore({ app: mockApp })

    const first = await provider.saveIfAbsent('thumbprint-1', 'jti-1')
    const second = await provider.saveIfAbsent('thumbprint-1', 'jti-1')

    assert.equal(first, true)
    assert.equal(second, false)
  })

  it('should treat different jwk thumbprints or jtis as different replay keys', async () => {
    const provider = firestoreDpopProofJtiStore({ app: mockApp })

    assert.equal(await provider.saveIfAbsent('thumbprint-1', 'jti-1'), true)
    assert.equal(await provider.saveIfAbsent('thumbprint-2', 'jti-1'), true)
    assert.equal(await provider.saveIfAbsent('thumbprint-1', 'jti-2'), true)
  })

  it('should allow saving the same replay key after expiration', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreDpopProofJtiStore({ app: mockApp, expiresIn: 1000 })

    assert.equal(await provider.saveIfAbsent('thumbprint-1', 'jti-1'), true)
    assert.equal(await provider.saveIfAbsent('thumbprint-1', 'jti-1'), false)

    mock.timers.tick(1001)

    assert.equal(await provider.saveIfAbsent('thumbprint-1', 'jti-1'), true)
  })

  it('should prefer per-call ttlMs over provider expiresIn', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreDpopProofJtiStore({ app: mockApp, expiresIn: 60_000 })

    assert.equal(
      await provider.saveIfAbsent('thumbprint-1', 'jti-1', { ttlMs: 1000 }),
      true
    )

    mock.timers.tick(1001)

    assert.equal(await provider.saveIfAbsent('thumbprint-1', 'jti-1'), true)
  })

  it('should store replay entries under a hashed document id', async () => {
    const provider = firestoreDpopProofJtiStore({ app: mockApp })

    await provider.saveIfAbsent('thumbprint/with/slash', 'jti/with/slash')

    const docId = createDocumentId('thumbprint/with/slash', 'jti/with/slash')
    const path = `vcknots/v1/dpopProofJtis/${docId}`
    assert.ok(store.has(path))
    assert.ok(!store.has('vcknots/v1/dpopProofJtis/thumbprint/with/slash:jti/with/slash'))
  })

  it('should store replay entry fields', async () => {
    const provider = firestoreDpopProofJtiStore({ app: mockApp })

    await provider.saveIfAbsent('thumbprint-1', 'jti-1')

    const docId = createDocumentId('thumbprint-1', 'jti-1')
    const data = store.get(`vcknots/v1/dpopProofJtis/${docId}`)

    assert.equal(data?.jwk_thumbprint, 'thumbprint-1')
    assert.equal(data?.jti, 'jti-1')
    assert.ok(data?.created_at instanceof Timestamp)
    assert.ok(data?.expires_at instanceof Timestamp)
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreDpopProofJtiStore({ app: mockApp, namespace: 'custom' })

    await provider.saveIfAbsent('thumbprint-1', 'jti-1')

    const docId = createDocumentId('thumbprint-1', 'jti-1')
    assert.ok(store.has(`custom/v1/dpopProofJtis/${docId}`))
    assert.ok(!store.has(`vcknots/v1/dpopProofJtis/${docId}`))
  })

  it('should strip slashes from namespace', async () => {
    const provider = firestoreDpopProofJtiStore({ app: mockApp, namespace: 'foo/bar' })

    await provider.saveIfAbsent('thumbprint-1', 'jti-1')

    const docId = createDocumentId('thumbprint-1', 'jti-1')
    assert.ok(store.has(`foobar/v1/dpopProofJtis/${docId}`))
  })
})
