import assert from 'node:assert/strict'
import { afterEach, describe, it, mock } from 'node:test'
import { RequestObjectId } from '@trustknots/vcknots'
import { RequestObject } from '@trustknots/vcknots'
import { firestoreRequestObjectStore } from '../../src/providers/firestore-request-object-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

const testRequestObject = {
  response_type: 'vp_token',
  client_id: 'https://verifier.example.com',
  response_mode: 'direct_post',
  response_uri: 'https://verifier.example.com/response',
  nonce: 'test-nonce',
  presentation_definition: {
    id: 'test-pd',
    input_descriptors: [],
  },
} as unknown as RequestObject

describe('firestoreRequestObjectStore', () => {
  afterEach(() => {
    store.clear()
    mock.timers.reset()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreRequestObjectStore({ app: mockApp })
    assert.equal(provider.kind, 'request-object-store-provider')
    assert.equal(provider.name, 'firestore-request-object-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch a request object', async () => {
    const provider = firestoreRequestObjectStore({ app: mockApp })
    await provider.save(RequestObjectId('test-id-123'), testRequestObject)
    const result = await provider.fetch(RequestObjectId('test-id-123'))
    assert.deepEqual(result, testRequestObject)
  })

  it('should return null for an unknown id', async () => {
    const provider = firestoreRequestObjectStore({ app: mockApp })
    const result = await provider.fetch(RequestObjectId('unknown-id'))
    assert.equal(result, null)
  })

  it('should delete a request object', async () => {
    const provider = firestoreRequestObjectStore({ app: mockApp })
    await provider.save(RequestObjectId('delete-me'), testRequestObject)
    await provider.delete(RequestObjectId('delete-me'))
    const result = await provider.fetch(RequestObjectId('delete-me'))
    assert.equal(result, null)
  })

  it('should return null and delete an expired request object', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreRequestObjectStore({ app: mockApp, expiresIn: 1000 })
    await provider.save(RequestObjectId('expiring-id'), testRequestObject)

    mock.timers.tick(1001)

    const result = await provider.fetch(RequestObjectId('expiring-id'))
    assert.equal(result, null)
    assert.ok(!store.has('vcknots/v1/requestObjects/expiring-id'))
  })

  it('should use default expiration of 5 minutes', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreRequestObjectStore({ app: mockApp })
    await provider.save(RequestObjectId('default-expiry'), testRequestObject)

    // Still valid before 5 minutes
    mock.timers.tick(4 * 60 * 1000)
    const validBefore = await provider.fetch(RequestObjectId('default-expiry'))
    assert.deepEqual(validBefore, testRequestObject)

    // Expired after 5 minutes
    mock.timers.tick(2 * 60 * 1000)
    const validAfter = await provider.fetch(RequestObjectId('default-expiry'))
    assert.equal(validAfter, null)
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestoreRequestObjectStore({ app: mockApp })
    await provider.save(RequestObjectId('my-id'), testRequestObject)
    assert.ok(store.has('vcknots/v1/requestObjects/my-id'))
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreRequestObjectStore({ app: mockApp, namespace: 'custom' })
    await provider.save(RequestObjectId('my-id'), testRequestObject)
    assert.ok(store.has('custom/v1/requestObjects/my-id'))
    assert.ok(!store.has('vcknots/v1/requestObjects/my-id'))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestoreRequestObjectStore({ app: mockApp, namespace: 'foo/bar/baz' })
    await provider.save(RequestObjectId('my-id'), testRequestObject)
    assert.ok(store.has('foobarbaz/v1/requestObjects/my-id'))
    assert.ok(!store.has('foo/bar/baz/v1/requestObjects/my-id'))
  })

  it('should strip leading and trailing slashes from namespace', async () => {
    const provider = firestoreRequestObjectStore({ app: mockApp, namespace: '/my/ns/' })
    await provider.save(RequestObjectId('my-id'), testRequestObject)
    assert.ok(store.has('myns/v1/requestObjects/my-id'))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestoreRequestObjectStore({ app: mockApp, namespace: '///' })
    await provider.save(RequestObjectId('my-id'), testRequestObject)
    assert.ok(store.has('vcknots/v1/requestObjects/my-id'))
  })
})
