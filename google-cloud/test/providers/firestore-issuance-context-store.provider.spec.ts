import assert from 'node:assert/strict'
import { afterEach, describe, it, mock } from 'node:test'
import { CredentialConfigurationId } from '@trustknots/vcknots'
import { firestoreIssuanceContextStore } from '../../src/providers/firestore-issuance-context-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestoreIssuanceContextStore', () => {
  afterEach(() => {
    store.clear()
    mock.timers.reset()
  })

  const configurations: CredentialConfigurationId[] = [
    CredentialConfigurationId('University_Degree'),
  ]
  const updatedConfigurations: CredentialConfigurationId[] = [
    CredentialConfigurationId('EmployeeID_JWT'),
  ]

  it('should have correct provider metadata', () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp })
    assert.equal(provider.kind, 'issuance-context-store-provider')
    assert.equal(provider.name, 'firestore-issuance-context-store-provider')
    assert.equal(provider.single, true)
  })

  it('should return null for an unknown access token hash', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp })

    const fetched = await provider.fetch('unknown-access-token-hash')

    assert.equal(fetched, null)
  })

  it('should save credential configuration ids and fetch them back', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp })

    await provider.save('test-access-token-hash', configurations)

    const fetched = await provider.fetch('test-access-token-hash')

    assert.deepStrictEqual(fetched, configurations)
  })

  it('should persist credential_configuration_ids in Firestore document', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp })

    await provider.save('stored-config-access-token-hash', configurations)

    const doc = store.get('vcknots/v1/issuanceContexts/stored-config-access-token-hash')
    assert.ok(doc)
    assert.deepStrictEqual(doc.credential_configuration_ids, configurations)
  })

  it('should overwrite existing context when saving with the same access token hash', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp })

    await provider.save('same-access-token-hash', configurations)
    await provider.save('same-access-token-hash', updatedConfigurations)

    const fetched = await provider.fetch('same-access-token-hash')

    assert.deepStrictEqual(fetched, updatedConfigurations)
  })

  it('should save independently for multiple access token hashes', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp })

    await provider.save('access-token-hash-1', configurations)
    await provider.save('access-token-hash-2', updatedConfigurations)

    assert.deepStrictEqual(await provider.fetch('access-token-hash-1'), configurations)
    assert.deepStrictEqual(await provider.fetch('access-token-hash-2'), updatedConfigurations)
  })

  it('should store expires_at as Firestore Timestamp', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreIssuanceContextStore({ app: mockApp })
    await provider.save('timestamp-check', configurations, 1)

    const doc = store.get('vcknots/v1/issuanceContexts/timestamp-check') as {
      expires_at?: { toMillis: () => number }
    }

    assert.ok(doc)
    assert.ok(doc.expires_at)
    assert.equal(typeof doc.expires_at?.toMillis, 'function')
    assert.equal(doc.expires_at?.toMillis(), 1000)
  })

  it('should fall back to default ttlSec when ttl is invalid', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreIssuanceContextStore({ app: mockApp })
    await provider.save('invalid-ttl', configurations, Number.NaN)

    const doc = store.get('vcknots/v1/issuanceContexts/invalid-ttl') as {
      expires_at?: { toMillis: () => number }
    }

    assert.ok(doc?.expires_at)
    assert.equal(doc.expires_at?.toMillis(), 300 * 1000)
  })

  it('should floor fractional ttlSec values', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreIssuanceContextStore({ app: mockApp })
    await provider.save('fractional-ttl', configurations, 1.9)

    const doc = store.get('vcknots/v1/issuanceContexts/fractional-ttl') as {
      expires_at?: { toMillis: () => number }
    }

    assert.ok(doc?.expires_at)
    assert.equal(doc.expires_at?.toMillis(), 1000)
  })

  it('should fall back to default ttlSec when fractional ttlSec floors to zero', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreIssuanceContextStore({ app: mockApp })
    await provider.save('fractional-zero', configurations, 0.1)

    const doc = store.get('vcknots/v1/issuanceContexts/fractional-zero') as {
      expires_at?: { toMillis: () => number }
    }

    assert.ok(doc?.expires_at)
    assert.equal(doc.expires_at?.toMillis(), 300 * 1000)
  })

  it('should expire the context after the specified ttl', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreIssuanceContextStore({ app: mockApp })
    await provider.save('expiring-access-token-hash', configurations, 1)

    mock.timers.tick(500)
    assert.deepStrictEqual(await provider.fetch('expiring-access-token-hash'), configurations)

    mock.timers.tick(600)
    assert.equal(await provider.fetch('expiring-access-token-hash'), null)
  })

  it('should delete expired context on fetch', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreIssuanceContextStore({ app: mockApp })
    await provider.save('expired-access-token-hash', configurations, 1)

    mock.timers.tick(1001)

    assert.equal(await provider.fetch('expired-access-token-hash'), null)
    assert.ok(!store.has('vcknots/v1/issuanceContexts/expired-access-token-hash'))
  })

  it('should use default ttl when ttl is not specified', async () => {
    mock.timers.enable({ apis: ['Date'] })

    const provider = firestoreIssuanceContextStore({ app: mockApp })
    await provider.save('default-ttl', configurations)

    mock.timers.tick(299_000)
    assert.deepStrictEqual(await provider.fetch('default-ttl'), configurations)

    mock.timers.tick(2_000)
    assert.equal(await provider.fetch('default-ttl'), null)
  })

  it('should delete an existing context', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp })

    await provider.save('delete-me', configurations)
    await provider.delete('delete-me')

    const fetched = await provider.fetch('delete-me')
    assert.equal(fetched, null)
  })

  it('should only delete the specified access token hash', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp })

    await provider.save('access-token-hash-1', configurations)
    await provider.save('access-token-hash-2', updatedConfigurations)

    await provider.delete('access-token-hash-1')

    assert.equal(await provider.fetch('access-token-hash-1'), null)
    assert.deepStrictEqual(await provider.fetch('access-token-hash-2'), updatedConfigurations)
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp })

    await provider.save('path-check', configurations)

    assert.ok(store.has('vcknots/v1/issuanceContexts/path-check'))
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp, namespace: 'custom' })

    await provider.save('my-access-token-hash', configurations)

    assert.ok(store.has('custom/v1/issuanceContexts/my-access-token-hash'))
    assert.ok(!store.has('vcknots/v1/issuanceContexts/my-access-token-hash'))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestoreIssuanceContextStore({
      app: mockApp,
      namespace: 'foo/bar/baz',
    })

    await provider.save('my-access-token-hash', configurations)

    assert.ok(store.has('foobarbaz/v1/issuanceContexts/my-access-token-hash'))
    assert.ok(!store.has('foo/bar/baz/v1/issuanceContexts/my-access-token-hash'))
  })

  it('should strip leading and trailing slashes from namespace', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp, namespace: '/my/ns/' })

    await provider.save('my-access-token-hash', configurations)

    assert.ok(store.has('myns/v1/issuanceContexts/my-access-token-hash'))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestoreIssuanceContextStore({ app: mockApp, namespace: '///' })

    await provider.save('my-access-token-hash', configurations)

    assert.ok(store.has('vcknots/v1/issuanceContexts/my-access-token-hash'))
  })
})
