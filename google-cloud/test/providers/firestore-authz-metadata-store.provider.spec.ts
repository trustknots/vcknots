import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { AuthorizationServerIssuer, AuthorizationServerMetadata } from '@trustknots/vcknots/authz'
import { firestoreAuthzServerMetadataStore } from '../../src/providers/firestore-authz-metadata-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestoreAuthzServerMetadataStore', () => {
  const md5 = (value: string) => createHash('md5').update(value).digest('base64url')

  const metadata: AuthorizationServerMetadata = AuthorizationServerMetadata({
    issuer: 'https://example.com/authz',
    authorization_endpoint: 'https://example.com/authz/authorize',
    token_endpoint: 'https://example.com/authz/token',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:pre-authorized_code'],
  })

  afterEach(() => {
    store.clear()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreAuthzServerMetadataStore({ app: mockApp })
    assert.equal(provider.kind, 'authz-server-metadata-store-provider')
    assert.equal(provider.name, 'firestore-authz-server-metadata-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch authz server metadata', async () => {
    const provider = firestoreAuthzServerMetadataStore({ app: mockApp })
    await provider.save(metadata)
    const fetched = await provider.fetch(AuthorizationServerIssuer(metadata.issuer))
    assert.deepEqual(fetched, metadata)
  })

  it('should return null when fetching metadata for an unknown issuer', async () => {
    const provider = firestoreAuthzServerMetadataStore({ app: mockApp })
    const fetched = await provider.fetch(AuthorizationServerIssuer('https://unknown.example.com/authz'))
    assert.equal(fetched, null)
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestoreAuthzServerMetadataStore({ app: mockApp })
    const expectedId = md5(metadata.issuer)

    await provider.save(metadata)

    assert.ok(store.has(`vcknots/v1/authServers/${expectedId}`))
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreAuthzServerMetadataStore({ app: mockApp, namespace: 'custom' })
    const expectedId = md5(metadata.issuer)

    await provider.save(metadata)

    assert.ok(store.has(`custom/v1/authServers/${expectedId}`))
    assert.ok(!store.has(`vcknots/v1/authServers/${expectedId}`))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestoreAuthzServerMetadataStore({ app: mockApp, namespace: 'foo/bar/baz' })
    const expectedId = md5(metadata.issuer)

    await provider.save(metadata)

    assert.ok(store.has(`foobarbaz/v1/authServers/${expectedId}`))
    assert.ok(!store.has(`foo/bar/baz/v1/authServers/${expectedId}`))
  })

  it('should strip leading and trailing slashes from namespace', async () => {
    const provider = firestoreAuthzServerMetadataStore({ app: mockApp, namespace: '/my/ns/' })
    const expectedId = md5(metadata.issuer)

    await provider.save(metadata)

    assert.ok(store.has(`myns/v1/authServers/${expectedId}`))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestoreAuthzServerMetadataStore({ app: mockApp, namespace: '///' })
    const expectedId = md5(metadata.issuer)

    await provider.save(metadata)

    assert.ok(store.has(`vcknots/v1/authServers/${expectedId}`))
  })

  it('should fully replace existing metadata on save', async () => {
    const provider = firestoreAuthzServerMetadataStore({ app: mockApp })
    await provider.save(metadata)

    const updated = AuthorizationServerMetadata({
      ...metadata,
      token_endpoint: 'https://example.com/authz/updated_token',
      grant_types_supported: ['authorization_code'],
    })
    await provider.save(updated)

    const fetched = await provider.fetch(AuthorizationServerIssuer(metadata.issuer))
    assert.notEqual(fetched, null)
    assert.deepEqual(fetched, updated)
  })
})
