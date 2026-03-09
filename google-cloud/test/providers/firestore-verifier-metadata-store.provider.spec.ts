import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { VerifierClientId, VerifierMetadata } from '@trustknots/vcknots/verifier'
import { firestoreVerifierMetadataStore } from '../../src/providers/firestore-verifier-metadata-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestoreVerifierMetadataStore', () => {
  const md5 = (value: string) => createHash('md5').update(value).digest('base64url')

  const verifier = VerifierClientId('https://example.com/verifier')

  const metadata: VerifierMetadata = {
    client_name: 'Example Verifier',
    redirect_uris: ['https://example.com/verifier/callback'],
    response_types: 'code',
    vp_formats: {
      jwt_vp_json: {
        alg: ['ES256'],
      },
    },
  }

  afterEach(() => {
    store.clear()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreVerifierMetadataStore({ app: mockApp })
    assert.equal(provider.kind, 'verifier-metadata-store-provider')
    assert.equal(provider.name, 'firestore-verifier-metadata-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch verifier metadata', async () => {
    const provider = firestoreVerifierMetadataStore({ app: mockApp })
    await provider.save(verifier, metadata)
    const fetched = await provider.fetch(verifier)
    assert.deepEqual(fetched, metadata)
  })

  it('should return null when fetching metadata for an unknown verifier', async () => {
    const provider = firestoreVerifierMetadataStore({ app: mockApp })
    const fetched = await provider.fetch(VerifierClientId('https://unknown.example.com/verifier'))
    assert.equal(fetched, null)
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestoreVerifierMetadataStore({ app: mockApp })
    const expectedId = md5(verifier)

    await provider.save(verifier, metadata)

    assert.ok(store.has(`vcknots/v1/verifiers/${expectedId}`))
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreVerifierMetadataStore({ app: mockApp, namespace: 'custom' })
    const expectedId = md5(verifier)

    await provider.save(verifier, metadata)

    assert.ok(store.has(`custom/v1/verifiers/${expectedId}`))
    assert.ok(!store.has(`vcknots/v1/verifiers/${expectedId}`))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestoreVerifierMetadataStore({ app: mockApp, namespace: 'foo/bar/baz' })
    const expectedId = md5(verifier)

    await provider.save(verifier, metadata)

    assert.ok(store.has(`foobarbaz/v1/verifiers/${expectedId}`))
    assert.ok(!store.has(`foo/bar/baz/v1/verifiers/${expectedId}`))
  })

  it('should strip leading and trailing slashes from namespace', async () => {
    const provider = firestoreVerifierMetadataStore({ app: mockApp, namespace: '/my/ns/' })
    const expectedId = md5(verifier)

    await provider.save(verifier, metadata)

    assert.ok(store.has(`myns/v1/verifiers/${expectedId}`))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestoreVerifierMetadataStore({ app: mockApp, namespace: '///' })
    const expectedId = md5(verifier)

    await provider.save(verifier, metadata)

    assert.ok(store.has(`vcknots/v1/verifiers/${expectedId}`))
  })

  it('should fully replace existing metadata on save', async () => {
    const provider = firestoreVerifierMetadataStore({ app: mockApp })
    await provider.save(verifier, metadata)

    const updated: VerifierMetadata = {
      ...metadata,
      client_name: 'Updated Verifier',
      redirect_uris: ['https://example.com/verifier/new-callback'],
    }
    await provider.save(verifier, updated)

    const fetched = await provider.fetch(verifier)
    assert.notEqual(fetched, null)
    assert.deepEqual(fetched, updated)
  })
})
