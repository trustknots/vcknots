import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { CredentialIssuer, CredentialIssuerMetadata } from '@trustknots/vcknots/issuer'
import { firestoreIssuerMetadataStore } from '../../src/providers/firestore-issuer-metadata-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestoreIssuerMetadataStore', () => {
  const md5 = (value: string) => createHash('md5').update(value).digest('base64url')

  const metadata: CredentialIssuerMetadata = {
    credential_issuer: CredentialIssuer('https://example.com/issuer'),
    credential_endpoint: 'https://example.com/issuer/credential',
    authorization_servers: ['https://example.com/authz'],
    credential_configurations_supported: {
      EmployeeID_jwt_vc_json: {
        format: 'jwt_vc_json',
        scope: 'employee_id',
        cryptographic_binding_methods_supported: ['did:example'],
        credential_definition: {
          type: ['VerifiableCredential', 'EmployeeIDCredential'],
        },
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['ES256'],
          },
        },
        credential_signing_alg_values_supported: ['ES256'],
      },
    },
  }

  afterEach(() => {
    store.clear()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreIssuerMetadataStore({ app: mockApp })
    assert.equal(provider.kind, 'issuer-metadata-store-provider')
    assert.equal(provider.name, 'firestore-issuer-metadata-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch issuer metadata', async () => {
    const provider = firestoreIssuerMetadataStore({ app: mockApp })
    await provider.save(metadata)
    const fetched = await provider.fetch(metadata.credential_issuer)
    assert.deepEqual(fetched, metadata)
  })

  it('should return null when fetching metadata for an unknown issuer', async () => {
    const provider = firestoreIssuerMetadataStore({ app: mockApp })
    const fetched = await provider.fetch(CredentialIssuer('https://unknown.example.com/issuer'))
    assert.equal(fetched, null)
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestoreIssuerMetadataStore({ app: mockApp })
    const expectedId = md5(metadata.credential_issuer)

    await provider.save(metadata)

    assert.ok(store.has(`vcknots/v1/issuers/${expectedId}`))
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreIssuerMetadataStore({ app: mockApp, namespace: 'custom' })
    const expectedId = md5(metadata.credential_issuer)

    await provider.save(metadata)

    assert.ok(store.has(`custom/v1/issuers/${expectedId}`))
    assert.ok(!store.has(`vcknots/v1/issuers/${expectedId}`))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestoreIssuerMetadataStore({ app: mockApp, namespace: 'foo/bar/baz' })
    const expectedId = md5(metadata.credential_issuer)

    await provider.save(metadata)

    assert.ok(store.has(`foobarbaz/v1/issuers/${expectedId}`))
    assert.ok(!store.has(`foo/bar/baz/v1/issuers/${expectedId}`))
  })

  it('should strip leading and trailing slashes from namespace', async () => {
    const provider = firestoreIssuerMetadataStore({ app: mockApp, namespace: '/my/ns/' })
    const expectedId = md5(metadata.credential_issuer)

    await provider.save(metadata)

    assert.ok(store.has(`myns/v1/issuers/${expectedId}`))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestoreIssuerMetadataStore({ app: mockApp, namespace: '///' })
    const expectedId = md5(metadata.credential_issuer)

    await provider.save(metadata)

    assert.ok(store.has(`vcknots/v1/issuers/${expectedId}`))
  })

  it('should fully replace existing metadata on save', async () => {
    const provider = firestoreIssuerMetadataStore({ app: mockApp })
    await provider.save(metadata)

    const updated: CredentialIssuerMetadata = {
      ...metadata,
      credential_endpoint: 'https://example.com/issuer/updated_credential',
      authorization_servers: ['https://example.com/new-authz'],
    }
    await provider.save(updated)

    const fetched = await provider.fetch(metadata.credential_issuer)
    assert.notEqual(fetched, null)
    assert.deepEqual(fetched, updated)
  })
})
