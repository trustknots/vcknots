import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { firestore, resolveFirestore } from '../../src/providers/firestore.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { mockApp, mockFirestore } = createFirestoreTestMock()

describe('firestore provider registry', () => {
  it('should include all Firestore-backed providers', () => {
    const providers = firestore({ app: mockApp })

    assert.deepEqual(
      providers.map((provider) => provider.kind),
      [
        'issuer-metadata-store-provider',
        'verifier-metadata-store-provider',
        'nonce-store-provider',
        'authz-server-metadata-store-provider',
        'authz-oauth-policy-store-provider',
        'authz-oauth-client-store-provider',
        'oauth-client-assertion-jti-store-provider',
        'pre-authorized-code-store-provider',
        'request-object-store-provider',
        'dpop-proof-jti-store-provider',
      ]
    )
  })

  it('should resolve Firestore from app and databaseId', () => {
    const resolved = resolveFirestore({ app: mockApp, databaseId: 'test-db' })

    assert.equal(resolved, mockFirestore)
  })
})
