import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { AuthorizationServerIssuer, AuthzOAuthClient } from '@trustknots/vcknots/authz'
import { firestoreAuthzOAuthClientStore } from '../../src/providers/firestore-authz-oauth-client-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestoreAuthzOAuthClientStore', () => {
  const issuer = AuthorizationServerIssuer('https://example.com/authz')
  const hash = (value: string) => createHash('sha256').update(value).digest('base64url')
  const client = AuthzOAuthClient({
    client_id: 'client-1',
    client_name: 'Client 1',
    token_endpoint_auth_method: 'private_key_jwt',
    senderConstrainedAccessToken: {
      method: 'dpop',
      dpop: { mode: 'required' },
    },
    enabled: true,
  })

  afterEach(() => {
    store.clear()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreAuthzOAuthClientStore({ app: mockApp })

    assert.equal(provider.kind, 'authz-oauth-client-store-provider')
    assert.equal(provider.name, 'firestore-authz-oauth-client-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch an OAuth client', async () => {
    const provider = firestoreAuthzOAuthClientStore({ app: mockApp })

    await provider.save(issuer, client)
    const fetched = await provider.fetch(issuer, client.client_id)

    assert.deepEqual(fetched, client)
  })

  it('should store issuer field for Firestore console visibility', async () => {
    const provider = firestoreAuthzOAuthClientStore({ app: mockApp })
    const expectedPath = `vcknots/v1/authzOAuthClients/${hash(issuer)}/clients/${hash(
      client.client_id
    )}`

    await provider.save(issuer, client)

    assert.equal(store.get(expectedPath)?.issuer, issuer)
  })

  it('should return null for unknown or disabled clients', async () => {
    const provider = firestoreAuthzOAuthClientStore({ app: mockApp })
    await provider.save(
      issuer,
      AuthzOAuthClient({
        client_id: 'disabled-client',
        enabled: false,
      })
    )

    assert.equal(await provider.fetch(issuer, 'unknown-client'), null)
    assert.equal(await provider.fetch(issuer, 'disabled-client'), null)
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreAuthzOAuthClientStore({ app: mockApp, namespace: 'custom' })
    const expectedPath = `custom/v1/authzOAuthClients/${hash(issuer)}/clients/${hash(
      client.client_id
    )}`

    await provider.save(issuer, client)

    assert.ok(store.has(expectedPath))
    assert.ok(!store.has(expectedPath.replace('custom/', 'vcknots/')))
  })
})
