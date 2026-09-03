import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { AuthorizationServerIssuer, AuthzOAuthPolicy } from '@trustknots/vcknots/authz'
import { firestoreAuthzOAuthPolicyStore } from '../../src/providers/firestore-authz-oauth-policy-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestoreAuthzOAuthPolicyStore', () => {
  const issuer = AuthorizationServerIssuer('https://example.com/authz')
  const md5 = (value: string) => createHash('md5').update(value).digest('base64url')
  const policy = AuthzOAuthPolicy({
    default_client: {
      senderConstrainedAccessToken: {
        method: 'dpop',
        dpop: {
          mode: 'optional',
        },
      },
    },
    anonymous_client: {
      senderConstrainedAccessToken: {
        method: 'dpop',
        dpop: {
          mode: 'required',
        },
      },
    },
  })

  afterEach(() => {
    store.clear()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreAuthzOAuthPolicyStore({ app: mockApp })

    assert.equal(provider.kind, 'authz-oauth-policy-store-provider')
    assert.equal(provider.name, 'firestore-authz-oauth-policy-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch authz OAuth policy', async () => {
    const provider = firestoreAuthzOAuthPolicyStore({ app: mockApp })

    await provider.save(issuer, policy)
    const fetched = await provider.fetch(issuer)

    assert.deepEqual(fetched, policy)
  })

  it('should store issuer field for Firestore console visibility', async () => {
    const provider = firestoreAuthzOAuthPolicyStore({ app: mockApp })
    const expectedId = md5(issuer)

    await provider.save(issuer, policy)

    assert.equal(store.get(`vcknots/v1/authzOAuthPolicies/${expectedId}`)?.issuer, issuer)
  })

  it('should return null when fetching policy for an unknown issuer', async () => {
    const provider = firestoreAuthzOAuthPolicyStore({ app: mockApp })

    const fetched = await provider.fetch(AuthorizationServerIssuer('https://unknown.example.com/authz'))

    assert.equal(fetched, null)
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestoreAuthzOAuthPolicyStore({ app: mockApp })
    const expectedId = md5(issuer)

    await provider.save(issuer, policy)

    assert.ok(store.has(`vcknots/v1/authzOAuthPolicies/${expectedId}`))
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreAuthzOAuthPolicyStore({ app: mockApp, namespace: 'custom' })
    const expectedId = md5(issuer)

    await provider.save(issuer, policy)

    assert.ok(store.has(`custom/v1/authzOAuthPolicies/${expectedId}`))
    assert.ok(!store.has(`vcknots/v1/authzOAuthPolicies/${expectedId}`))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestoreAuthzOAuthPolicyStore({ app: mockApp, namespace: 'foo/bar/baz' })
    const expectedId = md5(issuer)

    await provider.save(issuer, policy)

    assert.ok(store.has(`foobarbaz/v1/authzOAuthPolicies/${expectedId}`))
    assert.ok(!store.has(`foo/bar/baz/v1/authzOAuthPolicies/${expectedId}`))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestoreAuthzOAuthPolicyStore({ app: mockApp, namespace: '///' })
    const expectedId = md5(issuer)

    await provider.save(issuer, policy)

    assert.ok(store.has(`vcknots/v1/authzOAuthPolicies/${expectedId}`))
  })

  it('should merge updates on save', async () => {
    const provider = firestoreAuthzOAuthPolicyStore({ app: mockApp })
    await provider.save(issuer, policy)

    const updated = AuthzOAuthPolicy({
      default_client: {
        senderConstrainedAccessToken: {
          method: 'none',
        },
      },
    })
    await provider.save(issuer, updated)

    const fetched = await provider.fetch(issuer)
    assert.deepEqual(fetched, {
      ...policy,
      ...updated,
    })
  })
})
