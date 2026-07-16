import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { AuthorizationServerIssuer } from '../../../src/authorization-server.types'
import { AuthzOAuthPolicy } from '../../../src/authz-oauth-policy.types'
import { inMemoryAuthzOAuthPolicyStore } from '../../../src/providers/in-memory/in-memory-authz-oauth-policy-store.provider'

describe('InMemoryAuthzOAuthPolicyStoreProvider', () => {
  const issuer = AuthorizationServerIssuer('https://auth.example.com')
  const policy = AuthzOAuthPolicy({
    default_client: {
      senderConstrainedAccessToken: {
        method: 'dpop',
        dpop: {
          mode: 'optional',
        },
      },
    },
  })

  it('should return null for unknown issuer', async () => {
    const provider = inMemoryAuthzOAuthPolicyStore()
    const fetched = await provider.fetch(AuthorizationServerIssuer('https://unknown.example.com'))
    assert.equal(fetched, null)
  })

  it('should save and fetch policy by issuer', async () => {
    const provider = inMemoryAuthzOAuthPolicyStore()
    await provider.save(issuer, policy)

    const fetched = await provider.fetch(issuer)
    assert.deepEqual(fetched, policy)
  })

  it('should overwrite policy for the same issuer', async () => {
    const provider = inMemoryAuthzOAuthPolicyStore()
    await provider.save(issuer, policy)

    const updated = AuthzOAuthPolicy({
      default_client: {
        senderConstrainedAccessToken: {
          method: 'dpop',
          dpop: {
            mode: 'required',
          },
        },
      },
    })

    await provider.save(issuer, updated)
    const fetched = await provider.fetch(issuer)

    assert.deepEqual(fetched, updated)
    assert.notDeepEqual(fetched, policy)
  })
})
