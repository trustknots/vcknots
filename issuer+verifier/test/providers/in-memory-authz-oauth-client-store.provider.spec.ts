import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { AuthorizationServerIssuer, AuthzOAuthClient } from '../../src/authz.flows'
import { inMemoryAuthzOAuthClientStore } from '../../src/providers/in-memory/in-memory-authz-oauth-client-store.provider'

describe('inMemoryAuthzOAuthClientStore', () => {
  const issuer = AuthorizationServerIssuer('https://example.com/authz')
  const client = AuthzOAuthClient({
    client_id: 'client-1',
    token_endpoint_auth_method: 'private_key_jwt',
    senderConstrainedAccessToken: {
      method: 'dpop',
      dpop: { mode: 'required' },
    },
    enabled: true,
  })

  it('should save and fetch an OAuth client by issuer and client_id', async () => {
    const provider = inMemoryAuthzOAuthClientStore()

    await provider.save(issuer, client)
    const fetched = await provider.fetch(issuer, client.client_id)

    assert.deepEqual(fetched, client)
  })

  it('should return null for unknown or disabled clients', async () => {
    const provider = inMemoryAuthzOAuthClientStore()
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
})
