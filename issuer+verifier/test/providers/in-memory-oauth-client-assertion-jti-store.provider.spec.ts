import assert from 'node:assert/strict'
import { describe, it, mock } from 'node:test'
import { inMemoryOAuthClientAssertionJtiStore } from '../../src/providers/in-memory/in-memory-oauth-client-assertion-jti-store.provider'

describe('InMemoryOAuthClientAssertionJtiStoreProvider', () => {
  it('should have correct properties', () => {
    const provider = inMemoryOAuthClientAssertionJtiStore()

    assert.equal(provider.kind, 'oauth-client-assertion-jti-store-provider')
    assert.equal(provider.name, 'in-memory-oauth-client-assertion-jti-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save a jti only when it has not been used for the same client', async () => {
    const provider = inMemoryOAuthClientAssertionJtiStore()

    assert.equal(await provider.saveIfAbsent('client-1', 'jti-1'), true)
    assert.equal(await provider.saveIfAbsent('client-1', 'jti-1'), false)
    assert.equal(await provider.saveIfAbsent('client-2', 'jti-1'), true)
    assert.equal(await provider.saveIfAbsent('client-1', 'jti-2'), true)
  })

  it('should avoid delimiter collisions when building replay keys', async () => {
    const provider = inMemoryOAuthClientAssertionJtiStore()

    assert.equal(await provider.saveIfAbsent('client:a', 'b'), true)
    assert.equal(await provider.saveIfAbsent('client', 'a:b'), true)
  })

  it('should allow reuse after ttl expiration', async () => {
    const provider = inMemoryOAuthClientAssertionJtiStore()

    assert.equal(await provider.saveIfAbsent('client', 'jti', { ttlMs: -1 }), true)
    assert.equal(await provider.saveIfAbsent('client', 'jti'), true)
  })

  it('should remove expired jtis when saving a new one', async () => {
    const provider = inMemoryOAuthClientAssertionJtiStore()
    const dateNow = mock.method(Date, 'now')

    try {
      dateNow.mock.mockImplementation(() => 1_000)
      assert.equal(await provider.saveIfAbsent('client', 'expired-jti', { ttlMs: 100 }), true)

      dateNow.mock.mockImplementation(() => 1_200)
      assert.equal(await provider.saveIfAbsent('client', 'new-jti'), true)
      assert.equal(await provider.saveIfAbsent('client', 'expired-jti'), true)
    } finally {
      dateNow.mock.restore()
    }
  })
})
