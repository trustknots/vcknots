import assert from 'node:assert/strict'
import { describe, it, mock } from 'node:test'
import { inMemoryDpopProofJtiStore } from '../../src/providers/in-memory/in-memory-dpop-proof-jti-store.provider'

describe('InMemoryDpopProofJtiStoreProvider', () => {
  it('should have correct properties', () => {
    const provider = inMemoryDpopProofJtiStore()

    assert.equal(provider.kind, 'dpop-proof-jti-store-provider')
    assert.equal(provider.name, 'in-memory-dpop-proof-jti-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save a jti only when it has not been used for the same jwk thumbprint', async () => {
    const provider = inMemoryDpopProofJtiStore()

    assert.equal(await provider.saveIfAbsent('thumbprint-1', 'jti-1'), true)
    assert.equal(await provider.saveIfAbsent('thumbprint-1', 'jti-1'), false)
    assert.equal(await provider.saveIfAbsent('thumbprint-2', 'jti-1'), true)
    assert.equal(await provider.saveIfAbsent('thumbprint-1', 'jti-2'), true)
  })

  it('should allow reuse after ttl expiration', async () => {
    const provider = inMemoryDpopProofJtiStore()

    assert.equal(await provider.saveIfAbsent('thumbprint', 'jti', { ttlMs: -1 }), true)
    assert.equal(await provider.saveIfAbsent('thumbprint', 'jti'), true)
  })

  it('should remove expired jtis when saving a new one', async () => {
    const provider = inMemoryDpopProofJtiStore()
    const dateNow = mock.method(Date, 'now')

    try {
      dateNow.mock.mockImplementation(() => 1_000)
      assert.equal(await provider.saveIfAbsent('thumbprint', 'expired-jti', { ttlMs: 100 }), true)

      dateNow.mock.mockImplementation(() => 1_200)
      assert.equal(await provider.saveIfAbsent('thumbprint', 'new-jti'), true)
      assert.equal(await provider.saveIfAbsent('thumbprint', 'expired-jti'), true)
    } finally {
      dateNow.mock.restore()
    }
  })
})
