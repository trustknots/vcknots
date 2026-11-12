import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { inMemoryVerifierStateStore } from '../../../src/providers/in-memory/in-memory-verifier-state-store.provider'

describe('inMemoryVerifierStateStore', () => {
  it('should have correct properties', () => {
    const provider = inMemoryVerifierStateStore()

    assert.equal(provider.kind, 'verifier-state-store-provider')
    assert.equal(provider.name, 'in-memory-verifier-state-store-provider')
    assert.equal(provider.single, true)
  })

  describe('reserve', () => {
    it('should reject a state that is already reserved or registered', async () => {
      const provider = inMemoryVerifierStateStore()

      assert.equal(await provider.reserve('state-1'), true)
      assert.equal(await provider.reserve('state-1'), false)

      assert.equal(await provider.register('state-1', 'tx-1'), true)
      assert.equal(await provider.reserve('state-1'), false)
    })

    it('should allow reuse after ttl expiration', async () => {
      const provider = inMemoryVerifierStateStore()

      assert.equal(await provider.reserve('state', { ttlMs: -1 }), true)
      assert.equal(await provider.reserve('state'), true)
    })
  })

  describe('register', () => {
    it('should bind a reserved or free state', async () => {
      const provider = inMemoryVerifierStateStore()

      assert.equal(await provider.reserve('reserved'), true)
      assert.equal(await provider.register('reserved', 'tx-1'), true)
      assert.equal(await provider.register('free', 'tx-2'), true)

      assert.equal(await provider.take('reserved'), 'tx-1')
      assert.equal(await provider.take('free'), 'tx-2')
    })

    it('should not overwrite an active binding', async () => {
      const provider = inMemoryVerifierStateStore()

      assert.equal(await provider.register('state', 'tx-1'), true)
      assert.equal(await provider.register('state', 'tx-2'), false)
      assert.equal(await provider.take('state'), 'tx-1')
    })

    it('should overwrite an expired binding', async () => {
      const provider = inMemoryVerifierStateStore()

      assert.equal(await provider.register('state', 'tx-1', { ttlMs: -1 }), true)
      assert.equal(await provider.register('state', 'tx-2'), true)
      assert.equal(await provider.take('state'), 'tx-2')
    })
  })

  describe('take', () => {
    it('should return the transaction id only once', async () => {
      const provider = inMemoryVerifierStateStore()

      await provider.register('state', 'tx-1')
      assert.equal(await provider.take('state'), 'tx-1')
      assert.equal(await provider.take('state'), null)
    })

    it('should return the transaction id to only one of concurrent calls', async () => {
      const provider = inMemoryVerifierStateStore()

      await provider.register('state', 'tx-1')
      const results = await Promise.all([provider.take('state'), provider.take('state')])

      assert.deepEqual(
        results.filter((result) => result !== null),
        ['tx-1']
      )
    })

    it('should return null for an unknown state', async () => {
      const provider = inMemoryVerifierStateStore()

      assert.equal(await provider.take('unknown'), null)
    })

    it('should neither return nor remove a reservation', async () => {
      const provider = inMemoryVerifierStateStore()

      await provider.reserve('state')
      assert.equal(await provider.take('state'), null)
      assert.equal(await provider.reserve('state'), false)
    })

    it('should return null for an expired binding', async () => {
      const provider = inMemoryVerifierStateStore()

      await provider.register('state', 'tx-1', { ttlMs: -1 })
      assert.equal(await provider.take('state'), null)
    })
  })

  describe('consume', () => {
    it('should remove a reservation and a binding', async () => {
      const provider = inMemoryVerifierStateStore()

      await provider.reserve('reserved')
      await provider.register('registered', 'tx-1')

      await provider.consume('reserved')
      await provider.consume('registered')

      assert.equal(await provider.reserve('reserved'), true)
      assert.equal(await provider.take('registered'), null)
    })
  })
})
