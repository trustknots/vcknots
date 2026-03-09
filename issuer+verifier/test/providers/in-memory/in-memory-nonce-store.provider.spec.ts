import assert from 'node:assert'
import { beforeEach, describe, it, test } from 'node:test'
import { Nonce } from '../../../src/nonce.types'
import { NonceStoreProvider } from '../../../src/providers'
import { inMemoryNonceStore } from '../../../src/providers/in-memory/in-memory-nonce-store.provider'

describe('inMemoryNonceStore', () => {
  let nonceStoreProvider: NonceStoreProvider
  const testNonce = Nonce('test-nonce-value')

  describe('When initialized with no options (default behavior)', () => {
    beforeEach(() => {
      nonceStoreProvider = inMemoryNonceStore()
    })

    it('should have correct kind, name, and single properties', () => {
      assert.strictEqual(nonceStoreProvider.kind, 'nonce-store-provider')
      assert.strictEqual(nonceStoreProvider.name, 'in-memory-nonce-provider')
      assert.strictEqual(nonceStoreProvider.single, true)
    })

    it('save should store the cnonce, making it valid immediately', async () => {
      await nonceStoreProvider.save(testNonce)
      const isValid = await nonceStoreProvider.validate(testNonce)
      assert.strictEqual(isValid, true, 'Cnonce should be valid after saving')
    })

    it('validate should return false for a non-existent cnonce', async () => {
      const isValid = await nonceStoreProvider.validate(Nonce('non-existent-cnonce'))
      assert.strictEqual(isValid, false)
    })

    it('revoke should remove the cnonce, making it invalid', async () => {
      await nonceStoreProvider.save(testNonce)
      await nonceStoreProvider.revoke(testNonce)
      const isValid = await nonceStoreProvider.validate(testNonce)
      assert.strictEqual(isValid, false, 'Cnonce should be invalid after revoking')
    })

    it('revoke should not throw for a non-existent cnonce', async () => {
      await assert.doesNotThrow(async () => {
        await nonceStoreProvider.revoke(Nonce('non-existent-cnonce'))
      })
    })

    it('validate should return true for a cnonce before its default expiration time (using mocked time)', async () => {
      const oneMinuteInMs = 1 * 60 * 1000
      const mocks = test.mock.timers
      mocks.enable()
      await nonceStoreProvider.save(testNonce)
      try {
        mocks.tick(oneMinuteInMs)
        const isValid = await nonceStoreProvider.validate(testNonce)
        assert.strictEqual(isValid, true, 'Cnonce should be valid before default expiry time')
      } finally {
        mocks.reset()
      }
    })

    it('validate should return false for an expired cnonce after default expiration (using mocked time)', async () => {
      const fiveMinutesInMs = 5 * 60 * 1000
      const mocks = test.mock.timers
      mocks.enable()
      await nonceStoreProvider.save(testNonce)
      try {
        mocks.tick(fiveMinutesInMs + 1000)
        const isValid = await nonceStoreProvider.validate(testNonce)
        assert.strictEqual(isValid, false, 'Cnonce should be invalid after default expiry time')
      } finally {
        mocks.reset()
      }
    })
  })

  describe('When initialized with custom expiration option', () => {
    const testExpiryMs = 3 * 60 * 1000
    beforeEach(() => {
      nonceStoreProvider = inMemoryNonceStore({ c_nonce_expire_in: testExpiryMs })
    })

    it('save should store the cnonce with custom expiration, valid immediately', async () => {
      await nonceStoreProvider.save(testNonce)
      const isValid = await nonceStoreProvider.validate(testNonce)
      assert.strictEqual(
        isValid,
        true,
        'Cnonce should be valid immediately after saving with custom expiry'
      )
    })

    it('validate should return true for a cnonce before its options expiration time (using mocked time)', async () => {
      const oneMinuteInMs = 1 * 60 * 1000
      const mocks = test.mock.timers
      mocks.enable()
      await nonceStoreProvider.save(testNonce)
      try {
        mocks.tick(oneMinuteInMs)
        const isValid = await nonceStoreProvider.validate(testNonce)
        assert.strictEqual(isValid, true, 'Cnonce should be valid before default expiry time')
      } finally {
        mocks.reset()
      }
    })

    it('validate should return false for an expired cnonce after options expiration (using mocked time)', async () => {
      const fiveMinutesInMs = 5 * 60 * 1000
      const mocks = test.mock.timers
      mocks.enable()
      await nonceStoreProvider.save(testNonce)
      try {
        mocks.tick(fiveMinutesInMs)
        const isValid = await nonceStoreProvider.validate(testNonce)
        assert.strictEqual(isValid, false, 'Cnonce should be invalid after default expiry time')
      } finally {
        mocks.reset()
      }
    })
  })

  describe('Method return types', () => {
    beforeEach(() => {
      nonceStoreProvider = inMemoryNonceStore()
    })

    it('save method should return a Promise that resolves to undefined', async () => {
      const result = await nonceStoreProvider.save(Nonce('some-cnonce-for-return-test'))
      assert.strictEqual(result, undefined)
    })

    it('revoke method should return a Promise that resolves to undefined', async () => {
      const cnonceToRevoke = Nonce('another-cnonce-for-return-test')
      await nonceStoreProvider.save(cnonceToRevoke)
      const result = await nonceStoreProvider.revoke(cnonceToRevoke)
      assert.strictEqual(result, undefined)
    })
  })
})
