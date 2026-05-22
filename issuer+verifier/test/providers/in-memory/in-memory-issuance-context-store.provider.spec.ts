import assert from 'node:assert/strict'
import { afterEach, beforeEach, describe, it, mock } from 'node:test'
import { inMemoryIssuanceContextStore } from '../../../src/providers/in-memory/in-memory-issuance-context-store.provider'
import { CredentialConfigurationId } from '../../../src/credential-issuer.types'

describe('inMemoryIssuanceContextStore', () => {
  let provider: ReturnType<typeof inMemoryIssuanceContextStore>

  const configurations: CredentialConfigurationId[] = [
    CredentialConfigurationId('University_Degree'),
  ]
  const updatedConfigurations: CredentialConfigurationId[] = [
    CredentialConfigurationId('EmployeeID_JWT'),
  ]

  beforeEach(() => {
    provider = inMemoryIssuanceContextStore()
  })

  afterEach(() => {
    mock.timers.reset()
  })
  it('should have kind, name, and single properties correctly set', () => {
    assert.strictEqual(provider.kind, 'issuance-context-store-provider')
    assert.strictEqual(provider.name, 'in-memory-issuance-context-store-provider')
    assert.strictEqual(provider.single, true)
  })
  describe('save and fetch', () => {
    it('should return null when fetching unknown jti', async () => {
      const fetched = await provider.fetch('unknown-jti')
      assert.strictEqual(fetched, null)
    })

    it('should save and fetch credential configuration ids', async () => {
      await provider.save('test-jti', configurations)

      const fetched = await provider.fetch('test-jti')

      assert.deepStrictEqual(fetched, configurations)
    })

    it('should overwrite existing context when saving with the same jti', async () => {
      await provider.save('test-jti', configurations)
      await provider.save('test-jti', updatedConfigurations)

      const fetched = await provider.fetch('test-jti')

      assert.deepStrictEqual(fetched, updatedConfigurations)
    })

    it('should save independently for multiple jtis', async () => {
      await provider.save('jti-1', configurations)
      await provider.save('jti-2', updatedConfigurations)

      assert.deepStrictEqual(await provider.fetch('jti-1'), configurations)
      assert.deepStrictEqual(await provider.fetch('jti-2'), updatedConfigurations)
    })
  })

  describe('delete', () => {
    it('should delete an existing context', async () => {
      await provider.save('test-jti', configurations)

      await provider.delete('test-jti')

      const fetched = await provider.fetch('test-jti')
      assert.strictEqual(fetched, null)
    })

    it('should only delete the specified jti', async () => {
      await provider.save('jti-1', configurations)
      await provider.save('jti-2', updatedConfigurations)

      await provider.delete('jti-1')

      assert.strictEqual(await provider.fetch('jti-1'), null)
      assert.deepStrictEqual(await provider.fetch('jti-2'), updatedConfigurations)
    })
  })

  describe('ttl', () => {
    it('should expire the context after the specified ttl', async () => {
      mock.timers.enable({ apis: ['Date'] })

      await provider.save('test-jti', configurations, 1)

      mock.timers.tick(500)
      assert.deepStrictEqual(await provider.fetch('test-jti'), configurations)

      mock.timers.tick(600)
      assert.strictEqual(await provider.fetch('test-jti'), null)
    })

    it('should remove expired context on fetch', async () => {
      mock.timers.enable({ apis: ['Date'] })

      await provider.save('test-jti', configurations, 1)

      mock.timers.tick(1_100)
      assert.strictEqual(await provider.fetch('test-jti'), null)
      assert.strictEqual(await provider.fetch('test-jti'), null)
    })

    it('should use default ttl when ttl is not specified', async () => {
      mock.timers.enable({ apis: ['Date'] })

      await provider.save('test-jti', configurations)

      mock.timers.tick(299_000)
      assert.deepStrictEqual(await provider.fetch('test-jti'), configurations)

      mock.timers.tick(2_000)
      assert.strictEqual(await provider.fetch('test-jti'), null)
    })
  })
})
