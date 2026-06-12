import assert from 'node:assert/strict'
import { afterEach, beforeEach, describe, it, mock } from 'node:test'
import { inMemoryAllowedCredentialConfigurationStore } from '../../../src/providers/in-memory/in-memory-allowed-credential-configuration-store.provider'
import { CredentialConfigurationId } from '../../../src/credential-issuer.types'

describe('inMemoryAllowedCredentialConfigurationStore', () => {
  let provider: ReturnType<typeof inMemoryAllowedCredentialConfigurationStore>

  const configurations: CredentialConfigurationId[] = [
    CredentialConfigurationId('University_Degree'),
  ]
  const updatedConfigurations: CredentialConfigurationId[] = [
    CredentialConfigurationId('EmployeeID_JWT'),
  ]

  beforeEach(() => {
    provider = inMemoryAllowedCredentialConfigurationStore()
  })

  afterEach(() => {
    mock.timers.reset()
  })
  it('should have kind, name, and single properties correctly set', () => {
    assert.strictEqual(provider.kind, 'allowed-credential-configuration-store-provider')
    assert.strictEqual(provider.name, 'in-memory-allowed-credential-configuration-store-provider')
    assert.strictEqual(provider.single, true)
  })
  describe('save and fetch', () => {
    it('should return null when fetching an unknown access token hash', async () => {
      const fetched = await provider.fetch('unknown-access-token-hash')
      assert.strictEqual(fetched, null)
    })

    it('should save and fetch credential configuration ids', async () => {
      await provider.save('test-access-token-hash', configurations)

      const fetched = await provider.fetch('test-access-token-hash')

      assert.deepStrictEqual(fetched, configurations)
    })

    it('should overwrite existing context when saving with the same access token hash', async () => {
      await provider.save('test-access-token-hash', configurations)
      await provider.save('test-access-token-hash', updatedConfigurations)

      const fetched = await provider.fetch('test-access-token-hash')

      assert.deepStrictEqual(fetched, updatedConfigurations)
    })

    it('should save independently for multiple access token hashes', async () => {
      await provider.save('access-token-hash-1', configurations)
      await provider.save('access-token-hash-2', updatedConfigurations)

      assert.deepStrictEqual(await provider.fetch('access-token-hash-1'), configurations)
      assert.deepStrictEqual(await provider.fetch('access-token-hash-2'), updatedConfigurations)
    })
  })

  describe('delete', () => {
    it('should delete an existing context', async () => {
      await provider.save('test-access-token-hash', configurations)

      await provider.delete('test-access-token-hash')

      const fetched = await provider.fetch('test-access-token-hash')
      assert.strictEqual(fetched, null)
    })

    it('should only delete the specified access token hash', async () => {
      await provider.save('access-token-hash-1', configurations)
      await provider.save('access-token-hash-2', updatedConfigurations)

      await provider.delete('access-token-hash-1')

      assert.strictEqual(await provider.fetch('access-token-hash-1'), null)
      assert.deepStrictEqual(await provider.fetch('access-token-hash-2'), updatedConfigurations)
    })
  })

  describe('ttl', () => {
    it('should expire the context after the specified ttl', async () => {
      mock.timers.enable({ apis: ['Date'] })

      await provider.save('test-access-token-hash', configurations, 1)

      mock.timers.tick(500)
      assert.deepStrictEqual(await provider.fetch('test-access-token-hash'), configurations)

      mock.timers.tick(600)
      assert.strictEqual(await provider.fetch('test-access-token-hash'), null)
    })

    it('should remove expired context on fetch', async () => {
      mock.timers.enable({ apis: ['Date'] })

      await provider.save('test-access-token-hash', configurations, 1)

      mock.timers.tick(1_100)
      assert.strictEqual(await provider.fetch('test-access-token-hash'), null)
      assert.strictEqual(await provider.fetch('test-access-token-hash'), null)
    })

    it('should use default ttl when ttl is not specified', async () => {
      mock.timers.enable({ apis: ['Date'] })

      await provider.save('test-access-token-hash', configurations)

      mock.timers.tick(299_000)
      assert.deepStrictEqual(await provider.fetch('test-access-token-hash'), configurations)

      mock.timers.tick(2_000)
      assert.strictEqual(await provider.fetch('test-access-token-hash'), null)
    })
  })
})
