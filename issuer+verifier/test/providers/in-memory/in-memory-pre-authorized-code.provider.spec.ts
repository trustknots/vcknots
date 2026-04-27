import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { PreAuthorizedCode } from '../../../src/pre-authorized-code.types'
import { inMemoryPreAuthorizedCodeStore } from '../../../src/providers/in-memory/in-memory-pre-authorized-code-store.provider'
import { CredentialConfigurationId } from '../../../src'

describe('inMemoryPreAuthorizedCode', () => {
  let provider: ReturnType<typeof inMemoryPreAuthorizedCodeStore>
  const sampleCode: PreAuthorizedCode = PreAuthorizedCode('test_code_123_abc')
  const anotherSampleCode: PreAuthorizedCode = PreAuthorizedCode('another_code_456_def')
  const credentialConfigurationIds = [CredentialConfigurationId('UniversityDegreeCredential')]

  beforeEach(() => {
    provider = inMemoryPreAuthorizedCodeStore()
  })

  it('should have kind, name, and single properties correctly set', () => {
    assert.strictEqual(provider.kind, 'pre-authorized-code-store-provider')
    assert.strictEqual(provider.name, 'in-memory-pre-authorized-code-provider')
    assert.strictEqual(provider.single, true)
  })

  describe('save and validate', () => {
    it('should save a pre-authorized code and validate it successfully', async () => {
      await provider.save(sampleCode, credentialConfigurationIds)
      const isValid = await provider.validate(sampleCode)
      assert.strictEqual(isValid, credentialConfigurationIds)
    })

    it('should return null when validating a non-existent code', async () => {
      const isValid = await provider.validate(sampleCode) // sampleCode is not saved yet
      assert.strictEqual(isValid, null)
    })

    it('should keep different credential configuration ids per code', async () => {
      const configA = [CredentialConfigurationId('UniversityDegreeCredential')]
      const configB = [CredentialConfigurationId('StudentCardCredential')]

      await provider.save(sampleCode, configA)
      await provider.save(anotherSampleCode, configB)

      assert.deepStrictEqual(await provider.validate(sampleCode), configA)
      assert.deepStrictEqual(await provider.validate(anotherSampleCode), configB)
    })

    it('should overwrite credential configuration ids when saving the same code twice', async () => {
      const initialConfig = [CredentialConfigurationId('UniversityDegreeCredential')]
      const updatedConfig = [CredentialConfigurationId('StudentCardCredential')]

      await provider.save(sampleCode, initialConfig)
      await provider.save(sampleCode, updatedConfig)

      assert.deepStrictEqual(await provider.validate(sampleCode), updatedConfig)
    })

    it('should handle multiple codes correctly', async () => {
      await provider.save(sampleCode, credentialConfigurationIds)
      await provider.save(anotherSampleCode, credentialConfigurationIds)

      assert.strictEqual(await provider.validate(sampleCode), credentialConfigurationIds)
      assert.strictEqual(await provider.validate(anotherSampleCode), credentialConfigurationIds)
    })
  })

  describe('delete', () => {
    it('should delete a pre-authorized code, and it should no longer validate', async () => {
      await provider.save(sampleCode, credentialConfigurationIds)
      assert.strictEqual(await provider.validate(sampleCode), credentialConfigurationIds)

      await provider.delete(sampleCode)
      assert.strictEqual(await provider.validate(sampleCode), null)
    })

    it('should not throw an error when trying to delete a non-existent code', async () => {
      await assert.doesNotReject(provider.delete(sampleCode))
    })

    it('should only delete the specified code', async () => {
      await provider.save(sampleCode, credentialConfigurationIds)
      await provider.save(anotherSampleCode, credentialConfigurationIds)

      await provider.delete(sampleCode)

      assert.strictEqual(await provider.validate(sampleCode), null)
      assert.strictEqual(await provider.validate(anotherSampleCode), credentialConfigurationIds)
    })
  })

  describe('edge cases', () => {
    it('validate should return null when the store is empty', async () => {
      const isValid = await provider.validate(sampleCode)
      assert.strictEqual(isValid, null)
    })

    it('save should not return a value (void promise)', async () => {
      const result = await provider.save(sampleCode, credentialConfigurationIds)
      assert.strictEqual(result, undefined)
    })

    it('delete should not return a value (void promise)', async () => {
      await provider.save(sampleCode, credentialConfigurationIds)
      const result = await provider.delete(sampleCode)
      assert.strictEqual(result, undefined)
    })
  })
})
