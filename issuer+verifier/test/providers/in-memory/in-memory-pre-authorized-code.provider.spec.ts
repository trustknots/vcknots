import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { PreAuthorizedCode } from '../../../src/pre-authorized-code.types'
import { inMemoryPreAuthorizedCodeStore } from '../../../src/providers/in-memory/in-memory-pre-authorized-code-store.provider'

describe('inMemoryPreAuthorizedCode', () => {
  let provider: ReturnType<typeof inMemoryPreAuthorizedCodeStore>
  const sampleCode: PreAuthorizedCode = PreAuthorizedCode('test_code_123_abc')
  const anotherSampleCode: PreAuthorizedCode = PreAuthorizedCode('another_code_456_def')

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
      await provider.save(sampleCode)
      const isValid = await provider.validate(sampleCode)
      assert.strictEqual(isValid, true)
    })

    it('should return false when validating a non-existent code', async () => {
      const isValid = await provider.validate(sampleCode) // sampleCode is not saved yet
      assert.strictEqual(isValid, false)
    })

    it('should handle multiple codes correctly', async () => {
      await provider.save(sampleCode)
      await provider.save(anotherSampleCode)

      assert.strictEqual(await provider.validate(sampleCode), true)
      assert.strictEqual(await provider.validate(anotherSampleCode), true)
    })
  })

  describe('delete', () => {
    it('should delete a pre-authorized code, and it should no longer validate', async () => {
      await provider.save(sampleCode)
      assert.strictEqual(await provider.validate(sampleCode), true)

      await provider.delete(sampleCode)
      assert.strictEqual(await provider.validate(sampleCode), false)
    })

    it('should not throw an error when trying to delete a non-existent code', async () => {
      await assert.doesNotReject(provider.delete(sampleCode))
    })

    it('should only delete the specified code', async () => {
      await provider.save(sampleCode)
      await provider.save(anotherSampleCode)

      await provider.delete(sampleCode)

      assert.strictEqual(await provider.validate(sampleCode), false)
      assert.strictEqual(await provider.validate(anotherSampleCode), true)
    })
  })

  describe('edge cases', () => {
    it('validate should return false when the store is empty', async () => {
      const isValid = await provider.validate(sampleCode)
      assert.strictEqual(isValid, false)
    })

    it('save should not return a value (void promise)', async () => {
      const result = await provider.save(sampleCode)
      assert.strictEqual(result, undefined)
    })

    it('delete should not return a value (void promise)', async () => {
      await provider.save(sampleCode)
      const result = await provider.delete(sampleCode)
      assert.strictEqual(result, undefined)
    })
  })
})
