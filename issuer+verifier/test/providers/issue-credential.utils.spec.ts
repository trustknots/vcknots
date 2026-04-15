import { strict as assert } from 'node:assert'
import { describe, it } from 'node:test'
import {
  assertSafePath,
  getClaimValue,
  isPlainObject,
  setClaimValue,
} from '../../src/providers/issue-credential.utils'

describe('issueCredential utils', () => {
  describe('isPlainObject', () => {
    it('returns true for plain objects', () => {
      assert.equal(isPlainObject({ claim: 'value' }), true)
    })

    it('returns false for arrays and nullish values', () => {
      assert.equal(isPlainObject(['value']), false)
      assert.equal(isPlainObject(null), false)
      assert.equal(isPlainObject(undefined), false)
    })
  })

  describe('assertSafePath', () => {
    it('accepts non-empty safe paths', () => {
      assert.doesNotThrow(() => assertSafePath(['credentialSubject', 'name']))
    })

    it('rejects empty paths at runtime', () => {
      assert.throws(
        () => assertSafePath([]),
        (err: unknown) => {
          assert.equal((err as { name?: string }).name, 'INVALID_CLAIMS')
          assert.match(String((err as { message?: string }).message), /must not be empty/i)
          return true
        }
      )
    })

    it('rejects forbidden path segments', () => {
      assert.throws(
        () => assertSafePath(['credentialSubject', '__proto__']),
        (err: unknown) => {
          assert.equal((err as { name?: string }).name, 'INVALID_CLAIMS')
          assert.match(
            String((err as { message?: string }).message),
            /Unsupported claim path segment/
          )
          return true
        }
      )
    })
  })

  describe('getClaimValue', () => {
    it('returns nested values for valid paths', () => {
      const claims = { credentialSubject: { name: 'Alice' } }
      assert.equal(getClaimValue(claims, ['credentialSubject', 'name']), 'Alice')
    })

    it('returns undefined when the path is missing', () => {
      const claims = { credentialSubject: { name: 'Alice' } }
      assert.equal(getClaimValue(claims, ['credentialSubject', 'age']), undefined)
    })
  })

  describe('setClaimValue', () => {
    it('sets nested values on an empty target', () => {
      const target: Record<string, unknown> = {}
      setClaimValue(target, ['credentialSubject', 'name'], 'Alice')
      assert.deepEqual(target, { credentialSubject: { name: 'Alice' } })
    })

    it('replaces non-object intermediate values with objects', () => {
      const target: Record<string, unknown> = { credentialSubject: 'invalid' }
      setClaimValue(target, ['credentialSubject', 'name'], 'Alice')
      assert.deepEqual(target, { credentialSubject: { name: 'Alice' } })
    })

    it('rejects empty paths at runtime', () => {
      assert.throws(
        () => setClaimValue({}, [], 'Alice'),
        (err: unknown) => {
          assert.equal((err as { name?: string }).name, 'INVALID_CLAIMS')
          assert.match(String((err as { message?: string }).message), /must not be empty/i)
          return true
        }
      )
    })
  })
})
