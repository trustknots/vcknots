import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { nonce } from '../../src/providers/nonce.provider'
import { NonceProvider } from '../../src/providers/provider.types'

describe('NonceProvider', () => {
  const provider: NonceProvider = nonce()

  it('should be a NonceProvider', () => {
    assert.ok(provider, 'Provider instance should be created')
    assert.equal(typeof provider.generate, 'function', 'Provider should have a generate function')
  })

  it('should have correct kind, name, and single properties', () => {
    assert.equal(provider.kind, 'nonce-provider', "Kind should be 'nonce-provider'")
    assert.equal(
      provider.name,
      'default-nonce-provider',
      "Name should be 'default-nonce-provider'"
    )
    assert.strictEqual(provider.single, true, 'Single should be true')
  })

  describe('generate()', () => {
    it('should generate a Nonce string', async () => {
      const generatedNonce = await provider.generate()
      assert.ok(typeof generatedNonce === 'string', 'Generated nonce should be a string')
      assert.equal(generatedNonce.length, 32, 'Generated nonce should have 32 characters')
    })

    it('should generate different nonces on subsequent calls', () => {
      const noncePromise1 = provider.generate()
      const noncePromise2 = provider.generate()
      assert.notEqual(
        noncePromise1,
        noncePromise2,
        'Generated nonces should be different to ensure randomness'
      )
    })

    it('should generate a Nonce containing only hexadecimal characters', async () => {
      const generatedNonce = await provider.generate()
      // Regular expression to check for 32 hexadecimal characters
      const hexRegex = /^[0-9a-fA-F]{32}$/
      assert.ok(
        hexRegex.test(generatedNonce),
        'Generated nonce should consist of 32 hexadecimal characters'
      )
    })
  })
})
