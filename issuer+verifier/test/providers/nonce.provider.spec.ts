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
    it('should generate a Nonce with nonce and default nonce_expires_in (5 min)', async () => {
      const generatedNonce = await provider.generate()
      assert.ok(typeof generatedNonce.nonce === 'string', 'Generated nonce should have nonce string')
      assert.equal(generatedNonce.nonce.length, 32, 'Generated nonce should have 32 characters')
      assert.strictEqual(
        generatedNonce.nonce_expires_in,
        60 * 5 * 1000,
        'Should have default nonce_expires_in (5 minutes)'
      )
    })

    it('should set nonce_expires_in when options are passed', async () => {
      const generatedNonce = await provider.generate({ nonce_expires_in: 120000 })
      assert.strictEqual(generatedNonce.nonce_expires_in, 120000)
    })

    it('should generate different nonces on subsequent calls', async () => {
      const nonce1 = await provider.generate()
      const nonce2 = await provider.generate()
      assert.notEqual(
        nonce1.nonce,
        nonce2.nonce,
        'Generated nonces should be different to ensure randomness'
      )
    })

    it('should generate a Nonce containing only hexadecimal characters', async () => {
      const generatedNonce = await provider.generate()
      const hexRegex = /^[0-9a-fA-F]{32}$/
      assert.ok(
        hexRegex.test(generatedNonce.nonce),
        'Generated nonce should consist of 32 hexadecimal characters'
      )
    })
  })
})
