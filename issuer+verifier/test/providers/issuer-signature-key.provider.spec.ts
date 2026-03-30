import assert from 'node:assert/strict'
import { describe, it, beforeEach } from 'node:test'
import { issuerSignatureKey } from '../../src/providers/issuer-signature-key.provider'
import { IssuerSignatureKeyProvider } from '../../src/providers/provider.types'

describe('issuerSignatureKey', () => {
  let provider: IssuerSignatureKeyProvider

  beforeEach(() => {
    provider = issuerSignatureKey()
  })

  it('should have correct kind, name, and single properties', () => {
    assert.equal(provider.kind, 'issuer-signature-key-provider')
    assert.equal(provider.name, 'default-issuer-signature-key-provider')
    assert.strictEqual(provider.single, false)
  })

  describe('generate', () => {
    it('should generate an ES256 key pair by default', async () => {
      const { publicKey, privateKey } = await provider.generate()

      assert.ok(publicKey)
      assert.ok(privateKey)
      assert.equal(publicKey.alg, 'ES256')
      assert.equal(privateKey.alg, 'ES256')
      assert.equal(publicKey.kty, 'EC')
      assert.equal(publicKey.crv, 'P-256')
    })

    it('should generate a key pair with the specified algorithm', async () => {
      const es384Provider = issuerSignatureKey({ alg: 'ES384' })
      const { publicKey, privateKey } = await es384Provider.generate()

      assert.ok(publicKey)
      assert.ok(privateKey)
      assert.equal(publicKey.alg, 'ES384')
      assert.equal(privateKey.alg, 'ES384')
      assert.equal(publicKey.kty, 'EC')
      assert.equal(publicKey.crv, 'P-384')
    })
  })

  describe('canHandle', () => {
    it('should return true for the configured algorithm', () => {
      assert.strictEqual(provider.canHandle('ES256'), true)
    })

    it('should return false for other algorithms', () => {
      assert.strictEqual(provider.canHandle('RS256'), false)
      assert.strictEqual(provider.canHandle('ES384'), false)
    })

    it('should handle custom algorithm correctly', () => {
      const es384Provider = issuerSignatureKey({ alg: 'ES384' })
      assert.strictEqual(es384Provider.canHandle('ES384'), true)
      assert.strictEqual(es384Provider.canHandle('ES256'), false)
    })
  })
})
