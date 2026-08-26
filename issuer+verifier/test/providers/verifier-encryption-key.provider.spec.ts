import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import type { VerifierEncryptionKeyProvider } from '../../src/providers/provider.types'
import { verifierEncryptionKey } from '../../src/providers/verifier-encryption-key.provider'

describe('verifierEncryptionKey Provider', () => {
  let provider: VerifierEncryptionKeyProvider

  beforeEach(() => {
    provider = verifierEncryptionKey()
  })

  describe('generate', () => {
    it('should generate a valid RSA-OAEP-256 key pair', async () => {
      const { publicKey, privateKey } = await provider.generate()
      assert.ok(publicKey, 'Public JWK should exist')
      assert.ok(privateKey, 'Private JWK should exist')
      assert.equal(publicKey.kty, 'RSA', 'Public JWK kty should be RSA')
      assert.equal(privateKey.kty, 'RSA', 'Private JWK kty should be RSA')
      assert.ok(publicKey.n, 'Public JWK should have modulus n')
      assert.ok(publicKey.e, 'Public JWK should have exponent e')
      assert.ok(privateKey.d, 'Private key should have d component')
      assert.ok(publicKey.kid, 'Public key should have kid')
      assert.equal(publicKey.alg, 'RSA-OAEP-256')
      assert.equal(publicKey.use, 'enc')
      assert.equal(privateKey.alg, 'RSA-OAEP-256')
    })
  })

  describe('canHandle', () => {
    it('should return true for RSA-OAEP-256 algorithm', () => {
      assert.strictEqual(provider.canHandle('RSA-OAEP-256'), true)
    })

    it('should return false for other algorithms', () => {
      assert.strictEqual(provider.canHandle('ES256'), false)
      assert.strictEqual(provider.canHandle('RS256'), false)
      assert.strictEqual(provider.canHandle(''), false)
    })
  })
})
