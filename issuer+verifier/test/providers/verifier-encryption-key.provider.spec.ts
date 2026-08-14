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
    it('should generate a valid ECDH-ES key pair', async () => {
      const { publicKey, privateKey } = await provider.generate()
      assert.ok(publicKey, 'Public JWK should exist')
      assert.ok(privateKey, 'Private JWK should exist')
      assert.equal(publicKey.kty, 'EC', 'Public JWK kty should be EC')
      assert.equal(privateKey.kty, 'EC', 'Private JWK kty should be EC')
      assert.equal(publicKey.crv, 'P-256', 'Public JWK crv should be P-256')
      assert.equal(privateKey.crv, 'P-256', 'Private JWK crv should be P-256')
      assert.ok(publicKey.x, 'Public key should have x coordinate')
      assert.ok(publicKey.y, 'Public key should have y coordinate')
      assert.ok(privateKey.d, 'Private key should have d component')
      assert.ok(publicKey.kid, 'Public key should have kid')
      assert.equal(publicKey.alg, 'ECDH-ES')
      assert.equal(publicKey.use, 'enc')
      assert.equal(privateKey.alg, 'ECDH-ES')
    })
  })

  describe('canHandle', () => {
    it('should return true for ECDH-ES algorithm', () => {
      assert.strictEqual(provider.canHandle('ECDH-ES'), true)
    })

    it('should return false for other algorithms', () => {
      assert.strictEqual(provider.canHandle('ES256'), false)
      assert.strictEqual(provider.canHandle('RS256'), false)
      assert.strictEqual(provider.canHandle(''), false)
    })
  })
})
