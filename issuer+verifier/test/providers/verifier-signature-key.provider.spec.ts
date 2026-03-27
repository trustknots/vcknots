import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import type { VerifierSignatureKeyProvider } from '../../src/providers/provider.types'
import { verifierSignatureKey } from '../../src/providers/verifier-signature-key.provider'

describe('verifierSignatureKey Provider', () => {
  let provider: VerifierSignatureKeyProvider

  beforeEach(() => {
    provider = verifierSignatureKey()
  })

  describe('generate', () => {
    it('should generate a valid ES256 key pair', async () => {
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
    })
  })

  describe('canHandle', () => {
    it('should return true for ES256 algorithm', () => {
      assert.strictEqual(provider.canHandle('ES256'), true)
    })

    it('should return false for other algorithms', () => {
      assert.strictEqual(provider.canHandle('RS256'), false)
      assert.strictEqual(provider.canHandle('PS256'), false)
      assert.strictEqual(provider.canHandle(''), false)
    })
  })

  describe('verifierSignatureKey Provider with custom alg (not default value ES256)', () => {
    let provider: VerifierSignatureKeyProvider

    beforeEach(() => {
      provider = verifierSignatureKey({ alg: 'ES384' })
    })

    describe('generate', () => {
      it('should generate a valid ES384 key pair', async () => {
        const { publicKey, privateKey } = await provider.generate()
        assert.ok(publicKey, 'Public JWK should exist')
        assert.ok(privateKey, 'Private JWK should exist')
        assert.equal(publicKey.kty, 'EC', 'Public JWK kty should be EC')
        assert.equal(privateKey.kty, 'EC', 'Private JWK kty should be EC')
        assert.equal(publicKey.crv, 'P-384', 'Public JWK crv should be P-384')
        assert.equal(privateKey.crv, 'P-384', 'Private JWK crv should be P-384')
      })
    })

    describe('canHandle', () => {
      it('should return true for ES384 algorithm', () => {
        assert.strictEqual(provider.canHandle('ES384'), true)
      })

      it('should return false for other algorithms', () => {
        assert.strictEqual(provider.canHandle('ES256'), false)
      })
    })
  })
})
