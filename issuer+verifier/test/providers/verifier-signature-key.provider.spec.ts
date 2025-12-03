import assert from 'node:assert/strict'
import { beforeEach, describe, it, mock } from 'node:test'
import { Jwk } from '../../src/jwk.type'
import { JwtPayload } from '../../src/jwt.types'
import { ProofJwtHeader } from '../../src/credential.types'
import { jwtVerify, importJWK, CryptoKey } from 'jose'
import type {
  VerifierSignatureKeyProvider,
  VerifierSignatureKeyStoreProvider,
} from '../../src/providers/provider.types'
import { verifierSignatureKey } from '../../src/providers/verifier-signature-key.provider'
import { ClientId } from '../../src'
import { WithProviderRegistry } from '../../src/providers/provider.registry'

describe('verifierSignatureKey Provider', () => {
  let provider: VerifierSignatureKeyProvider & WithProviderRegistry

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

  describe('sign', () => {
    let privateKey: Jwk
    let publicKey: Jwk
    let jwtPayload: JwtPayload
    const jwtHeader: ProofJwtHeader = {
      typ: 'openid4vci-proof+jwt',
      alg: 'ES256',
      kid: 'test-kid',
    }

    beforeEach(async () => {
      const keyPair = await provider.generate()
      privateKey = keyPair.privateKey
      publicKey = keyPair.publicKey

      const mockKeyStore: VerifierSignatureKeyStoreProvider = {
        kind: 'verifier-signature-key-store-provider',
        name: 'mock-verifier-signature-key-store-provider',
        single: true,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        async fetchPrivate(verifierId, _keyAlg): Promise<CryptoKey | null> {
          if (verifierId === 'test-verifier') {
            return (await importJWK(privateKey)) as CryptoKey
          }
          return null
        },
        save: mock.fn(),
        fetch: mock.fn(),
      }

      mock.method(provider.providers, 'get', (name: string) => {
        if (name === 'verifier-signature-key-store-provider') {
          return mockKeyStore
        }
        return undefined
      })

      const iat = Math.floor(Date.now() / 1000)
      jwtPayload = {
        iss: 'test-issuer',
        sub: 'test-subject',
        aud: 'test-audience',
        iat: iat,
        exp: iat + 3600,
      }
    })

    it('should sign a JWT payload and return a valid signature', async () => {
      const signature = await provider.sign(
        'test-verifier' as ClientId,
        'ES256',
        jwtPayload,
        jwtHeader
      )
      assert.ok(signature)
      assert.equal(typeof signature, 'string')

      // Reconstruct the JWS to verify the signature
      const protectedHeader = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')
      const protectedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url')
      const jws = `${protectedHeader}.${protectedPayload}.${signature}`

      const key = await importJWK(publicKey, 'ES256')
      const { payload } = await jwtVerify(jws, key)

      assert.deepStrictEqual(payload, jwtPayload)
    })

    it('should throw an error for invalid private key', async () => {
      await assert.rejects(
        () => provider.sign('invalid-verifier' as ClientId, 'ES256', jwtPayload, jwtHeader),
        (err: Error) => {
          assert.match(err.message, /sign error/)
          return true
        }
      )
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
