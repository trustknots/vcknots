import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { exportJWK, generateKeyPair, importJWK, jwtVerify } from 'jose'
import type { JWK } from 'jose'
import { ClientId } from '../../../src/client-id.types'
import { inMemoryVerifierSignatureKeyStore } from '../../../src/providers/in-memory/in-memory-verifier-signature-key-store.provider'
import { ProofJwtHeader } from '../../../src/credential.types'
import { JwtPayload } from '../../../src/jwt.types'
import type { SignatureKeyEntry } from '../../../src/signature-key.types'

describe('inMemoryVerifierSignatureKeyStore', () => {
  let store: ReturnType<typeof inMemoryVerifierSignatureKeyStore>
  const verifier = ClientId('https://verifier.example.com')
  let pair1: SignatureKeyEntry
  let pair2: SignatureKeyEntry

  beforeEach(async () => {
    store = inMemoryVerifierSignatureKeyStore()
    const keys1 = await generateKeyPair('ES256', { extractable: true })
    const pubKey1 = await exportJWK(keys1.publicKey)
    const privKey1 = await exportJWK(keys1.privateKey)
    pair1 = {
      format: 'jwk',
      declaredAlg: 'ES256',
      publicKey: { ...pubKey1, kid: 'kid1', alg: 'ES256' },
      privateKey: { ...privKey1, kid: 'kid1', alg: 'ES256' },
    }

    const keys2 = await generateKeyPair('ES384', { extractable: true })
    const pubKey2 = await exportJWK(keys2.publicKey)
    const privKey2 = await exportJWK(keys2.privateKey)
    pair2 = {
      format: 'jwk',
      declaredAlg: 'ES384',
      publicKey: { ...pubKey2, kid: 'kid2', alg: 'ES384' },
      privateKey: { ...privKey2, kid: 'kid2', alg: 'ES384' },
    }
  })

  it('should save and fetch key pairs for a verifier', async () => {
    await store.save(verifier, 'ES256', pair1)
    const fetched = await store.fetch(verifier, 'ES256')
    assert.ok(fetched)
    assert.equal(fetched.algorithm.name, 'ECDSA')
  })

  it('should append new key pairs with different alg', async () => {
    await store.save(verifier, 'ES256', pair1)
    await store.save(verifier, 'ES384', pair2)
    const fetched1 = await store.fetch(verifier, 'ES256')
    const fetched2 = await store.fetch(verifier, 'ES384')
    assert.ok(fetched1)
    assert.ok(fetched2)
  })

  it('should replace key pair with same alg', async () => {
    const keys1b = await generateKeyPair('ES256', { extractable: true })
    const pubKey1b = await exportJWK(keys1b.publicKey)
    const privKey1b = await exportJWK(keys1b.privateKey)
    const pair1b: SignatureKeyEntry = {
      ...pair1,
      publicKey: { ...pubKey1b, kid: 'kid1b', alg: 'ES256' },
      privateKey: { ...privKey1b, kid: 'kid1b', alg: 'ES256' },
    }

    await store.save(verifier, 'ES256', pair1)
    await store.save(verifier, 'ES256', pair1b)
    const fetched = await store.fetch(verifier, 'ES256')
    assert.ok(fetched)
  })

  it('should reject save when pair algorithm does not match keyAlg', async () => {
    await assert.rejects(store.save(verifier, 'ES256', pair2), (error: Error) => {
      assert.equal(error.name, 'ILLEGAL_ARGUMENT')
      assert.match(error.message, /does not match the requested key algorithm/)
      return true
    })
  })

  it('should return null if no key pairs saved', async () => {
    const fetched = await store.fetch(ClientId('https://unknown.example.com'), 'ES256')
    assert.strictEqual(fetched, null)
  })

  it('should sign a JWT payload and return a valid signature', async () => {
    await store.save(verifier, 'ES256', pair1)
    const jwtHeader: ProofJwtHeader = {
      typ: 'openid4vci-proof+jwt',
      alg: 'ES256',
      kid: 'kid1',
    }
    const iat = Math.floor(Date.now() / 1000)
    const jwtPayload: JwtPayload = {
      iss: 'test-issuer',
      sub: 'test-subject',
      aud: 'test-audience',
      iat,
      exp: iat + 3600,
    }

    const signature = await store.sign(verifier, 'ES256', jwtPayload, jwtHeader)

    assert.ok(signature)
    assert.equal(typeof signature, 'string')

    const protectedHeader = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')
    const protectedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url')
    const jws = `${protectedHeader}.${protectedPayload}.${signature}`

    assert.ok(pair1.publicKey && typeof pair1.publicKey !== 'string')
    const key = await importJWK(pair1.publicKey as JWK, 'ES256')
    const { payload } = await jwtVerify(jws, key)

    assert.deepStrictEqual(payload, jwtPayload)
  })

  it('should return null when verifier key pairs are not found', async () => {
    const jwtHeader: ProofJwtHeader = {
      typ: 'openid4vci-proof+jwt',
      alg: 'ES256',
      kid: 'kid1',
    }
    const iat = Math.floor(Date.now() / 1000)
    const jwtPayload: JwtPayload = {
      iss: 'test-issuer',
      sub: 'test-subject',
      aud: 'test-audience',
      iat,
      exp: iat + 3600,
    }

    const signature = await store.sign(
      ClientId('https://unknown.example.com'),
      'ES256',
      jwtPayload,
      jwtHeader
    )

    assert.strictEqual(signature, null)
  })
})
