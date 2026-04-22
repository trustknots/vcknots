import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { jwtVerify } from 'jose'
import { AuthorizationServerIssuer } from '../../../src/authorization-server.types'
import { JwtPayload } from '../../../src/jwt.types'
import { authzSignatureKey } from '../../../src/providers/authz-signature-key.provider'
import { inMemoryAuthzSignatureKeyStore } from '../../../src/providers/in-memory/in-memory-authz-signature-key-store.provider'
import { SignatureKeyEntry } from '../../../src/signature-key.types'

type InMemoryAuthzKeyProvider = ReturnType<typeof inMemoryAuthzSignatureKeyStore>

describe('InMemoryAuthzKeyProvider', () => {
  let provider: InMemoryAuthzKeyProvider

  const issuer1 = AuthorizationServerIssuer('https://authz.example.com/hoge')
  const issuer2 = AuthorizationServerIssuer('https://authz.example.com/fuga')
  const unknownIssuer = AuthorizationServerIssuer('https://unknown.example.com/unknown')
  const jwtHeader = {
    typ: 'JWT',
    alg: 'ES256',
  }

  beforeEach(() => {
    provider = inMemoryAuthzSignatureKeyStore()
    provider.providers = {
      get(kind) {
        if (kind === 'authz-signature-key-provider') {
          return [authzSignatureKey(), authzSignatureKey({ alg: 'ES384' })]
        }
        throw new Error(`Unexpected provider kind: ${kind}`)
      },
      select() {
        throw new Error('select is not used in this test')
      },
    }
  })

  it('should generate and fetch a public key when no pair is provided', async () => {
    await provider.save(issuer1, 'ES256')

    const fetchedPublicKey = await provider.fetch(issuer1, 'ES256')

    assert.ok(fetchedPublicKey)
    assert.equal(fetchedPublicKey.type, 'public')
  })

  it('should save a provided key pair and sign a JWT payload', async () => {
    const iat = Math.floor(Date.now() / 1000)
    const jwtPayload: JwtPayload = {
      iss: issuer1,
      sub: 'test-subject',
      aud: 'test-audience',
      iat,
      exp: iat + 3600,
    }
    const pair = await authzSignatureKey().generate()
    const entry: SignatureKeyEntry = {
      ...pair,
      format: 'jwk',
      declaredAlg: 'ES256',
    }

    await provider.save(issuer1, 'ES256', entry)
    const signature = await provider.sign(issuer1, 'ES256', jwtPayload, jwtHeader)

    assert.ok(signature)

    const encodedHeader = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')
    const encodedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url')
    const publicKey = await provider.fetch(issuer1, 'ES256')

    assert.ok(publicKey)

    const { payload } = await jwtVerify(
      `${encodedHeader}.${encodedPayload}.${signature}`,
      publicKey,
      { issuer: issuer1 }
    )

    assert.deepStrictEqual(payload, jwtPayload)
  })

  it('should return null when fetching a key for an unknown issuer', async () => {
    const fetchedPublicKey = await provider.fetch(unknownIssuer, 'ES256')

    assert.equal(fetchedPublicKey, null)
  })

  it('should keep different key algorithms isolated per issuer', async () => {
    await provider.save(issuer1, 'ES256')
    await provider.save(issuer2, 'ES384')

    const issuer1Key = await provider.fetch(issuer1, 'ES256')
    const issuer2Key = await provider.fetch(issuer2, 'ES384')

    assert.ok(issuer1Key)
    assert.ok(issuer2Key)
    assert.equal(await provider.fetch(issuer1, 'ES384'), null)
  })

  it('should throw when the provided pair algorithm does not match the requested algorithm', async () => {
    const pair = await authzSignatureKey({ alg: 'ES256' }).generate()
    const entry: SignatureKeyEntry = {
      ...pair,
      format: 'jwk',
      declaredAlg: 'ES256',
    }

    await assert.rejects(() => provider.save(issuer1, 'ES384', entry), {
      name: 'ILLEGAL_ARGUMENT',
    })
  })
})
