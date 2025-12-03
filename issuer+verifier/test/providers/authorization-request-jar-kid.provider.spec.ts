import assert from 'node:assert/strict'
import { describe, it, mock, before } from 'node:test'
import { authzRequestJARKid } from '../../src/providers/authorization-request-jar-kid.provider'
import { VerifierSignatureKeyStoreProvider } from '../../src/providers/provider.types'
import { RequestObject } from '../../src/request-object.types'
import { ClientId } from '../../src/client-id.types'
import { generateKeyPair, exportJWK, calculateJwkThumbprint } from 'jose'

describe('AuthzRequestJARProvider', () => {
  const verifierId = 'test-verifier' as ClientId
  const alg = 'ES256'
  let publicKey: CryptoKey
  let kid: string

  before(async () => {
    const keys = await generateKeyPair(alg)
    publicKey = keys.publicKey
    const jwk = await exportJWK(publicKey)
    kid = await calculateJwkThumbprint(jwk)
  })

  const mockKeyStore: VerifierSignatureKeyStoreProvider = {
    kind: 'verifier-signature-key-store-provider',
    name: 'mock-key-store',
    single: true,
    fetch: mock.fn(async (id: ClientId, fetchAlg: string) => {
      if (id === verifierId && fetchAlg === alg) {
        return publicKey
      }
      return null
    }),
    save: mock.fn(async () => {}),
    fetchPrivate: mock.fn(async () => null),
  }

  const provider = authzRequestJARKid()
  mock.method(provider.providers, 'get', (name: string) => {
    if (name === 'verifier-signature-key-store-provider') {
      return mockKeyStore
    }
    return undefined
  })

  it('should have correct kind, name, and single properties', () => {
    assert.equal(provider.kind, 'authz-request-jar-provider')
    assert.equal(provider.name, 'default-authz-request-jar-provider')
    assert.strictEqual(provider.single, false)
  })

  it('should handle key type "redirect_uri"', () => {
    assert.ok(provider.canHandle('redirect_uri'))
    assert.ok(!provider.canHandle('other'))
  })

  it('should generate a JWT with kid', async () => {
    const requestObject: RequestObject = {
      response_type: 'code',
      client_id: 'test-client',
      redirect_uri: 'https://example.com/cb',
      response_mode: 'query',
    }

    const jwt = await provider.generate(verifierId, requestObject, alg)

    assert.deepStrictEqual(jwt.header, {
      alg,
      typ: 'oauth-authz-req+jwt',
      kid,
    })
    assert.ok(jwt.payload.iat)
    assert.equal(typeof jwt.payload.iat, 'number')
    const { iat, ...payload } = jwt.payload
    assert.deepStrictEqual(payload, requestObject)
  })

  it('should generate a JWT with nonce', async () => {
    const requestObject: RequestObject = {
      response_type: 'code',
      client_id: 'test-client',
      redirect_uri: 'https://example.com/cb',
      response_mode: 'query',
    }
    const nonce = 'test-nonce'

    const jwt = await provider.generate(verifierId, requestObject, alg, nonce)

    assert.deepStrictEqual(jwt.header, {
      alg,
      typ: 'oauth-authz-req+jwt',
      kid,
    })
    assert.ok(jwt.payload.iat)
    assert.equal(typeof jwt.payload.iat, 'number')
    const { iat, ...payload } = jwt.payload
    assert.deepStrictEqual(payload, { ...requestObject, nonce })
  })

  it('should generate a JWT with wallet_nonce', async () => {
    const requestObject: RequestObject = {
      response_type: 'code',
      client_id: 'test-client',
      redirect_uri: 'https://example.com/cb',
      response_mode: 'query',
    }
    const nonce = 'test-nonce'
    const wallet_nonce = 'test-wallet_nonce'

    const jwt = await provider.generate(verifierId, requestObject, alg, nonce, wallet_nonce)

    assert.deepStrictEqual(jwt.header, {
      alg,
      typ: 'oauth-authz-req+jwt',
      kid,
    })
    assert.ok(jwt.payload.iat)
    assert.equal(typeof jwt.payload.iat, 'number')
    const { iat, ...payload } = jwt.payload
    assert.deepStrictEqual(payload, { ...requestObject, nonce, wallet_nonce })
  })

  it('should throw an error if key is not found', async () => {
    const requestObject: RequestObject = {
      response_type: 'code',
      client_id: 'test-client',
      redirect_uri: 'https://example.com/cb',
      response_mode: 'query',
    }
    const nonce = 'test-nonce'

    await assert.rejects(
      provider.generate('unknown-verifier' as ClientId, requestObject, alg, nonce),
      {
        name: 'AUTHZ_VERIFIER_KEY_NOT_FOUND',
        message: 'Verifier key not found.',
      }
    )
  })
})
