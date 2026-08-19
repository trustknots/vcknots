import assert from 'node:assert/strict'
import { describe, it, mock } from 'node:test'
import { ClientId } from '../../src/client-id.types'
import { raise } from '../../src/errors'
import { authzRequestJARX5c } from '../../src/providers/authorization-request-jar-x5c.provider'
import { VerifierCertificateStoreProvider } from '../../src/providers/provider.types'
import { RequestObject } from '../../src/request-object.types'

describe('AuthzRequestJARProvider', () => {
  const x5c = ['sign1', 'sign2']
  const verifierId = 'test-verifier' as ClientId
  const emptyVerifierId = 'empty-verifier' as ClientId

  const mockCertificateStore: VerifierCertificateStoreProvider = {
    kind: 'verifier-certificate-store-provider',
    name: 'mock-certificate-store',
    single: true,
    fetch: mock.fn(async (id: string) => {
      if (id === verifierId) return x5c
      if (id === emptyVerifierId) return []
      return Promise.reject(
        raise('CERTIFICATE_NOT_FOUND', { message: 'Verifier certificate not found.' })
      )
    }),
    save: mock.fn(async () => {}),
  }

  const provider = authzRequestJARX5c()
  mock.method(provider.providers, 'get', (name: string) => {
    if (name === 'verifier-certificate-store-provider') {
      return mockCertificateStore
    }
    return undefined
  })

  it('should have correct kind, name, and single properties', () => {
    assert.equal(provider.kind, 'authz-request-jar-provider')
    assert.equal(provider.name, 'authorization-request-jar-x5c.provider')
    assert.strictEqual(provider.single, false)
  })

  it('should handle supported client_id_prefixes', () => {
    assert.ok(provider.canHandle('x509_san_dns'))
    assert.ok(!provider.canHandle('other'))
  })

  it('should generate a JWT with x5c', async () => {
    const requestObject: RequestObject = {
      response_type: 'code',
      client_id: 'test-client',
      redirect_uri: 'https://example.com/cb',
      response_mode: 'query',
    }
    const alg = 'ES256'

    const jwt = await provider.generate(verifierId, requestObject, alg)

    assert.deepStrictEqual(jwt.header, {
      alg,
      typ: 'oauth-authz-req+jwt',
      x5c,
    })
    assert.ok(jwt.payload.iat)
    assert.equal(typeof jwt.payload.iat, 'number')
    const { iat, ...payload } = jwt.payload
    assert.deepStrictEqual(payload, requestObject)
  })

  it('should generate a JWT with nonce', async () => {
    const alg = 'ES256'
    const nonce = 'test-nonce'
    const requestObject: RequestObject = {
      response_type: 'code',
      client_id: 'test-client',
      redirect_uri: 'https://example.com/cb',
      response_mode: 'query',
      nonce,
    }

    const jwt = await provider.generate(verifierId, requestObject, alg)

    assert.deepStrictEqual(jwt.header, {
      alg,
      typ: 'oauth-authz-req+jwt',
      x5c,
    })
    assert.ok(jwt.payload.iat)
    assert.equal(typeof jwt.payload.iat, 'number')
    const { iat, ...payload } = jwt.payload
    assert.deepStrictEqual(payload, requestObject)
  })

  it('should generate a JWT with wallet_nonce', async () => {
    const alg = 'ES256'
    const nonce = 'test-nonce'
    const wallet_nonce = 'test-wallet_nonce'
    const requestObject: RequestObject = {
      response_type: 'code',
      client_id: 'test-client',
      redirect_uri: 'https://example.com/cb',
      response_mode: 'query',
      nonce,
    }

    const jwt = await provider.generate(verifierId, requestObject, alg, wallet_nonce)

    assert.deepStrictEqual(jwt.header, {
      alg,
      typ: 'oauth-authz-req+jwt',
      x5c,
    })
    assert.ok(jwt.payload.iat)
    assert.equal(typeof jwt.payload.iat, 'number')
    const { iat, ...payload } = jwt.payload
    assert.deepStrictEqual(payload, { ...requestObject, wallet_nonce })
  })

  it('should throw an error if certificate is not found', async () => {
    const alg = 'ES256'
    const requestObject: RequestObject = {
      response_type: 'code',
      client_id: 'test-client',
      redirect_uri: 'https://example.com/cb',
      response_mode: 'query',
    }

    await assert.rejects(provider.generate('unknown-verifier' as ClientId, requestObject, alg), {
      name: 'CERTIFICATE_NOT_FOUND',
      message: 'Verifier certificate not found.',
    })
  })

  it('should throw an error if certificate store returns empty array', async () => {
    const alg = 'ES256'
    const requestObject: RequestObject = {
      response_type: 'code',
      client_id: 'test-client',
      redirect_uri: 'https://example.com/cb',
      response_mode: 'query',
    }

    await assert.rejects(provider.generate(emptyVerifierId, requestObject, alg), {
      name: 'CERTIFICATE_NOT_FOUND',
      message: 'Verifier certificate not found.',
    })
  })
})
