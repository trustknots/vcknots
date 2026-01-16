import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { afterEach, before, describe, it, mock } from 'node:test'
import * as jwt from 'jsonwebtoken'
import { VerifiableCredential } from '../../src'
import { VcknotsError } from '../../src/errors/vcknots.error'
import { Jwk } from '../../src/jwk.type'
import { VerifyCredentialProvider } from '../../src/providers/provider.types'
import { verifyCredentialJwt } from '../../src/providers/verify-credential-jwt-vc-json.provider'
import base64url from 'base64url'

describe('verifyCredentialJwt provider', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  })
  const jwk = publicKey.export({ format: 'jwk' }) as Jwk
  jwk.use = 'sig'
  jwk.alg = 'RS256'
  let provider: VerifyCredentialProvider
  const issuer = 'https://issuer.example.com'
  const kid = 'test-key-id'
  const vc: VerifiableCredential = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: issuer,
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    },
  }

  const vcJwt = jwt.sign({ vc }, privateKey, {
    algorithm: 'RS256',
    header: { kid: kid, alg: 'RS256', typ: 'JWT' },
  })

  const mockFetch = (status: number, body: unknown, ok = true) => {
    return mock.method(global, 'fetch', () => {
      return Promise.resolve({
        status,
        ok,
        json: async () => body,
        statusText: `Status ${status}`,
      } as Response)
    })
  }

  before(() => {
    provider = verifyCredentialJwt()
  })

  afterEach(() => {
    mock.reset()
  })

  it('should verify a valid VC JWT', async () => {
    mockFetch(200, {
      issuer,
      jwks: { keys: [jwk] },
    })
    const result = await provider.verify(vcJwt)
    assert.strictEqual(result, true)
  })

  it('should throw ILLEGAL_ARGUMENT if vc is not a string', async () => {
    await assert.rejects(provider.verify({} as never), (err: VcknotsError) => {
      assert.strictEqual(err.name, 'ILLEGAL_ARGUMENT')
      assert.strictEqual(err.message, 'VC represented as object is not supported.')
      return true
    })
  })

  it('should throw INVALID_CREDENTIAL for non-https issuer URI', async () => {
    const vcWithHttpIssuer = { ...vc, issuer: 'http://issuer.example.com' }
    const jwtWithHttpIssuer = jwt.sign({ vc: vcWithHttpIssuer }, privateKey, {
      algorithm: 'RS256',
    })
    await assert.rejects(provider.verify(jwtWithHttpIssuer), (err: VcknotsError) => {
      assert.strictEqual(err.name, 'INVALID_CREDENTIAL')
      assert.strictEqual(err.message, 'Issuer URI must use https scheme')
      return true
    })
  })

  it('should handle issuer URL with path', async () => {
    const issuerWithPath = `${issuer}/path`
    const vcWithIssuerPath = { ...vc, issuer: issuerWithPath }
    const jwtWithIssuerPath = jwt.sign({ vc: vcWithIssuerPath }, privateKey, {
      algorithm: 'RS256',
    })
    const fetch = mockFetch(200, {
      issuer: issuerWithPath,
      jwks: { keys: [jwk] },
    })
    await provider.verify(jwtWithIssuerPath)
    assert.strictEqual(fetch.mock.calls[0].arguments[0], `${issuer}/.well-known/jwt-vc-issuer/path`)
  })

  it('should throw INVALID_CREDENTIAL if fetching metadata fails', async () => {
    mockFetch(404, {}, false)
    await assert.rejects(provider.verify(vcJwt), (err: VcknotsError) => {
      assert.strictEqual(err.name, 'INVALID_CREDENTIAL')
      assert.strictEqual(err.message, 'Failed to fetch issuer metadata: Status 404')
      return true
    })
  })

  it('should throw INVALID_CREDENTIAL if issuer in metadata does not match', async () => {
    mockFetch(200, {
      issuer: 'https://wrong-issuer.example.com',
      jwks: { keys: [jwk] },
    })
    await assert.rejects(provider.verify(vcJwt), (err: VcknotsError) => {
      assert.strictEqual(err.name, 'INVALID_CREDENTIAL')
      assert.strictEqual(err.message, 'Issuer in metadata does not match VC issuer')
      return true
    })
  })

  it('should verify with jwks_uri', async () => {
    const jwksUri = 'https://issuer.example.com/jwks.json'
    const fetch = mock.fn(
      (url: string) => {
        if (url.includes('.well-known')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ issuer, jwks_uri: jwksUri }),
          } as Response)
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ keys: [jwk] }),
        } as Response)
      },
      { times: 2 }
    )
    mock.method(global, 'fetch', fetch)

    const result = await provider.verify(vcJwt)
    assert.strictEqual(result, true)
    assert.strictEqual(fetch.mock.calls[1].arguments[0], jwksUri)
  })

  it('should throw JWKS_NOT_FOUND if fetching jwks_uri fails', async () => {
    const jwksUri = 'https://issuer.example.com/jwks.json'
    const fetch = mock.fn(
      (url: string) => {
        if (url.includes('.well-known')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({ issuer, jwks_uri: jwksUri }),
          } as Response)
        }
        return Promise.resolve({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        } as Response)
      },
      { times: 2 }
    )
    mock.method(global, 'fetch', fetch)
    await assert.rejects(provider.verify(vcJwt), (err: VcknotsError) => {
      assert.strictEqual(err.name, 'JWKS_NOT_FOUND')
      assert.strictEqual(err.message, 'Failed to fetch JWKS: Not Found')
      return true
    })
  })

  it('should throw JWKS_NOT_FOUND if no jwks or jwks_uri in metadata', async () => {
    mockFetch(200, { issuer })
    await assert.rejects(provider.verify(vcJwt), (err: VcknotsError) => {
      assert.strictEqual(err.name, 'JWKS_NOT_FOUND')
      assert.strictEqual(err.message, 'No JWKS or JWKS URI found in issuer metadata')
      return true
    })
  })

  it('should throw JWKS_NOT_FOUND if jwks keys are empty', async () => {
    mockFetch(200, { issuer, jwks: { keys: [] } })
    await assert.rejects(provider.verify(vcJwt), (err: VcknotsError) => {
      assert.strictEqual(err.name, 'JWKS_NOT_FOUND')
      assert.match(
        err.message,
        /Empty JWKS keys in jwt-vc-issuer for: https:\/\/issuer.example.com\//
      )
      return true
    })
  })

  it('should throw INVALID_CREDENTIAL if issuer is not found in jwt', async () => {
    const payload = JSON.parse(base64url.decode(vcJwt.split('.')[1]))
    const newPayload = { ...payload, vc: { ...payload.vc, issuer: undefined } }
    const newJwt = `${vcJwt.split('.')[0]}.${base64url.encode(
      JSON.stringify(newPayload)
    )}.${vcJwt.split('.')[2]}`

    await assert.rejects(provider.verify(newJwt), (err: VcknotsError) => {
      assert.strictEqual(err.name, 'INVALID_CREDENTIAL')
      return true
    })
  })

  it("canHandle should return true for 'jwt_vc_json'", () => {
    assert.strictEqual(provider.canHandle('jwt_vc_json'), true)
  })

  it("canHandle should return false for formats other than 'jwt_vc_json'", () => {
    assert.strictEqual(provider.canHandle('ldp_vc'), false)
    assert.strictEqual(provider.canHandle('another_format'), false)
  })

  it('should handle payload with vc property', async () => {
    mockFetch(200, {
      issuer,
      jwks: { keys: [jwk] },
    })

    const result = await provider.verify(vcJwt) // vcJwt is already in { vc: ... } format
    assert.strictEqual(result, true)
  })

  it('should handle payload without vc property (flat)', async () => {
    const flatJwt = jwt.sign(vc, privateKey, {
      algorithm: 'RS256',
      header: { kid: kid, alg: 'RS256', typ: 'JWT' },
    })

    mockFetch(200, {
      issuer,
      jwks: { keys: [jwk] },
    })

    const result = await provider.verify(flatJwt)
    assert.strictEqual(result, true)
  })
})
