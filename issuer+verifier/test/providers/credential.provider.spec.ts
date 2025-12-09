import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { afterEach, before, describe, it, mock } from 'node:test'

import * as jwt from 'jsonwebtoken'
import { VerifiableCredential } from '../../src'
import { VcknotsError } from '../../src/errors/vcknots.error'
import { Jwk } from '../../src/jwk.type'
import { PresentationSubmission } from '../../src/presentation-submission.types'
import { credential } from '../../src/providers/credential.provider'
import { CredentialProvider } from '../../src/providers/provider.types'

describe('credential provider', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  })
  const jwk = publicKey.export({ format: 'jwk' }) as Jwk
  jwk.use = 'sig'
  jwk.alg = 'RS256'
  let provider: CredentialProvider
  const issuer = 'https://issuer.example.com'
  const kid = 'test-key-id'
  const vc: VerifiableCredential = {
    iss: issuer,
    sub: 'user-did',
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    issuer: issuer,
    issuanceDate: new Date().toISOString(),
  }

  const vcJwt = jwt.sign(vc, privateKey, {
    algorithm: 'RS256',
    header: { kid: kid, alg: 'RS256', typ: 'JWT' },
  })

  const mockFetch = (status: number, body: unknown) => {
    const mockResponse = {
      status,
      json: async () => body,
    }
    mock.method(global, 'fetch', () => Promise.resolve(mockResponse as Response))
  }

  const validPresentationSubmission: PresentationSubmission = {
    id: 'ps-id-1',
    definition_id: 'pd-id-1',
    descriptor_map: [
      {
        id: 'descriptor-1',
        format: 'jwt_vp_json',
        path: '$',
        path_nested: {
          id: 'id',
          format: 'jwt_vc_json',
          path: '$.verifiableCredential[0]',
        },
      },
    ],
  }

  before(() => {
    provider = credential()
  })

  afterEach(() => {
    mock.reset()
  })

  it('should verify a valid VC JWT', async () => {
    mockFetch(200, { jwks: { keys: [jwk] } })

    const result = await provider.verify(vcJwt, issuer, validPresentationSubmission)
    assert.strictEqual(result, true)
  })

  it('should handle issuer URL with a trailing slash', async () => {
    const issuerWithSlash = `${issuer}/`

    const fetchSpy = mock.method(global, 'fetch', () =>
      Promise.resolve({
        status: 200,
        json: async () => ({ jwks: { keys: [jwk] } }),
      } as Response)
    )

    const result = await provider.verify(vcJwt, issuerWithSlash, validPresentationSubmission)
    assert.strictEqual(result, true)

    const fetchCall = fetchSpy.mock.calls[0]
    assert.strictEqual(fetchCall.arguments[0], `${issuer}/.well-known/jwt-vc-issuer`)
  })

  it('should throw VcknotsError with code ISSUER_NOT_FOUND if fetch fails', async () => {
    mockFetch(404, { error: 'not found' })

    await assert.rejects(
      provider.verify(vcJwt, issuer, validPresentationSubmission),
      (err: VcknotsError) => {
        assert.strictEqual(err.name, 'ISSUER_NOT_FOUND')
        assert.match(err.message, /Cannot fetch jwt-vc-issuer for:/)
        return true
      }
    )
  })

  it('should throw VcknotsError with code JWKS_NOT_FOUND if jwks is missing', async () => {
    mockFetch(200, { message: 'no jwks here' })

    await assert.rejects(
      provider.verify(vcJwt, issuer, validPresentationSubmission),
      (err: VcknotsError) => {
        assert.strictEqual(err.name, 'JWKS_NOT_FOUND')
        assert.match(err.message, /Missing JWKS section in jwt-vc-issuer for:/)
        return true
      }
    )
  })

  it('should throw VcknotsError with code JWKS_NOT_FOUND if jwks.keys is empty', async () => {
    mockFetch(200, { jwks: { keys: [] } })

    await assert.rejects(
      provider.verify(vcJwt, issuer, validPresentationSubmission),
      (err: VcknotsError) => {
        assert.strictEqual(err.name, 'JWKS_NOT_FOUND')
        assert.match(err.message, /Empty JWKS keys in jwt-vc-issuer for:/)
        return true
      }
    )
  })

  it('should throw VcknotsError with code INVALID_JWT for invalid signature', async () => {
    const { privateKey: otherPrivateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })

    const jwtSignedByInvalidPrivateKey = jwt.sign(vc, otherPrivateKey, {
      algorithm: 'RS256',
      header: { kid: kid, alg: 'RS256', typ: 'JWT' },
    })

    // Sign with a different key than the one in JWKS
    mockFetch(200, { jwks: { keys: [jwk] } })

    await assert.rejects(
      provider.verify(jwtSignedByInvalidPrivateKey, issuer, validPresentationSubmission),
      (err: VcknotsError) => {
        assert.strictEqual(err.name, 'INVALID_JWT')
        assert.match(err.message, /Invalid VC signature detected/)
        return true
      }
    )
  })

  it('should throw VcknotsError with code INVALID_PRESENTATION_SUBMISSION if path_nested is missing', async () => {
    const badSubmission: PresentationSubmission = {
      id: 'ps-id-1',
      definition_id: 'pd-id-1',
      descriptor_map: [{ id: 'd1', format: 'jwt_vc', path: '$' }],
    }
    mockFetch(200, { jwks: { keys: [jwk] } })

    await assert.rejects(provider.verify(vcJwt, issuer, badSubmission), (err: VcknotsError) => {
      assert.strictEqual(err.name, 'INVALID_PRESENTATION_SUBMISSION')
      assert.match(err.message, /Missing path_nested/)
      return true
    })
  })

  it('should throw VcknotsError with code INVALID_PRESENTATION_SUBMISSION for unsupported format', async () => {
    const badSubmission: PresentationSubmission = {
      id: 'ps-id-1',
      definition_id: 'pd-id-1',
      descriptor_map: [
        {
          id: 'd1',
          format: 'ldp_vc',
          path: '$',
          path_nested: {
            format: 'ldp_vc',
            path: '$',
            id: 'id',
          },
        },
      ],
    }
    mockFetch(200, { jwks: { keys: [jwk] } })

    await assert.rejects(provider.verify(vcJwt, issuer, badSubmission), (err: VcknotsError) => {
      assert.strictEqual(err.name, 'INVALID_PRESENTATION_SUBMISSION')
      assert.match(err.message, /Unsupported vc format: ldp_vc/)
      return true
    })
  })
})
