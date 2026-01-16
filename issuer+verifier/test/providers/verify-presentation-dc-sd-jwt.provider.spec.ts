import assert from 'node:assert/strict'
import { afterEach, before, describe, it, mock } from 'node:test'

import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs'
import { SDJwtInstance } from '@sd-jwt/core'
import { Jwk } from '../../src/jwk.type'
import { VcknotsError } from '../../src/errors/vcknots.error'
import { verifyVerifiablePresentationDcSdJwt } from '../../src/providers/verify-presentation-dc-sd-jwt.provider'
import { VerifyVerifiablePresentationProvider } from '../../src/providers/provider.types'

const issuer = 'https://issuer.example.com'
const kid = 'test-kid'

describe('sd-jwt provider', () => {
  let provider: VerifyVerifiablePresentationProvider
  let publicJwk: Jwk
  let privateJwk: Jwk

  const issueSdJwt = async (iss: string, headerOverrides: Record<string, unknown> = {}) => {
    const signer = await ES256.getSigner(privateJwk)
    const instance = new SDJwtInstance({
      hasher: digest,
      signer,
      saltGenerator: () => generateSalt(8),
      signAlg: ES256.alg,
    })

    return instance.issue({ iss, sub: 'user-123', name: 'Alice' }, undefined, {
      header: { kid, ...headerOverrides },
    })
  }

  const mockFetch = (body: unknown, ok = true) =>
    mock.method(globalThis, 'fetch', async () => ({
      ok,
      statusText: ok ? 'OK' : 'Error',
      json: async () => body,
    }))

  before(async () => {
    provider = verifyVerifiablePresentationDcSdJwt()
    const keyPair = await ES256.generateKeyPair()
    publicJwk = { ...keyPair.publicKey, kid }
    privateJwk = { ...keyPair.privateKey, kid }
  })

  afterEach(() => {
    mock.restoreAll()
  })

  it('verifies SD-JWT using jwks in issuer metadata', async () => {
    const sdJwt = await issueSdJwt(issuer)
    const fetchSpy = mockFetch({ issuer, jwks: { keys: [publicJwk] } })

    const result = await provider.verify(sdJwt, { kind: 'dc+sd-jwt', specifiedDisclosures: [''] })

    assert.equal(result, true)
    assert.equal(fetchSpy.mock.callCount(), 1)
    const call = fetchSpy.mock.calls[0]
    assert.equal(call.arguments[0], `${issuer}/.well-known/jwt-vc-issuer`)
  })

  it('fetches metadata for issuer with path segment', async () => {
    const issuerWithPath = `${issuer}/tenant`
    const sdJwtWithPath = await issueSdJwt(issuerWithPath)
    const fetchSpy = mockFetch({ issuer: issuerWithPath, jwks: { keys: [publicJwk] } })

    const result = await provider.verify(sdJwtWithPath, {
      kind: 'dc+sd-jwt',
    })

    assert.equal(result, true)
    const call = fetchSpy.mock.calls[0]
    assert.equal(call.arguments[0], `${issuer}/.well-known/jwt-vc-issuer/tenant`)
  })

  it('rejects unsupported verify options', async () => {
    const sdJwt = await issueSdJwt(issuer)

    await assert.rejects(provider.verify(sdJwt, { kind: 'jwt_vp_json' }), (err: VcknotsError) => {
      assert.equal(err.name, 'ILLEGAL_ARGUMENT')
      return true
    })
  })

  it('fails when issuer metadata cannot be fetched', async () => {
    const sdJwt = await issueSdJwt(issuer)
    mockFetch({}, false)

    await assert.rejects(provider.verify(sdJwt, { kind: 'dc+sd-jwt' }), (err: VcknotsError) => {
      assert.equal(err.name, 'INVALID_SD_JWT')
      assert.match(err.message, /Failed to fetch issuer metadata/)
      return true
    })
  })

  it('fails when signature does not match metadata key', async () => {
    const sdJwt = await issueSdJwt(issuer)
    const otherKeyPair = await ES256.generateKeyPair()
    const mismatchedJwk = { ...otherKeyPair.publicKey, kid }
    mockFetch({ issuer, jwks: { keys: [mismatchedJwk] } })

    await assert.rejects(provider.verify(sdJwt, { kind: 'dc+sd-jwt' }), (err: Error) => {
      assert.equal(err.name, 'SDJWTException')
      assert.match(err.message, /Invalid JWT Signature/)
      return true
    })
  })

  it('fails when SD-JWT header lacks kid', async () => {
    const sdJwtNoKid = await issueSdJwt(issuer, { kid: '' })
    mockFetch({ issuer, jwks: { keys: [publicJwk] } })

    await assert.rejects(
      provider.verify(sdJwtNoKid, { kind: 'dc+sd-jwt' }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_SD_JWT')
        assert.match(err.message, /SD-JWT header missing kid for JWKs/)
        return true
      }
    )
  })

  it('fails when Key-Binding JWT is expected but not present', async () => {
    const sdJwt = await issueSdJwt(issuer)
    mockFetch({ issuer, jwks: { keys: [publicJwk] } })

    await assert.rejects(
      provider.verify(sdJwt, { kind: 'dc+sd-jwt', isKbJwt: true }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_SD_JWT')
        assert.match(err.message, /Expected Key-Binding JWT, but it was not present./)
        return true
      }
    )
  })

  it('verifies successfully when Key-Binding JWT is expected and present', async () => {
    let sdJwt = await issueSdJwt(issuer)
    sdJwt += 'eyJhbGciO..'
    mockFetch({ issuer, jwks: { keys: [publicJwk] } })

    await assert.rejects(
      provider.verify(sdJwt, { kind: 'dc+sd-jwt', isKbJwt: true }),
      (err: Error) => {
        assert.notEqual(err.message, 'Expected Key-Binding JWT, but it was not present.')
        return true
      }
    )
  })

  it('reports supported format via canHandle', () => {
    assert.equal(provider.canHandle('dc+sd-jwt'), true)
    assert.equal(provider.canHandle('jwt_vc_json'), false)
  })
})
