import assert from 'node:assert/strict'
import { afterEach, before, describe, it, mock } from 'node:test'

import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs'
import { SDJwtInstance } from '@sd-jwt/core'
import { Jwk } from '../../src/jwk.type'
import { VcknotsError } from '../../src/errors/vcknots.error'
import { verifyVerifiablePresentationDcSdJwt } from '../../src/providers/verify-presentation-dc-sd-jwt.provider'
// import { VerifyVerifiablePresentationProvider } from '../../src/providers/provider.types'
import { CnonceStoreProvider } from '../../src/providers/provider.types'

const issuer = 'https://issuer.example.com'
const kid = 'test-kid'

describe('sd-jwt provider', () => {
  // let provider: VerifyVerifiablePresentationProvider
  let provider: ReturnType<typeof verifyVerifiablePresentationDcSdJwt>
  let mockCnonceStore: CnonceStoreProvider
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

    return instance.issue({ iss, sub: 'user-123', name: 'Alice', vct: 'vcknots-test' }, undefined, {
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
    mockCnonceStore = {
      kind: 'cnonce-store-provider',
      name: 'mock-cnonce-store',
      single: true,
      validate: mock.fn(async (nonce: string) => nonce === 'bcb201b7e186ed380127b9158a9d57a6'),
      revoke: mock.fn(async () => {}),
      save: mock.fn(async () => {}),
    }

    Object.defineProperty(provider, 'providers', {
      value: {
        get: (kind: string) => {
          if (kind === 'cnonce-store-provider') {
            return mockCnonceStore
          }
          return undefined
        },
        select: () => {
          // This test assumes that select will not be called.
        },
      },
      configurable: true,
    })
  })

  afterEach(() => {
    mock.restoreAll()
  })

  it('verifies SD-JWT using jwks in issuer metadata', async () => {
    const sdJwt = await issueSdJwt(issuer)
    const fetchSpy = mockFetch({ issuer, jwks: { keys: [publicJwk] } })

    const result = await provider.verify(sdJwt, { kind: 'dc+sd-jwt', specifiedDisclosures: [] })

    assert.ok(result)
    assert.equal(fetchSpy.mock.callCount(), 1)
    const call = fetchSpy.mock.calls[0]
    assert.equal(call.arguments[0], `${issuer}/.well-known/jwt-vc-issuer`)
  })

  it('fetches metadata for issuer with path segment', async () => {
    const issuerWithPath = `${issuer}/tenant/1234`
    const sdJwtWithPath = await issueSdJwt(issuerWithPath)
    const fetchSpy = mockFetch({ issuer: issuerWithPath, jwks: { keys: [publicJwk] } })

    const result = await provider.verify(sdJwtWithPath, {
      kind: 'dc+sd-jwt',
    })

    assert.ok(result)
    const call = fetchSpy.mock.calls[0]
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-13#section-5.1
    assert.equal(call.arguments[0], `${issuer}/.well-known/jwt-vc-issuer/tenant/1234`)
  })

  it('verifies SD-JWT using jwks_uri in issuer metadata', async () => {
    const sdJwt = await issueSdJwt(issuer)
    const jwksUri = 'https://issuer.example.com/jwks'
    const fetchSpy = mock.fn(
      async (url: string) => {
        if (url.includes('.well-known')) {
          return {
            ok: true,
            statusText: 'OK',
            json: async () => ({ issuer, jwks_uri: jwksUri }),
          }
        }
        return {
          ok: true,
          statusText: 'OK',
          json: async () => ({ keys: [publicJwk] }),
        }
      },
      { times: 2 }
    )
    mock.method(globalThis, 'fetch', fetchSpy)

    const result = await provider.verify(sdJwt, { kind: 'dc+sd-jwt', specifiedDisclosures: [] })

    assert.ok(result)
    assert.equal(fetchSpy.mock.callCount(), 2)
    assert.equal(fetchSpy.mock.calls[0].arguments[0], `${issuer}/.well-known/jwt-vc-issuer`)
    assert.equal(fetchSpy.mock.calls[1].arguments[0], jwksUri)
  })

  it('fails when jwks_uri fetch fails', async () => {
    const sdJwt = await issueSdJwt(issuer)
    const jwksUri = 'https://issuer.example.com/jwks'
    const fetchSpy = mock.fn(
      async (url: string) => {
        if (url.includes('.well-known')) {
          return {
            ok: true,
            statusText: 'OK',
            json: async () => ({ issuer, jwks_uri: jwksUri }),
          }
        }
        return {
          ok: false,
          statusText: 'Not Found',
          json: async () => ({}),
        }
      },
      { times: 2 }
    )
    mock.method(globalThis, 'fetch', fetchSpy)

    await assert.rejects(
      provider.verify(sdJwt, { kind: 'dc+sd-jwt', specifiedDisclosures: [] }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_SD_JWT')
        assert.match(err.message, /Failed to fetch JWKS/)
        return true
      }
    )
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

  it('fails when no matching JWK is found for kid', async () => {
    const sdJwt = await issueSdJwt(issuer)
    const otherKeyPair = await ES256.generateKeyPair()
    const mismatchedJwk = { ...otherKeyPair.publicKey, kid: 'other-kid' }
    mockFetch({ issuer, jwks: { keys: [mismatchedJwk] } })

    await assert.rejects(provider.verify(sdJwt, { kind: 'dc+sd-jwt' }), (err: VcknotsError) => {
      assert.equal(err.name, 'INVALID_SD_JWT')
      assert.match(err.message, /No matching JWK found for kid/)
      return true
    })
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
    const sampleSdJwt =
      'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCIsIng1YyI6WyJNSUlDSGpDQ0FjT2dBd0lCQWdJVVpYOUJTNUNET0pSVzJ0MUZLMVVETXQvUXdNRXdDZ1lJS29aSXpqMEVBd0l3SVRFTE1Ba0dBMVVFQmhNQ1IwSXhFakFRQmdOVkJBTU1DVTlKUkVZZ1ZHVnpkREFlRncweU5ERXhNalV3T0RNMk1EUmFGdzB6TkRFeE1qTXdPRE0yTURSYU1DRXhDekFKQmdOVkJBWVRBa2RDTVJJd0VBWURWUVFEREFsUFNVUkdJRlJsYzNRd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFUVC9kTHNkNTFMTEJyR1Y2UjIzbzZ2eW1SeEhYZUZCb0k4eXEzMXk1a0ZWMlZWMGdpOXg1WnpFRmlxOERNaUFIdWNMQUNGbmR4THRab3JDaGE5enpuUW80SFlNSUhWTUIwR0ExVWREZ1FXQkJTNWNiZGdBZU1CaTV3eHBicHdJU0doU2hBV0VUQWZCZ05WSFNNRUdEQVdnQlM1Y2JkZ0FlTUJpNXd4cGJwd0lTR2hTaEFXRVRBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUlHQkJnTlZIUkVFZWpCNGdoQjNkM2N1YUdWbGJtRnVMbTFsTG5WcmdoMWtaVzF2TG1ObGNuUnBabWxqWVhScGIyNHViM0JsYm1sa0xtNWxkSUlKYkc5allXeG9iM04wZ2hac2IyTmhiR2h2YzNRdVpXMXZZbWw0TG1OdkxuVnJnaUprWlcxdkxuQnBaQzFwYzNOMVpYSXVZblZ1WkdWelpISjFZMnRsY21WcExtUmxNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUNQYm5MeENJK1dSMXZoT1crQThLem5BV3YxTUpvK1lFYjFNSTQ1TktXL1ZRSWhBTHpzcW94OFZ1QlJ3TjJkbDVMa3BueFA0b0g5cDZIMEFPWm1LUCtZN25YUyJdfQ.eyJfc2QiOlsiMDRVY1lqOEV1T1ExWWZHNzdWUDZQdWdPVWF1dnRNQ0tSU1RvdUR4aldidyIsIkgwdElaUGhWVFVqTnhCd1VzelFrMW95VlVQNU5zZGRLNWo2ZGcyb0NPemMiLCJXelV0Nkd2ZnJyVHlLWmFIRFhTcERYWHJGLUxURm1UME9WTFhvYmFpZnVNIiwiWGVuek44TVl1LU5fMXpGV3g1dVVYb0FWLWhwdG1MV2d5ekczbUVkR0tDZyIsImVMbVlqTGVLY0ZQS2dVN1YwQWlVOVVMeXZ3cWVKLWJ4ZWdDUGlMTWlTMFkiLCJsdmtZMVh3OFE5M1BUOERQRHhHSlhCMzlobHJTNFpOUVZCbkhmcFZOUVZBIiwibXY3T0tCMnRoUWpOV2lxU3ZBTDAxY2VOUG5wTDlDVmhlNGRmNHRSYUxGTSIsIm52Mm9rMjFXejVkN2lsenNkczE1Vk5tRXI1U0VPYlBzVWNxNmpjemxXaEUiXSwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIuZXVkaXcuZGV2IiwidmN0IjoidXJuOmV1LmV1cm9wYS5lYy5ldWRpOnBpZDoxIiwiX3NkX2FsZyI6InNoYS0yNTYiLCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZXpaZ0t3TXVlQXlaTEhVZ1Nwek5rYk9XRGdqSlhUQU9KbjhNZnRPbmF5USIsInkiOiJGeV9VNEt5WlFmLTlqS3BGSnRINk9GRlJYbXdBY3ZleWZ1b0RwMWhTT0ZvIn19LCJpYXQiOjE3NzIwMTU0NjV9.gseVu9AStknO-locvvCKcnj8PnUWSZtMF4wE-SqqXteI4xMOfUaA0zFpZR6hGfNBPUSZL3ROw4RYDLQIOQjsMQ~WyJkMTQ2V0NwTVg1MDZpZzY3UHoxVGtBIiwgImZhbWlseV9uYW1lIiwgIlRFU1QiXQ~WyJzQnE1aUY1dTFibVRfU2dYblF1UmtBIiwgImdpdmVuX25hbWUiLCAiVEFSTyJd~WyJRNG80UjFxdDhacENFSkhIWFRZRmpRIiwgImJpcnRoZGF0ZSIsICIyMDAwLTAzLTAzIl0~WyJHUDRwcXpKaVJ4RGN0TEVlcEZ5VzJBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIkpQIl1d~WyJKX2pYUkZxT0poR18yRmFmOHl4bFBBIiwgImlzc3VpbmdfYXV0aG9yaXR5IiwgIlRlc3QgUElEIGlzc3VlciJd~WyJiNDk2UGotUDdXS05iWkFKMDJ3NVhnIiwgImlzc3VpbmdfY291bnRyeSIsICJGQyJd~WyJ4bGlVZlExX050Y3IyYnBJcGJCN1lnIiwgIjE4IiwgdHJ1ZV0~WyJ3dDJCRVFYVDBfUDNIQ0N4VVVoSmZBIiwgImFnZV9lcXVhbF9vcl9vdmVyIiwgeyJfc2QiOiBbInNDczNOZlNLYVRoR3pRbERVRTd5WnR4VmVBSm5lRGY2dS1nNFk1NVdRekUiXX1d~WyJxcm1aeGpLNUtPZXRGUHFOSGpWN0h3IiwgImxvY2FsaXR5IiwgIkpBUEFOIl0~WyJpc0ZDcF8xREhnUUpZLVBtZWYwRHV3IiwgInBsYWNlX29mX2JpcnRoIiwgeyJfc2QiOiBbIjF1LWszbEFKMHlPV2x4OUJLLWFSVEVaUUZyLXVPUFRrTGdEN3U5aTFlMEUiXX1d~'
    const sampleKbJwt =
      'eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJhdWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIiwiaWF0IjoxNzcyMDE1NDg4LCJub25jZSI6ImJjYjIwMWI3ZTE4NmVkMzgwMTI3YjkxNThhOWQ1N2E2Iiwic2RfaGFzaCI6IkdpNkkxZTFqdVgyU29QVmwwR3pXamZTZHBkaUVxOFowc2FKX3B4Y3poVVkifQ.bHaKF05dNqYM7jOlhgQGjqO958lTMTMM4Pu9YJVM9fjDW_zTVur5ZzDKHWxImq_8lPQ3euAJvXJlz6j7Yj2mtw'
    const sampleSdJwtVp = sampleSdJwt + sampleKbJwt

    const result = await provider.verify(sampleSdJwtVp, { kind: 'dc+sd-jwt', isKbJwt: true })
    assert.ok(result)
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    assert.equal((mockCnonceStore.validate as any).mock.callCount(), 1)
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    assert.equal((mockCnonceStore.revoke as any).mock.callCount(), 1)
  })

  it('reports supported format via canHandle', () => {
    assert.equal(provider.canHandle('dc+sd-jwt'), true)
    assert.equal(provider.canHandle('jwt_vc_json'), false)
  })

  it('fails when signature does not match x5c key', async () => {
    const certificate =
      'MIICHjCCAcOgAwIBAgIUZX9BS5CDOJRW2t1FK1UDMt/QwMEwCgYIKoZIzj0EAwIwITELMAkGA1UEBhMCR0IxEjAQBgNVBAMMCU9JREYgVGVzdDAeFw0yNDExMjUwODM2MDRaFw0zNDExMjMwODM2MDRaMCExCzAJBgNVBAYTAkdCMRIwEAYDVQQDDAlPSURGIFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT/dLsd51LLBrGV6R23o6vymRxHXeFBoI8yq31y5kFV2VV0gi9x5ZzEFiq8DMiAHucLACFndxLtZorCha9zznQo4HYMIHVMB0GA1UdDgQWBBS5cbdgAeMBi5wxpbpwISGhShAWETAfBgNVHSMEGDAWgBS5cbdgAeMBi5wxpbpwISGhShAWETAPBgNVHRMBAf8EBTADAQH/MIGBBgNVHREEejB4ghB3d3cuaGVlbmFuLm1lLnVrgh1kZW1vLmNlcnRpZmljYXRpb24ub3BlbmlkLm5ldIIJbG9jYWxob3N0ghZsb2NhbGhvc3QuZW1vYml4LmNvLnVrgiJkZW1vLnBpZC1pc3N1ZXIuYnVuZGVzZHJ1Y2tlcmVpLmRlMAoGCCqGSM49BAMCA0kAMEYCIQCPbnLxCI+WR1vhOW+A8KznAWv1MJo+YEb1MI45NKW/VQIhALzsqox8VuBRwN2dl5LkpnxP4oH9p6H0AOZmKP+Y7nXS'
    const sdJwt = await issueSdJwt(issuer, { x5c: [certificate] })
    await assert.rejects(
      provider.verify(sdJwt, { kind: 'dc+sd-jwt', specifiedDisclosures: [] }),
      (err: Error) => {
        assert.equal(err.name, 'SDJWTException')
        assert.match(err.message, /Invalid JWT Signature/)
        return true
      }
    )
  })
})
