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
    mockCnonceStore = {
      kind: 'cnonce-store-provider',
      name: 'mock-cnonce-store',
      single: true,
      validate: mock.fn(async (nonce: string) => nonce === '07cc78df02924028995d94544d22b75b'),
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

    assert.equal(result, true)
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
      'eyJ4NWMiOlsiTUlJQ0hqQ0NBY09nQXdJQkFnSVVaWDlCUzVDRE9KUlcydDFGSzFVRE10L1F3TUV3Q2dZSUtvWkl6ajBFQXdJd0lURUxNQWtHQTFVRUJoTUNSMEl4RWpBUUJnTlZCQU1NQ1U5SlJFWWdWR1Z6ZERBZUZ3MHlOREV4TWpVd09ETTJNRFJhRncwek5ERXhNak13T0RNMk1EUmFNQ0V4Q3pBSkJnTlZCQVlUQWtkQ01SSXdFQVlEVlFRRERBbFBTVVJHSUZSbGMzUXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBVFQvZExzZDUxTExCckdWNlIyM282dnltUnhIWGVGQm9JOHlxMzF5NWtGVjJWVjBnaTl4NVp6RUZpcThETWlBSHVjTEFDRm5keEx0Wm9yQ2hhOXp6blFvNEhZTUlIVk1CMEdBMVVkRGdRV0JCUzVjYmRnQWVNQmk1d3hwYnB3SVNHaFNoQVdFVEFmQmdOVkhTTUVHREFXZ0JTNWNiZGdBZU1CaTV3eHBicHdJU0doU2hBV0VUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01JR0JCZ05WSFJFRWVqQjRnaEIzZDNjdWFHVmxibUZ1TG0xbExuVnJnaDFrWlcxdkxtTmxjblJwWm1sallYUnBiMjR1YjNCbGJtbGtMbTVsZElJSmJHOWpZV3hvYjNOMGdoWnNiMk5oYkdodmMzUXVaVzF2WW1sNExtTnZMblZyZ2lKa1pXMXZMbkJwWkMxcGMzTjFaWEl1WW5WdVpHVnpaSEoxWTJ0bGNtVnBMbVJsTUFvR0NDcUdTTTQ5QkFNQ0Ewa0FNRVlDSVFDUGJuTHhDSStXUjF2aE9XK0E4S3puQVd2MU1KbytZRWIxTUk0NU5LVy9WUUloQUx6c3FveDhWdUJSd04yZGw1TGtwbnhQNG9IOXA2SDBBT1ptS1ArWTduWFMiXSwidHlwIjoiZGMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJfc2QiOlsiMHBzU1pmUEpWVUNDZkZFSy0wc241TEV3UjA5RkZXdWFpTHMzQld0ZWpBdyIsIk5qa1l6RVdDRUxiSG9LTlhkdUsxYVgxRW91SW9kemJmNFJ2NXVucnRmdTAiLCJPV04xMnUzZFRkTFNOZ3hWRlBVQzN1eUdleEFiSWN0QWU2SUQwWlVYbGtvIiwiUWN4ZmhHOGR4RXdsNUZVRnAxUEt1T0hEOHJQZzBsX1RnS0VEZE5qb1lhQSIsImQwSXhiVEwtR0s1RTk0aGpQNi1HcEhYSGN1dllSNEIwV2Q5MFZvMUU3YkkiLCJmTU9ybXhFRWJ2emRXendZdkFhVmtuNjlSVUsyMXN3NzA4TVZFYmpvSkNJIiwiaU4xZnRJOWozZlRubGViaGVzSHZUeFVEYmI2UGdiaUUzazBjaGFWUG5vdyIsInhGdjJpT3dPY2tNYVU5d0tXX3k3QmFEaEowSHoxUXZaSFRIX1B6NnVnX3MiXSwidmN0IjoidXJuOmV1ZGk6cGlkOjEiLCJpc3MiOiJodHRwczovL2RlbW8uY2VydGlmaWNhdGlvbi5vcGVuaWQubmV0L3Rlc3QvYS9ob2dldGVzdCIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJWbmx3bFRvNmZqWmlxU0phOEI5ZlY0Z3hyZzZ3X1ZPbmgxZ2FaQ0pPbEcwIiwieSI6IjVyMVM5Vm9rWmRTQTU0RG9UNVNxYWxHLThIY2cyVWJMZ2hRWGUwY2VQbkUifX0sImV4cCI6MTc3MDE3MzAzNSwiaWF0IjoxNzY4OTYzNDM1fQ.R4fKWZ_jaUZB5giiVGx2fJxwXoNrhKY7mDWPjTOLEuZC6u3nsUTJ0BcvrNEnX_XGddMuqj-fyw3GKlf-D2wGxA~WyJRSTRNdzZDbmkzc1NXaVRoQmhHMXJ3IiwiZ2l2ZW5fbmFtZSIsIkplYW4iXQ~WyJ4QmN0YkhScXRNVmEzc216YmhMeUJBIiwiZmFtaWx5X25hbWUiLCJEdXBvbnQiXQ~WyJxRGZGbDlwc2FQOFZZc0tDblNvcDd3IiwiYmlydGhkYXRlIiwiMTk4MC0wNS0yMyJd~WyJQVjZsM2V3OWFJZkUyRnVzNEZmdGl3IiwiRlIiXQ~WyJXZVc3UU9UVUdzd3hGcEh0VE0xS2JnIiwibmF0aW9uYWxpdGllcyIsW3siLi4uIjoiOFBSZm92MlJUSGNYX1g4YWN3b1ZWV3Q4LWVfUWtUbnh0Z0h3c3dQNzd0SSJ9XV0~WyJubTBLc2pMQUt0Nm1kdWh0WDVoZE9nIiwiY291bnRyeSIsIkREIl0~WyJwQ2JLUllxTFkyRGQxeWVaLWowenB3IiwicGxhY2Vfb2ZfYmlydGgiLHsiX3NkIjpbInhmUVRHZFlLYnNrZExfZ1F2bGtCUDZRRk55bzhyUTJmWWxSc0x2MUN4YzAiXX1d~'
    const sampleKbJwt =
      'eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiLUx0R09tNFZKUk1YbEI2amNEQzlqMGU0QlBSeVdvbFlGdFNaNkZXeDdRTSIsImF1ZCI6Ing1MDlfc2FuX2RuczpweHY3Y2g5ci04MDgwLmFzc2UuZGV2dHVubmVscy5tcyIsImlhdCI6MTc2ODk2MzQzNSwibm9uY2UiOiIwN2NjNzhkZjAyOTI0MDI4OTk1ZDk0NTQ0ZDIyYjc1YiJ9.m0AVZJBNfmWWrmJieWThPRIe91JfNB4q7vmDZ7dHopsfNm7OatLQvGxZwMr3GTYv2-cczY8eZpA0Pe93lSv2lw'
    const sampleSdJwtVp = sampleSdJwt + sampleKbJwt

    const result = await provider.verify(sampleSdJwtVp, { kind: 'dc+sd-jwt', isKbJwt: true })
    assert.equal(result, true)
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
