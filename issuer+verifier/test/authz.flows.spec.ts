import assert from 'node:assert/strict'
import { beforeEach, describe, it, mock } from 'node:test'
import base64url from 'base64url'
import { generateKeyPair, SignJWT } from 'jose'
import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from '../src/authorization-server.types'
import { AuthzFlow, initializeAuthzFlow } from '../src/authz.flows'
import { PreAuthorizedCode } from '../src/pre-authorized-code.types'
import {
  AccessTokenProvider,
  AuthzServerMetadataStoreProvider,
  DPoPProofJtiStoreProvider,
  DPoPProofProvider,
  AuthzSignatureKeyStoreProvider,
  NonceProvider,
  NonceStoreProvider,
  PreAuthorizedCodeStoreProvider,
} from '../src/providers'
import { GrantType, TokenRequest, TokenResponse } from '../src/token-request.types'
import type { VcknotsContext } from '../src/vcknots.context'

describe('AuthzFlows', () => {
  let flow: AuthzFlow
  let mockContext: VcknotsContext

  const mockAuthzMetadataProvider = {
    kind: 'authz-server-metadata-store-provider',
    name: 'mock-authz-server-metadata-store-provider',
    single: true,
    fetch: mock.fn(),
    save: mock.fn(),
  } satisfies AuthzServerMetadataStoreProvider

  const mockCodeStoreProvider = {
    kind: 'pre-authorized-code-store-provider',
    name: 'mock-pre-authorized-code-store-provider',
    single: true,
    validate: mock.fn(),
    delete: mock.fn(),
    save: mock.fn(),
  } satisfies PreAuthorizedCodeStoreProvider

  const mockAccessTokenProvider = {
    kind: 'access-token-provider',
    name: 'mock-access-token-provider',
    single: true,
    createTokenPayload: mock.fn(),
  } satisfies AccessTokenProvider

  const mockAuthzKeyProvider = {
    kind: 'authz-signature-key-store-provider',
    name: 'mock-authz-signature-key-store-provider',
    single: true,
    fetch: mock.fn(),
    save: mock.fn(),
    sign: mock.fn(),
  } satisfies AuthzSignatureKeyStoreProvider

  const mockDpopProofProvider = {
    kind: 'dpop-proof-provider',
    name: 'mock-dpop-proof-provider',
    single: true,
    proofJtiTtlMs: 123_000,
    verifyProof: mock.fn(),
  } satisfies DPoPProofProvider

  const mockDpopProofJtiStoreProvider = {
    kind: 'dpop-proof-jti-store-provider',
    name: 'mock-dpop-proof-jti-store-provider',
    single: true,
    saveIfAbsent: mock.fn(),
  } satisfies DPoPProofJtiStoreProvider

  const mockNonceProvider = {
    kind: 'nonce-provider',
    name: 'mock-nonce-provider',
    single: true,
    generate: mock.fn(),
  } satisfies NonceProvider

  const mockNonceStoreProvider = {
    kind: 'nonce-store-provider',
    name: 'mock-nonce-store-provider',
    single: true,
    save: mock.fn(),
    validate: mock.fn(),
    revoke: mock.fn(),
    consume: mock.fn(),
  } satisfies NonceStoreProvider

  const sampleIssuer = AuthorizationServerIssuer('https://auth.example.com')
  const sampleMetadata: AuthorizationServerMetadata = {
    issuer: sampleIssuer,
    authorization_endpoint: 'https://auth.example.com/auth',
    token_endpoint: 'https://auth.example.com/token',
    response_types_supported: ['code'],
  }

  beforeEach(() => {
    mock.reset()

    mockContext = {
      providers: {
        get: mock.fn((kind: string) => {
          switch (kind) {
            case 'authz-server-metadata-store-provider':
              return mockAuthzMetadataProvider
            case 'pre-authorized-code-store-provider':
              return mockCodeStoreProvider
            case 'access-token-provider':
              return mockAccessTokenProvider
            case 'authz-signature-key-store-provider':
              return mockAuthzKeyProvider
            case 'dpop-proof-provider':
              return mockDpopProofProvider
            case 'dpop-proof-jti-store-provider':
              return mockDpopProofJtiStoreProvider
            case 'nonce-provider':
              return mockNonceProvider
            case 'nonce-store-provider':
              return mockNonceStoreProvider
            default:
              throw new Error(`Unexpected provider kind requested: ${kind}`)
          }
        }),
      },
    } as unknown as VcknotsContext

    flow = initializeAuthzFlow(mockContext)
  })

  describe('findAuthzServerMetadata()', () => {
    it('should call the authz-server-metadata-store-provider to fetch metadata', async () => {
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => sampleMetadata)
      const result = await flow.findAuthzServerMetadata(sampleIssuer)

      assert.strictEqual(mockAuthzMetadataProvider.fetch.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzMetadataProvider.fetch.mock.calls[0].arguments, [
        sampleIssuer,
      ])
      assert.deepStrictEqual(result, sampleMetadata)
    })
  })

  describe('createAuthzServerMetadata()', () => {
    it('should create metadata and initialize the authz signing key with the default algorithm', async () => {
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => null)
      mock.method(mockAuthzKeyProvider, 'save', async () => {})
      mock.method(mockAuthzMetadataProvider, 'save', async () => {})

      await flow.createAuthzServerMetadata(sampleMetadata)

      assert.strictEqual(mockAuthzMetadataProvider.fetch.mock.callCount(), 1)
      assert.strictEqual(mockAuthzKeyProvider.save.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzKeyProvider.save.mock.calls[0].arguments, [
        sampleMetadata.issuer,
        'ES256',
      ])
      assert.strictEqual(mockAuthzMetadataProvider.save.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzMetadataProvider.save.mock.calls[0].arguments, [
        sampleMetadata,
      ])
    })

    it('should pass the requested algorithm to the key store', async () => {
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => null)
      mock.method(mockAuthzKeyProvider, 'save', async () => {})
      mock.method(mockAuthzMetadataProvider, 'save', async () => {})

      await flow.createAuthzServerMetadata(sampleMetadata, { alg: 'ES256' })

      assert.deepStrictEqual(mockAuthzKeyProvider.save.mock.calls[0].arguments, [
        sampleMetadata.issuer,
        'ES256',
      ])
    })

    it('should throw when the issuer is already registered', async () => {
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => sampleMetadata)

      await assert.rejects(() => flow.createAuthzServerMetadata(sampleMetadata), {
        name: 'duplicate_authz_server',
      })
    })
  })

  describe('createDpopNonceChallenge()', () => {
    it('should generate and save a DPoP nonce challenge', async () => {
      mock.method(mockNonceProvider, 'generate', async () => ({
        nonce: 'generated-dpop-nonce',
        nonce_expires_in: 1234,
      }))
      mock.method(mockNonceStoreProvider, 'save', async () => {})

      const nonce = await flow.createDpopNonceChallenge(1234)

      assert.equal(nonce, 'generated-dpop-nonce')
      assert.deepStrictEqual(mockNonceProvider.generate.mock.calls[0].arguments, [
        { nonce_expires_in: 1234 },
      ])
      assert.deepStrictEqual(mockNonceStoreProvider.save.mock.calls[0].arguments, [
        {
          nonce: 'generated-dpop-nonce',
          nonce_expires_in: 1234,
        },
      ])
    })
  })

  describe('createAccessToken()', () => {
    const preAuthCode = PreAuthorizedCode('test-pre-auth-code')
    const tokenRequest: TokenRequest = {
      grant_type: GrantType.PreAuthorizedCode,
      'pre-authorized_code': preAuthCode,
    }
    const samplePayload = { iss: sampleIssuer, sub: preAuthCode }
    const sampleSignature = 'signed-jwt-signature-part'

    describe('Pre-Authorized Code Flow', () => {
      beforeEach(() => {
        mock.method(mockCodeStoreProvider, 'validate', async () => true)
        mock.method(mockCodeStoreProvider, 'delete', async () => {})
        mock.method(mockAuthzKeyProvider, 'sign', async () => sampleSignature)
        mock.method(mockAccessTokenProvider, 'createTokenPayload', async () => samplePayload)
        mock.method(mockDpopProofProvider, 'verifyProof', async () => ({
          jwkThumbprint: 'test-jkt',
          jti: 'test-jti',
          iat: Math.floor(Date.now() / 1000),
        }))
        mock.method(mockDpopProofJtiStoreProvider, 'saveIfAbsent', async () => true)
        mock.method(mockNonceStoreProvider, 'validate', async () => true)
        mock.method(mockNonceStoreProvider, 'revoke', async () => true)
        mock.method(mockNonceStoreProvider, 'consume', async () => true)
      })

      it('should successfully create an access token with default expiry', async () => {
        const response = (await flow.createAccessToken(sampleIssuer, tokenRequest)) as TokenResponse

        assert.strictEqual(mockCodeStoreProvider.validate.mock.callCount(), 1)
        assert.strictEqual(mockCodeStoreProvider.delete.mock.callCount(), 1)
        assert.strictEqual(mockAuthzKeyProvider.sign.mock.callCount(), 1)
        assert.strictEqual(mockAccessTokenProvider.createTokenPayload.mock.callCount(), 1)

        const encode = (x: unknown) => base64url.encode(JSON.stringify(x))
        const expectedHeader = { alg: 'ES256', typ: 'JWT' }
        const expectedAccessToken = `${encode(expectedHeader)}.${encode(
          samplePayload
        )}.${sampleSignature}`

        assert.strictEqual(response.access_token, expectedAccessToken)
        assert.strictEqual(response.token_type, 'bearer')
        assert.strictEqual(response.expires_in, 86400) // Default value
      })

      it('should use ttl from options when provided', async () => {
        const options = { ttlSec: 1800 }
        const response = (await flow.createAccessToken(
          sampleIssuer,
          tokenRequest,
          options
        )) as TokenResponse

        assert.strictEqual(response.expires_in, options.ttlSec)
      })

      it('should throw if pre-authorized code is invalid', async () => {
        mock.method(mockCodeStoreProvider, 'validate', async () => false)
        await assert.rejects(() => flow.createAccessToken(sampleIssuer, tokenRequest), {
          name: 'invalid_grant',
        })
      })

      it('should throw if signing returns null', async () => {
        mock.method(mockAuthzKeyProvider, 'sign', async () => null)
        await assert.rejects(() => flow.createAccessToken(sampleIssuer, tokenRequest), {
          name: 'internal_server_error',
        })
      })

      it('should bind access token to DPoP proof jwk thumbprint', async () => {
        const response = (await flow.createAccessToken(sampleIssuer, tokenRequest, {
          dpopProof: {
            proofJwt: 'aaa.bbb.ccc',
            htm: 'POST',
            htu: 'https://auth.example.com/token',
          },
        })) as TokenResponse

        assert.strictEqual(mockDpopProofProvider.verifyProof.mock.callCount(), 1)
        assert.deepStrictEqual(mockDpopProofJtiStoreProvider.saveIfAbsent.mock.calls[0].arguments, [
          'test-jkt',
          'test-jti',
          { ttlMs: mockDpopProofProvider.proofJtiTtlMs },
        ])
        assert.deepStrictEqual(
          mockAccessTokenProvider.createTokenPayload.mock.calls[0].arguments[2],
          {
            ttlSec: undefined,
            cnf: { jkt: 'test-jkt' },
          }
        )
        assert.strictEqual(response.token_type, 'DPoP')
      })

      it('should require nonce when DPoP proof nonce is required', async () => {
        await assert.rejects(
          () =>
            flow.createAccessToken(sampleIssuer, tokenRequest, {
              dpopProof: {
                proofJwt: 'aaa.bbb.ccc',
                htm: 'POST',
                htu: 'https://auth.example.com/token',
                nonceRequired: true,
              },
            }),
          {
            name: 'use_dpop_nonce',
            message: 'Authorization server requires nonce in DPoP proof.',
          }
        )
      })

      it('should reject invalid DPoP proof nonce when nonce is required', async () => {
        mock.method(mockDpopProofProvider, 'verifyProof', async () => ({
          jwkThumbprint: 'test-jkt',
          jti: 'test-jti',
          iat: Math.floor(Date.now() / 1000),
          nonce: 'invalid-nonce',
        }))
        mock.method(mockNonceStoreProvider, 'consume', async () => false)

        await assert.rejects(
          () =>
            flow.createAccessToken(sampleIssuer, tokenRequest, {
              dpopProof: {
                proofJwt: 'aaa.bbb.ccc',
                htm: 'POST',
                htu: 'https://auth.example.com/token',
                nonceRequired: true,
              },
            }),
          {
            name: 'use_dpop_nonce',
            message: 'Authorization server requires nonce in DPoP proof.',
          }
        )
      })

      it('should consume DPoP proof nonce when nonce is required', async () => {
        mock.method(mockDpopProofProvider, 'verifyProof', async () => ({
          jwkThumbprint: 'test-jkt',
          jti: 'test-jti',
          iat: Math.floor(Date.now() / 1000),
          nonce: 'valid-nonce',
        }))

        const response = (await flow.createAccessToken(sampleIssuer, tokenRequest, {
          dpopProof: {
            proofJwt: 'aaa.bbb.ccc',
            htm: 'POST',
            htu: 'https://auth.example.com/token',
            nonceRequired: true,
          },
        })) as TokenResponse

        assert.strictEqual(response.token_type, 'DPoP')
        assert.deepStrictEqual(mockNonceStoreProvider.consume.mock.calls[0].arguments, [
          { nonce: 'valid-nonce' },
        ])
        assert.strictEqual(mockNonceStoreProvider.validate.mock.callCount(), 0)
        assert.strictEqual(mockNonceStoreProvider.revoke.mock.callCount(), 0)
      })

      it('should reject reused DPoP proof jti', async () => {
        mock.method(mockDpopProofJtiStoreProvider, 'saveIfAbsent', async () => false)

        await assert.rejects(
          () =>
            flow.createAccessToken(sampleIssuer, tokenRequest, {
              dpopProof: {
                proofJwt: 'aaa.bbb.ccc',
                htm: 'POST',
                htu: 'https://auth.example.com/token',
              },
            }),
          {
            name: 'invalid_dpop_proof',
            message: 'DPoP proof JWT jti has already been used.',
          }
        )
      })
    })

    it('should throw if grant type is authorization_code', async () => {
      const authCodeTokenRequest: TokenRequest = {
        grant_type: GrantType.AuthorizationCode,
        code: 'some-auth-code',
      }
      await assert.rejects(() => flow.createAccessToken(sampleIssuer, authCodeTokenRequest), {
        name: 'unsupported_grant_type',
      })
    })

    it('should throw if grant type is not supported', async () => {
      const authCodeTokenRequest = {
        grant_type: 'unsupported_grant_type',
        code: 'some-auth-code',
      } as unknown as TokenRequest
      await assert.rejects(() => flow.createAccessToken(sampleIssuer, authCodeTokenRequest), {
        name: 'invalid_request',
      })
    })
  })

  describe('verifyAccessToken()', () => {
    it('should verify a valid access token', async () => {
      const keys = await generateKeyPair('ES256', { extractable: true })
      const accessToken = await new SignJWT({ iss: sampleIssuer })
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
        .sign(keys.privateKey)

      mock.method(mockAuthzKeyProvider, 'fetch', async () => keys.publicKey)

      const result = await flow.verifyAccessToken(sampleIssuer, accessToken)

      assert.strictEqual(result, true)
      assert.strictEqual(mockAuthzKeyProvider.fetch.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzKeyProvider.fetch.mock.calls[0].arguments, [
        sampleIssuer,
        'ES256',
      ])
    })

    it('should throw if authz issuer key is not found', async () => {
      const keys = await generateKeyPair('ES256', { extractable: true })
      const accessToken = await new SignJWT({ iss: sampleIssuer })
        .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
        .sign(keys.privateKey)

      mock.method(mockAuthzKeyProvider, 'fetch', async () => null)

      await assert.rejects(() => flow.verifyAccessToken(sampleIssuer, accessToken), {
        name: 'authz_issuer_key_not_found',
      })
    })

    it('should throw when access token is malformed', async () => {
      await assert.rejects(() => flow.verifyAccessToken(sampleIssuer, 'invalid-token'), {
        name: 'invalid_access_token',
      })
    })
  })
})
