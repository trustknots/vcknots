import assert from 'node:assert/strict'
import { beforeEach, describe, it, mock } from 'node:test'
import base64url from 'base64url'
import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from '../src/authorization-server.types'
import { AuthzFlow, initializeAuthzFlow } from '../src/authz.flows'
import { Cnonce } from '../src/cnonce.types'
import { PreAuthorizedCode } from '../src/pre-authorized-code.types'
import {
  AccessTokenProvider,
  AuthzServerMetadataStoreProvider,
  AuthzSignatureKeyProvider,
  AuthzSignatureKeyStoreProvider,
  CnonceProvider,
  CnonceStoreProvider,
  PreAuthorizedCodeStoreProvider,
} from '../src/providers'
import { GrantType, TokenRequest, TokenResponse } from '../src/token-request.types'
import type { VcknotsContext } from '../src/vcknots.context'

describe('AuthzFlows', () => {
  let flow: AuthzFlow
  let mockContext: VcknotsContext

  // --- Mock Providers ---
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

  const mockCnonceProvider = {
    kind: 'cnonce-provider',
    name: 'mock-cnonce-provider',
    single: true,
    generate: mock.fn(),
  } satisfies CnonceProvider

  const mockCnonceStoreProvider = {
    kind: 'cnonce-store-provider',
    name: 'mock-cnonce-store-provider',
    single: true,
    revoke: mock.fn(),
    validate: mock.fn(),
    save: mock.fn(),
  } satisfies CnonceStoreProvider

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
  } satisfies AuthzSignatureKeyStoreProvider

  const mockAuthzSignatureKeyProvider = {
    kind: 'authz-signature-key-provider',
    name: 'mock-authz-signature-key-provider',
    single: false,
    sign: mock.fn(),
    canHandle: mock.fn(),
    generate: mock.fn(),
  } satisfies AuthzSignatureKeyProvider

  // --- Test Data ---
  const sampleIssuer = AuthorizationServerIssuer('https://auth.example.com')
  const sampleMetadata: AuthorizationServerMetadata = {
    issuer: sampleIssuer,
    authorization_endpoint: 'https://auth.example.com/auth',
    token_endpoint: 'https://auth.example.com/token',
    response_types_supported: ['code'],
  }

  beforeEach(() => {
    mock.reset() // Reset all mocks before each test

    // Setup mock context to return mock providers
    mockContext = {
      providers: {
        get: mock.fn((kind: string) => {
          switch (kind) {
            case 'authz-server-metadata-store-provider':
              return mockAuthzMetadataProvider
            case 'pre-authorized-code-store-provider':
              return mockCodeStoreProvider
            case 'cnonce-provider':
              return mockCnonceProvider
            case 'cnonce-store-provider':
              return mockCnonceStoreProvider
            case 'access-token-provider':
              return mockAccessTokenProvider
            case 'authz-signature-key-store-provider':
              return mockAuthzKeyProvider
            case 'authz-signature-key-provider':
              // The implementation filters an array of providers
              return [mockAuthzSignatureKeyProvider]
            default:
              throw new Error(`Unexpected provider kind requested: ${kind}`)
          }
        }),
      },
    } as unknown as VcknotsContext // Use cast to simplify mock setup

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
    it('should create metadata, generate and save a key pair', async () => {
      const sampleKeyPair = {
        privateJwk: { kty: 'EC', crv: 'P-256', d: 'private-d-value', alg: 'ES256' },
        publicJwk: {
          kty: 'EC',
          crv: 'P-256',
          x: 'public-x-value',
          y: 'public-y-value',
          alg: 'ES256',
        },
      }
      // Arrange: Mock the methods that will be called in the flow
      mock.method(mockAuthzSignatureKeyProvider, 'canHandle', async () => true)
      mock.method(mockAuthzSignatureKeyProvider, 'generate', async () => sampleKeyPair)
      mock.method(mockAuthzKeyProvider, 'save', async () => {})
      mock.method(mockAuthzMetadataProvider, 'save', async () => {})

      // Act: Run the function to be tested
      await flow.createAuthzServerMetadata(sampleMetadata)

      // Assert: Verify that all expected methods were called correctly
      // 1. A key pair is generated
      assert.strictEqual(mockAuthzSignatureKeyProvider.generate.mock.callCount(), 1)

      // 2. The key pair is saved to the key store
      assert.strictEqual(mockAuthzKeyProvider.save.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzKeyProvider.save.mock.calls[0].arguments, [
        sampleMetadata.issuer,
        sampleKeyPair,
      ])

      // 3. The metadata is saved
      assert.strictEqual(mockAuthzMetadataProvider.save.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzMetadataProvider.save.mock.calls[0].arguments, [
        sampleMetadata,
      ])
    })

    it('should throw if authorization server private key algorithm is not supported', async () => {
      // canHandle is undefined
      await assert.rejects(flow.createAuthzServerMetadata(sampleMetadata), {
        name: 'PROVIDER_NOT_FOUND',
      })
    })
  })

  describe('createAccessToken()', () => {
    const preAuthCode = PreAuthorizedCode('test-pre-auth-code')
    const tokenRequest: TokenRequest = {
      grant_type: GrantType.PreAuthorizedCode,
      'pre-authorized_code': preAuthCode,
    }
    const privateKey = { kty: 'EC', crv: 'P-256', alg: 'ES256', d: 'private-d-value' }
    const samplePayload = { iss: sampleIssuer, sub: preAuthCode }
    const sampleSignature = 'signed-jwt-signature-part'
    const sampleCnonce = Cnonce('test-cnonce-value')

    describe('Pre-Authorized Code Flow', () => {
      beforeEach(() => {
        // Setup mocks for a successful path
        mock.method(mockCodeStoreProvider, 'validate', async () => true)
        mock.method(mockAuthzKeyProvider, 'fetch', async () => ({
          privateKey: privateKey,
          publicKey: {},
        }))
        mock.method(mockAuthzSignatureKeyProvider, 'canHandle', async () => true)
        mock.method(mockAuthzSignatureKeyProvider, 'sign', async () => sampleSignature)
        mock.method(mockAccessTokenProvider, 'createTokenPayload', () => samplePayload)
        mock.method(mockCnonceProvider, 'generate', async () => sampleCnonce)
      })

      it('should successfully create an access token with default expiry', async () => {
        const response = (await flow.createAccessToken(sampleIssuer, tokenRequest)) as TokenResponse

        assert.strictEqual(mockCodeStoreProvider.validate.mock.callCount(), 1)
        assert.strictEqual(mockCodeStoreProvider.delete.mock.callCount(), 1)
        assert.strictEqual(mockAuthzKeyProvider.fetch.mock.callCount(), 1)
        assert.strictEqual(mockAuthzSignatureKeyProvider.canHandle.mock.callCount(), 1)
        assert.strictEqual(mockAuthzSignatureKeyProvider.sign.mock.callCount(), 1)
        assert.strictEqual(mockAccessTokenProvider.createTokenPayload.mock.callCount(), 1)
        assert.strictEqual(mockCnonceProvider.generate.mock.callCount(), 1)
        assert.strictEqual(mockCnonceStoreProvider.save.mock.callCount(), 1)

        const encode = (x: unknown) => base64url.encode(JSON.stringify(x))
        const expectedHeader = { alg: privateKey.alg, typ: 'JWT' }
        const expectedAccessToken = `${encode(expectedHeader)}.${encode(
          samplePayload
        )}.${sampleSignature}`

        assert.strictEqual(response.access_token, expectedAccessToken)
        assert.strictEqual(response.token_type, 'bearer')
        assert.strictEqual(response.c_nonce, sampleCnonce)
        assert.strictEqual(response.expires_in, 86400) // Default value
        assert.strictEqual(response.c_nonce_expires_in, 300000) // Default value (5 minutes)
      })

      it('should use ttl and c_nonce_expires_in from options when provided', async () => {
        const options = { ttlSec: 1800, c_nonce_expire_in: 60000 }
        const response = (await flow.createAccessToken(
          sampleIssuer,
          tokenRequest,
          options
        )) as TokenResponse

        assert.strictEqual(response.expires_in, options.ttlSec)
        assert.strictEqual(response.c_nonce_expires_in, options.c_nonce_expire_in)
      })

      it('should throw if pre-authorized code is invalid', async () => {
        mock.method(mockCodeStoreProvider, 'validate', async () => false)
        await assert.rejects(flow.createAccessToken(sampleIssuer, tokenRequest), {
          name: 'PRE_AUTHORIZED_CODE_NOT_FOUND',
        })
      })

      it('should throw if authz key is not found', async () => {
        mock.method(mockAuthzKeyProvider, 'fetch', async () => undefined)
        await assert.rejects(flow.createAccessToken(sampleIssuer, tokenRequest), {
          name: 'INVALID_REQUEST',
        })
      })

      it('should throw if privateKey is not found', async () => {
        mock.method(mockAuthzKeyProvider, 'fetch', async () => ({
          privateJwk: undefined,
        }))
        await assert.rejects(flow.createAccessToken(sampleIssuer, tokenRequest), {
          name: 'INVALID_REQUEST',
        })
      })

      it('should throw if privateKey algorithm is not found', async () => {
        const privateJwkWithoutAlg = { ...privateKey, alg: undefined }
        mock.method(mockAuthzKeyProvider, 'fetch', async () => ({
          publicJwk: {},
          privateJwk: privateJwkWithoutAlg,
        }))
        await assert.rejects(flow.createAccessToken(sampleIssuer, tokenRequest), {
          name: 'INVALID_REQUEST',
        })
      })

      it('should throw if no signature provider can handle the key algorithm', async () => {
        mockAuthzSignatureKeyProvider.canHandle.mock.mockImplementation(() => false)
        await assert.rejects(flow.createAccessToken(sampleIssuer, tokenRequest), {
          name: 'PROVIDER_NOT_FOUND',
        })
      })
    })

    it('should throw if grant type is authorization_code', async () => {
      const authCodeTokenRequest: TokenRequest = {
        grant_type: GrantType.AuthorizationCode,
        code: 'some-auth-code',
      }
      await assert.rejects(flow.createAccessToken(sampleIssuer, authCodeTokenRequest), {
        name: 'FEATURE_NOT_IMPLEMENTED_YET',
      })
    })

    it('should throw if grant type is not supported', async () => {
      const authCodeTokenRequest: TokenRequest = {
        grant_type: 'unsupported_grant_type', // actually unsupported grant type is guard by enum
        code: 'some-auth-code',
      } as unknown as TokenRequest
      await assert.rejects(flow.createAccessToken(sampleIssuer, authCodeTokenRequest), {
        name: 'INVALID_REQUEST',
      })
    })
  })
})
