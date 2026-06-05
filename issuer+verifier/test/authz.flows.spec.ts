import assert from 'node:assert/strict'
import { beforeEach, describe, it, mock } from 'node:test'
import base64url from 'base64url'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from '../src/authorization-server.types'
import { AuthzFlow, initializeAuthzFlow } from '../src/authz.flows'
import { AuthzOAuthClient } from '../src/authz-oauth-client.types'
import { AuthzOAuthPolicy } from '../src/authz-oauth-policy.types'
import { PreAuthorizedCode } from '../src/pre-authorized-code.types'
import {
  AccessTokenProvider,
  AuthzOAuthClientStoreProvider,
  AuthzOAuthPolicyStoreProvider,
  AuthzServerMetadataStoreProvider,
  DPoPProofJtiStoreProvider,
  DPoPProofProvider,
  OAuthClientAssertionJtiStoreProvider,
  AuthzSignatureKeyStoreProvider,
  NonceProvider,
  NonceStoreProvider,
  PreAuthorizedCodeStoreProvider,
  IssuanceContextStoreProvider,
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

  const mockAuthzOAuthPolicyStoreProvider = {
    kind: 'authz-oauth-policy-store-provider',
    name: 'mock-authz-oauth-policy-store-provider',
    single: true,
    fetch: mock.fn(),
    save: mock.fn(),
  } satisfies AuthzOAuthPolicyStoreProvider

  const mockAuthzOAuthClientStoreProvider = {
    kind: 'authz-oauth-client-store-provider',
    name: 'mock-authz-oauth-client-store-provider',
    single: true,
    fetch: mock.fn(),
    save: mock.fn(),
  } satisfies AuthzOAuthClientStoreProvider

  const mockCodeStoreProvider = {
    kind: 'pre-authorized-code-store-provider',
    name: 'mock-pre-authorized-code-store-provider',
    single: true,
    consume: mock.fn(),
    save: mock.fn(),
  } satisfies PreAuthorizedCodeStoreProvider

  const mockIssuanceContextStoreProvider = {
    kind: 'issuance-context-store-provider',
    name: 'mock-issuance-context-store-provider',
    single: true,
    save: mock.fn(),
    fetch: mock.fn(),
    delete: mock.fn(),
  } satisfies IssuanceContextStoreProvider

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

  const mockOAuthClientAssertionJtiStoreProvider = {
    kind: 'oauth-client-assertion-jti-store-provider',
    name: 'mock-oauth-client-assertion-jti-store-provider',
    single: true,
    saveIfAbsent: mock.fn(),
  } satisfies OAuthClientAssertionJtiStoreProvider

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
    token_endpoint_auth_methods_supported: ['private_key_jwt'],
    token_endpoint_auth_signing_alg_values_supported: ['ES256'],
  }
  const sampleOAuthPolicy = AuthzOAuthPolicy({
    default_client: {
      senderConstrainedAccessToken: {
        method: 'dpop',
        dpop: {
          mode: 'optional',
        },
      },
    },
    anonymous_client: {
      senderConstrainedAccessToken: {
        method: 'dpop',
        dpop: {
          mode: 'required',
        },
      },
    },
  })

  beforeEach(() => {
    mock.reset()

    mockContext = {
      providers: {
        get: mock.fn((kind: string) => {
          switch (kind) {
            case 'authz-server-metadata-store-provider':
              return mockAuthzMetadataProvider
            case 'authz-oauth-policy-store-provider':
              return mockAuthzOAuthPolicyStoreProvider
            case 'authz-oauth-client-store-provider':
              return mockAuthzOAuthClientStoreProvider
            case 'pre-authorized-code-store-provider':
              return mockCodeStoreProvider
            case 'issuance-context-store-provider':
              return mockIssuanceContextStoreProvider
            case 'access-token-provider':
              return mockAccessTokenProvider
            case 'authz-signature-key-store-provider':
              return mockAuthzKeyProvider
            case 'dpop-proof-provider':
              return mockDpopProofProvider
            case 'dpop-proof-jti-store-provider':
              return mockDpopProofJtiStoreProvider
            case 'oauth-client-assertion-jti-store-provider':
              return mockOAuthClientAssertionJtiStoreProvider
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

  describe('findAuthzOAuthPolicy()', () => {
    it('should call the authz-oauth-policy-store-provider to fetch policy', async () => {
      mock.method(mockAuthzOAuthPolicyStoreProvider, 'fetch', async () => sampleOAuthPolicy)

      const result = await flow.findAuthzOAuthPolicy(sampleIssuer)

      assert.strictEqual(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzOAuthPolicyStoreProvider.fetch.mock.calls[0].arguments, [
        sampleIssuer,
      ])
      assert.deepStrictEqual(result, sampleOAuthPolicy)
    })
  })

  describe('createAuthzOAuthPolicy()', () => {
    it('should call the authz-oauth-policy-store-provider to save policy by issuer', async () => {
      mock.method(mockAuthzOAuthPolicyStoreProvider, 'save', async () => {})

      await flow.createAuthzOAuthPolicy(sampleIssuer, sampleOAuthPolicy)

      assert.strictEqual(mockAuthzOAuthPolicyStoreProvider.save.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzOAuthPolicyStoreProvider.save.mock.calls[0].arguments, [
        sampleIssuer,
        sampleOAuthPolicy,
      ])
    })
  })

  describe('findAuthzOAuthClient()', () => {
    it('should call the authz-oauth-client-store-provider to fetch client by issuer and client id', async () => {
      const sampleClient = AuthzOAuthClient({
        client_id: 'wallet-client',
        token_endpoint_auth_method: 'none',
        enabled: true,
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)

      const result = await flow.findAuthzOAuthClient(sampleIssuer, sampleClient.client_id)

      assert.strictEqual(mockAuthzOAuthClientStoreProvider.fetch.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzOAuthClientStoreProvider.fetch.mock.calls[0].arguments, [
        sampleIssuer,
        sampleClient.client_id,
      ])
      assert.deepStrictEqual(result, sampleClient)
    })
  })

  describe('createAuthzOAuthClient()', () => {
    it('should call the authz-oauth-client-store-provider to save client by issuer', async () => {
      const sampleClient = AuthzOAuthClient({
        client_id: 'wallet-client',
        token_endpoint_auth_method: 'none',
        enabled: true,
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'save', async () => {})

      await flow.createAuthzOAuthClient(sampleIssuer, sampleClient)

      assert.strictEqual(mockAuthzOAuthClientStoreProvider.save.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzOAuthClientStoreProvider.save.mock.calls[0].arguments, [
        sampleIssuer,
        sampleClient,
      ])
    })
  })

  describe('resolveAuthzPolicyDpopMode()', () => {
    it('should resolve DPoP mode from the requested policy client kind', async () => {
      mock.method(mockAuthzOAuthPolicyStoreProvider, 'fetch', async () => sampleOAuthPolicy)

      const result = await flow.resolveAuthzPolicyDpopMode(sampleIssuer, 'anonymous_client')

      assert.equal(result, 'required')
      assert.deepStrictEqual(mockAuthzOAuthPolicyStoreProvider.fetch.mock.calls[0].arguments, [
        sampleIssuer,
      ])
    })

    it('should let a client policy override the authorization server default policy', async () => {
      mock.method(mockAuthzOAuthPolicyStoreProvider, 'fetch', async () => sampleOAuthPolicy)

      const result = await flow.resolveAuthzPolicyDpopMode(sampleIssuer, 'default_client', {
        senderConstrainedAccessToken: {
          method: 'dpop',
          dpop: { mode: 'required' },
        },
      })

      assert.equal(result, 'required')
    })

    it('should default to off when no sender constraint policy exists', async () => {
      mock.method(mockAuthzOAuthPolicyStoreProvider, 'fetch', async () => null)

      const result = await flow.resolveAuthzPolicyDpopMode(sampleIssuer, 'default_client')

      assert.equal(result, 'off')
    })
  })

  describe('resolveTokenRequestClientPolicy()', () => {
    const signedPrivateKeyJwt = async (
      clientId: string,
      options?: { audience?: string; alg?: string; kid?: string; iat?: number | null; nbf?: number }
    ) => {
      const alg = options?.alg ?? 'ES256'
      const kid = options?.kid ?? 'client-key-1'
      const keys = await generateKeyPair(alg, { extractable: true })
      const jwk = await exportJWK(keys.publicKey)
      const publicJwk = { ...jwk, kid, alg, use: 'sig' }
      let assertionBuilder = new SignJWT({ iss: clientId, sub: clientId })
        .setProtectedHeader({ alg, kid })
        .setAudience(options?.audience ?? sampleMetadata.token_endpoint)
        .setExpirationTime('5m')
        .setJti('client-assertion-jti')

      if (options?.iat !== null) {
        assertionBuilder =
          typeof options?.iat === 'number'
            ? assertionBuilder.setIssuedAt(options.iat)
            : assertionBuilder.setIssuedAt()
      }
      if (typeof options?.nbf === 'number') {
        assertionBuilder = assertionBuilder.setNotBefore(options.nbf)
      }

      const assertion = await assertionBuilder.sign(keys.privateKey)

      return { assertion, publicJwk }
    }

    it('should use the anonymous client policy when client_id and client_assertion are missing', async () => {
      mock.method(mockAuthzOAuthPolicyStoreProvider, 'fetch', async () => sampleOAuthPolicy)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {})

      assert.deepStrictEqual(result, {
        ok: true,
        clientKind: 'anonymous_client',
        dpopMode: 'required',
      })
      assert.equal(mockAuthzOAuthClientStoreProvider.fetch.mock.callCount(), 0)
    })

    it('should reject an unknown registered client id', async () => {
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => null)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_id: 'unknown-client',
      })

      assert.deepStrictEqual(result, {
        ok: false,
        error: 'invalid_client',
        error_description: 'Registered OAuth client was not found.',
        clientId: 'unknown-client',
      })
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
    })

    it('should use a registered client sender constraint when configured', async () => {
      const sampleClient = AuthzOAuthClient({
        client_id: 'wallet-client',
        token_endpoint_auth_method: 'none',
        senderConstrainedAccessToken: {
          method: 'dpop',
          dpop: { mode: 'required' },
        },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)
      mock.method(mockAuthzOAuthPolicyStoreProvider, 'fetch', async () => sampleOAuthPolicy)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_id: sampleClient.client_id,
      })

      assert.deepStrictEqual(result, {
        ok: true,
        clientKind: 'default_client',
        clientId: sampleClient.client_id,
        clientPolicy: {
          senderConstrainedAccessToken: sampleClient.senderConstrainedAccessToken,
        },
        dpopMode: 'required',
      })
    })

    it('should use the default client policy when the registered client has no sender constraint', async () => {
      const sampleClient = AuthzOAuthClient({
        client_id: 'wallet-client',
        token_endpoint_auth_method: 'none',
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)
      mock.method(mockAuthzOAuthPolicyStoreProvider, 'fetch', async () => sampleOAuthPolicy)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_id: sampleClient.client_id,
      })

      assert.deepStrictEqual(result, {
        ok: true,
        clientKind: 'default_client',
        clientId: sampleClient.client_id,
        clientPolicy: undefined,
        dpopMode: 'optional',
      })
    })

    it('should extract client_id from private_key_jwt client_assertion iss/sub', async () => {
      const { assertion, publicJwk } = await signedPrivateKeyJwt('private-key-client')
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [publicJwk] },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => ({
        ...sampleMetadata,
        token_endpoint_auth_signing_alg_values_supported: ['ES256'],
      }))
      mock.method(mockAuthzOAuthPolicyStoreProvider, 'fetch', async () => sampleOAuthPolicy)
      mock.method(mockOAuthClientAssertionJtiStoreProvider, 'saveIfAbsent', async () => true)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      })

      assert.equal(mockAuthzOAuthClientStoreProvider.fetch.mock.callCount(), 1)
      assert.deepStrictEqual(mockAuthzOAuthClientStoreProvider.fetch.mock.calls[0].arguments, [
        sampleIssuer,
        sampleClient.client_id,
      ])
      assert.deepStrictEqual(result, {
        ok: true,
        clientKind: 'default_client',
        clientId: sampleClient.client_id,
        clientPolicy: undefined,
        dpopMode: 'optional',
      })
      assert.equal(mockOAuthClientAssertionJtiStoreProvider.saveIfAbsent.mock.callCount(), 1)
      const saveArgs = mockOAuthClientAssertionJtiStoreProvider.saveIfAbsent.mock.calls[0].arguments
      assert.equal(saveArgs[0], sampleClient.client_id)
      assert.equal(saveArgs[1], 'client-assertion-jti')
      assert.ok((saveArgs[2] as { ttlMs: number }).ttlMs > 0)
    })

    it('should reject private_key_jwt clients when the assertion signature is invalid', async () => {
      const { assertion } = await signedPrivateKeyJwt('private-key-client')
      const { publicJwk } = await signedPrivateKeyJwt('private-key-client')
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [publicJwk] },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => sampleMetadata)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      })

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.equal(result.error, 'invalid_client')
        assert.equal(result.error_description, 'client_assertion verification failed.')
        assert.equal(result.clientId, sampleClient.client_id)
      }
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
      assert.equal(mockOAuthClientAssertionJtiStoreProvider.saveIfAbsent.mock.callCount(), 0)
    })

    it('should reject private_key_jwt clients when alg is not supported by metadata', async () => {
      const { assertion, publicJwk } = await signedPrivateKeyJwt('private-key-client')
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [publicJwk] },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => ({
        ...sampleMetadata,
        token_endpoint_auth_signing_alg_values_supported: ['RS256'],
      }))

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      })

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.equal(result.error, 'invalid_client')
        assert.equal(
          result.error_description,
          'client_assertion alg is not supported by the authorization server metadata.'
        )
        assert.equal(result.clientId, sampleClient.client_id)
        assert.deepStrictEqual(result.log, {
          clientId: sampleClient.client_id,
          alg: 'ES256',
          supportedAlgs: ['RS256'],
        })
      }
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
      assert.equal(mockOAuthClientAssertionJtiStoreProvider.saveIfAbsent.mock.callCount(), 0)
    })

    it('should reject private_key_jwt clients when metadata does not advertise private_key_jwt', async () => {
      const { assertion, publicJwk } = await signedPrivateKeyJwt('private-key-client')
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [publicJwk] },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => ({
        ...sampleMetadata,
        token_endpoint_auth_methods_supported: ['client_secret_post'],
      }))

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      })

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.equal(result.error, 'invalid_client')
        assert.equal(
          result.error_description,
          'authorization server metadata must include private_key_jwt in token_endpoint_auth_methods_supported for private_key_jwt client authentication.'
        )
        assert.equal(result.clientId, sampleClient.client_id)
        assert.deepStrictEqual(result.log, {
          clientId: sampleClient.client_id,
          supportedAuthMethods: ['client_secret_post'],
        })
      }
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
      assert.equal(mockOAuthClientAssertionJtiStoreProvider.saveIfAbsent.mock.callCount(), 0)
    })

    it('should reject private_key_jwt clients when metadata does not declare signing algs', async () => {
      const { assertion, publicJwk } = await signedPrivateKeyJwt('private-key-client')
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [publicJwk] },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => ({
        ...sampleMetadata,
        token_endpoint_auth_signing_alg_values_supported: undefined,
      }))

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      })

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.equal(result.error, 'invalid_client')
        assert.equal(
          result.error_description,
          'authorization server metadata must include token_endpoint_auth_signing_alg_values_supported for private_key_jwt client authentication.'
        )
        assert.equal(result.clientId, sampleClient.client_id)
        assert.deepStrictEqual(result.log, {
          clientId: sampleClient.client_id,
        })
      }
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
      assert.equal(mockOAuthClientAssertionJtiStoreProvider.saveIfAbsent.mock.callCount(), 0)
    })

    it('should include configured client_assertion_audience when private_key_jwt aud mismatches', async () => {
      const expectedAudience = 'https://auth.example.com/custom-token-audience'
      const { assertion, publicJwk } = await signedPrivateKeyJwt('private-key-client', {
        audience: sampleMetadata.token_endpoint,
      })
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        client_assertion_audience: expectedAudience,
        jwks: { keys: [publicJwk] },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => sampleMetadata)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      })

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.equal(result.error, 'invalid_client')
        assert.equal(
          result.error_description,
          `client_assertion aud claim does not match registered client_assertion_audience setting (${expectedAudience}).`
        )
        assert.equal(result.clientId, sampleClient.client_id)
        assert.deepStrictEqual(result.log?.expectedAudiences, [expectedAudience])
      }
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
      assert.equal(mockOAuthClientAssertionJtiStoreProvider.saveIfAbsent.mock.callCount(), 0)
    })

    it('should reject private_key_jwt clients when iat is missing', async () => {
      const { assertion, publicJwk } = await signedPrivateKeyJwt('private-key-client', {
        iat: null,
      })
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [publicJwk] },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      })

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.equal(result.error, 'invalid_client')
        assert.equal(result.error_description, 'client_assertion iat claim is required.')
        assert.equal(result.clientId, sampleClient.client_id)
      }
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
      assert.equal(mockOAuthClientAssertionJtiStoreProvider.saveIfAbsent.mock.callCount(), 0)
    })

    it('should reject private_key_jwt clients when iat is too far in the future', async () => {
      const now = Math.floor(Date.now() / 1000)
      const { assertion, publicJwk } = await signedPrivateKeyJwt('private-key-client', {
        iat: now + 60,
      })
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [publicJwk] },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      })

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.equal(result.error, 'invalid_client')
        assert.equal(
          result.error_description,
          'client_assertion iat claim is too far in the future.'
        )
        assert.equal(result.clientId, sampleClient.client_id)
        assert.equal(result.log?.clockToleranceSeconds, 10)
      }
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
      assert.equal(mockOAuthClientAssertionJtiStoreProvider.saveIfAbsent.mock.callCount(), 0)
    })

    it('should reject private_key_jwt clients when nbf is too far in the future', async () => {
      const now = Math.floor(Date.now() / 1000)
      const { assertion, publicJwk } = await signedPrivateKeyJwt('private-key-client', {
        nbf: now + 60,
      })
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [publicJwk] },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      })

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.equal(result.error, 'invalid_client')
        assert.equal(
          result.error_description,
          'client_assertion nbf claim is too far in the future.'
        )
        assert.equal(result.clientId, sampleClient.client_id)
        assert.equal(result.log?.clockToleranceSeconds, 10)
      }
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
      assert.equal(mockOAuthClientAssertionJtiStoreProvider.saveIfAbsent.mock.callCount(), 0)
    })

    it('should reject private_key_jwt clients when assertion jti was already used', async () => {
      const { assertion, publicJwk } = await signedPrivateKeyJwt('private-key-client')
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'ES256',
        jwks: { keys: [publicJwk] },
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)
      mock.method(mockAuthzMetadataProvider, 'fetch', async () => sampleMetadata)
      mock.method(mockOAuthClientAssertionJtiStoreProvider, 'saveIfAbsent', async () => false)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_assertion_type:
          'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
      })

      assert.deepStrictEqual(result, {
        ok: false,
        error: 'invalid_client',
        error_description: 'client_assertion jti has already been used.',
        clientId: sampleClient.client_id,
        log: {
          clientId: sampleClient.client_id,
          jti: 'client-assertion-jti',
        },
      })
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
    })

    it('should reject private_key_jwt clients when assertion parameters are missing', async () => {
      const sampleClient = AuthzOAuthClient({
        client_id: 'private-key-client',
        token_endpoint_auth_method: 'private_key_jwt',
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_id: sampleClient.client_id,
      })

      assert.deepStrictEqual(result, {
        ok: false,
        error: 'invalid_client',
        error_description:
          'client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer for private_key_jwt client authentication.',
        clientId: sampleClient.client_id,
        log: {
          clientId: sampleClient.client_id,
          tokenEndpointAuthMethod: 'private_key_jwt',
          hasClientAssertionType: false,
          hasClientAssertion: false,
        },
      })
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
    })

    it('should reject registered clients with unsupported client authentication methods', async () => {
      const sampleClient = AuthzOAuthClient({
        client_id: 'secret-client',
        token_endpoint_auth_method: 'client_secret_post',
      })
      mock.method(mockAuthzOAuthClientStoreProvider, 'fetch', async () => sampleClient)

      const result = await flow.resolveTokenRequestClientPolicy(sampleIssuer, {
        client_id: sampleClient.client_id,
      })

      assert.deepStrictEqual(result, {
        ok: false,
        error: 'invalid_client',
        error_description: 'client_secret_post client authentication is not implemented yet.',
        clientId: sampleClient.client_id,
        log: {
          clientId: sampleClient.client_id,
          tokenEndpointAuthMethod: 'client_secret_post',
        },
      })
      assert.equal(mockAuthzOAuthPolicyStoreProvider.fetch.mock.callCount(), 0)
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
    const samplePayload = { iss: sampleIssuer, sub: preAuthCode, jti: 'test-jti' }
    const sampleSignature = 'signed-jwt-signature-part'

    describe('Pre-Authorized Code Flow', () => {
      beforeEach(() => {
        mock.method(mockCodeStoreProvider, 'consume', async () => ['test-credential-config-id'])
        mock.method(mockIssuanceContextStoreProvider, 'save', async () => {})
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

        assert.strictEqual(mockCodeStoreProvider.consume.mock.callCount(), 1)
        assert.strictEqual(mockIssuanceContextStoreProvider.save.mock.callCount(), 1)
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

      it('should pass verified client_id into access token payload options', async () => {
        await flow.createAccessToken(sampleIssuer, tokenRequest, {
          clientId: 'wallet-client',
        })

        const payloadOptions =
          mockAccessTokenProvider.createTokenPayload.mock.calls[0].arguments[2]
        assert.strictEqual(payloadOptions.ttlSec, undefined)
        assert.strictEqual(payloadOptions.clientId, 'wallet-client')
        assert.strictEqual(typeof payloadOptions.jti, 'string')
      })

      it('should throw if pre-authorized code is invalid', async () => {
        mock.method(mockCodeStoreProvider, 'consume', async () => null)
        await assert.rejects(() => flow.createAccessToken(sampleIssuer, tokenRequest), {
          name: 'invalid_grant',
        })
      })

      it('should throw invalid_grant when no credential configurations are found for the pre-authorized code', async () => {
        mock.method(mockCodeStoreProvider, 'consume', async () => null)

        await assert.rejects(() => flow.createAccessToken(sampleIssuer, tokenRequest), {
          name: 'invalid_grant',
          message:
            'The provided pre-authorized code is invalid or no credential configurations were found for the provided pre-authorized code.',
        })

        assert.strictEqual(mockCodeStoreProvider.consume.mock.callCount(), 1)
        assert.strictEqual(mockIssuanceContextStoreProvider.save.mock.callCount(), 0)
        assert.strictEqual(mockAccessTokenProvider.createTokenPayload.mock.callCount(), 0)
        assert.strictEqual(mockAuthzKeyProvider.sign.mock.callCount(), 0)
      })

      it('should use the same generated jti for issuance context and access token payload', async () => {
        mock.method(
          mockAccessTokenProvider,
          'createTokenPayload',
          async (
            _authz: AuthorizationServerIssuer,
            _code: PreAuthorizedCode,
            options: { jti?: string }
          ) => ({
            iss: sampleIssuer,
            sub: preAuthCode,
            jti: options?.jti,
          })
        )

        const response = (await flow.createAccessToken(sampleIssuer, tokenRequest)) as TokenResponse

        assert.strictEqual(mockIssuanceContextStoreProvider.save.mock.callCount(), 1)
        assert.strictEqual(mockAccessTokenProvider.createTokenPayload.mock.callCount(), 1)

        const savedJti = mockIssuanceContextStoreProvider.save.mock.calls[0].arguments[0]
        const payloadOptions = mockAccessTokenProvider.createTokenPayload.mock.calls[0].arguments[2]

        assert.strictEqual(typeof savedJti, 'string')
        assert.ok(savedJti.length > 0)
        assert.strictEqual(payloadOptions?.jti, savedJti)

        const [, encodedPayload] = response.access_token.split('.')
        const decodedPayload = JSON.parse(base64url.decode(encodedPayload))

        assert.strictEqual(decodedPayload.jti, savedJti)
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
        const payload = mockAccessTokenProvider.createTokenPayload.mock.calls[0].arguments[2]
        assert.deepStrictEqual(payload?.cnf, { jkt: 'test-jkt' })
        assert.strictEqual(payload.ttlSec, undefined)
        assert.strictEqual(typeof payload?.jti, 'string')
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
