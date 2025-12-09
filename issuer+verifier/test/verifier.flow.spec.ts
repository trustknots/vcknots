import assert from 'node:assert/strict'
import { before, beforeEach, describe, it, mock } from 'node:test'
import { AuthorizationRequest } from '../src/authorization-request.types'
import { AuthorizationResponse } from '../src/authorization-response.types'
import { ClientId } from '../src/client-id.types'
import { Dcql } from '../src/dcql.type'
import { PresentationExchange } from '../src/presentation-exchange.types'
import {
  CnonceProvider,
  CnonceStoreProvider,
  CredentialProvider,
  CredentialQueryGenerationOptions,
  CredentialQueryProvider,
  DidProvider,
  HolderBindingProvider,
  JwtSignatureProvider,
  RequestObjectIdProvider,
  RequestObjectStoreProvider,
  VerifierMetadataStoreProvider,
  VerifierSignatureKeyProvider,
  VerifierSignatureKeyStoreProvider,
} from '../src/providers'
import { VcknotsContext, initializeContext } from '../src/vcknots.context'
import { VerifierMetadata } from '../src/verifier-metadata.types'
import { VerifierFlow, initializeVerifierFlow } from '../src/verifier.flows'
import { TransactionDataProvider } from '../src/providers'
import base64url from 'base64url'

type JwtHeader = {
  alg: string
  typ?: string
  kid?: string
}

type JwtPayload = {
  [key: string]: unknown
}

const b64u = (obj: Record<string, unknown>) =>
  Buffer.from(JSON.stringify(obj)).toString('base64url')

const makeJwt = (header: JwtHeader, payload: JwtPayload) => `${b64u(header)}.${b64u(payload)}.sig`

// a minimal VC payload that parseVerifiableCredentialBase() should accept
const minimalVc = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  issuer: 'https://example.com',
  issuanceDate: '2024-01-01T00:00:00Z',
}

describe('VerifierFlow', () => {
  let context: VcknotsContext
  let verifierFlow: VerifierFlow

  const mockVerifierMetadataStore = {
    kind: 'verifier-metadata-store-provider',
    name: 'mock-verifier-metadata-store-provider',
    single: true,
    save: mock.fn(),
    fetch: mock.fn(),
  } satisfies VerifierMetadataStoreProvider

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
    save: mock.fn(),
    validate: mock.fn(),
    revoke: mock.fn(),
  } satisfies CnonceStoreProvider

  const mockCredentialQueryProvider = {
    kind: 'credential-query-provider',
    name: 'mock-credential-query-provider',
    single: false,
    generate: mock.fn(),
    canHandle: mock.fn(),
  } satisfies CredentialQueryProvider

  const mockCredentialProvider = {
    kind: 'credential-provider',
    name: 'mock-credential-provider',
    single: true,
    verify: mock.fn(),
  } satisfies CredentialProvider

  const mockJwtSignatureProvider = {
    kind: 'jwt-signature-provider',
    name: 'mock-jwt-signature-provider',
    single: true,
    verify: mock.fn(),
  } satisfies JwtSignatureProvider

  const mockHolderBindingProvider = {
    kind: 'holder-binding-provider',
    name: 'mock-holder-binding-provider',
    single: true,
    verify: mock.fn(),
  } satisfies HolderBindingProvider

  const mockDidProvider = {
    kind: 'did-provider',
    name: 'mock-did-provider',
    single: false,
    resolveDid: mock.fn(),
    canHandle: mock.fn(),
  } satisfies DidProvider

  const mockRequestObjectStoreProvider = {
    kind: 'request-object-store-provider',
    name: 'mock-in-memory-request-object-store-provider',
    single: true,
    fetch: mock.fn(),
    save: mock.fn(),
    delete: mock.fn(),
  } satisfies RequestObjectStoreProvider

  const mockRequestObjectIdProvider = {
    kind: 'request-object-id-provider',
    name: 'default-request-object-id-provider',
    single: true,
    generate: mock.fn(),
  } satisfies RequestObjectIdProvider

  const mockTransactionDataProvider = {
    kind: 'transaction-data-provider',
    name: 'mock-transaction-data-provider',
    single: true,
    generate: mock.fn(),
  } satisfies TransactionDataProvider

  const mockKeyProvider = {
    kind: 'verifier-signature-key-provider',
    name: 'mock-verifier-signature-key-provider',
    single: false,
    generate: mock.fn(),
    sign: mock.fn(),
    canHandle: mock.fn(),
  } satisfies VerifierSignatureKeyProvider

  const mockKeyStoreProvider = {
    kind: 'verifier-signature-key-store-provider',
    name: 'mock-verifier-signature-key-store-provider',
    single: true,
    save: mock.fn(),
    fetch: mock.fn(),
    fetchPrivate: mock.fn(),
  } satisfies VerifierSignatureKeyStoreProvider

  beforeEach(() => {
    mock.reset()
  })

  before(() => {
    context = initializeContext({
      providers: [
        mockVerifierMetadataStore,
        mockCnonceProvider,
        mockCnonceStoreProvider,
        mockCredentialQueryProvider,
        mockCredentialProvider,
        mockJwtSignatureProvider,
        mockHolderBindingProvider,
        mockDidProvider,
        mockRequestObjectStoreProvider,
        mockRequestObjectIdProvider,
        mockTransactionDataProvider,
        mockKeyProvider,
        mockKeyStoreProvider,
      ],
    })
    verifierFlow = initializeVerifierFlow(context)
  })

  describe('createVerifierMetadata', () => {
    it('should generate key pairs and save them to the key store', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          jwt_vc_json: { alg_values_supported: ['ES256'] },
          jwt_vp_json: { alg_values_supported: ['ES256'] }
        },
      })
      // Mock the key provider's generate function
      mock.method(mockKeyProvider, 'generate', async () => ({
        publicKey: { alg: 'ES256', kid: 'test-kid', kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
        privateKey: {
          alg: 'ES256',
          kid: 'test-kid',
          kty: 'EC',
          crv: 'P-256',
          x: 'x',
          y: 'y',
          d: 'd',
        },
      }))
      // Mock the key provider's canHandle function
      mock.method(mockKeyProvider, 'canHandle', () => true)
      // Mock the key store's save function
      mock.method(mockKeyStoreProvider, 'save', async () => { })
      // Mock the metadata store's save function
      mock.method(mockVerifierMetadataStore, 'save', async () => { })

      await verifierFlow.createVerifierMetadata(ClientId('https://example.com'), metadata)

      // Check that the key provider's generate function is called
      assert.equal(mockKeyProvider.generate.mock.callCount(), 1)
      // Check that the key store's save function is called
      assert.equal(mockKeyStoreProvider.save.mock.callCount(), 1)
      // Check that the metadata store's save function is called
      assert.equal(mockVerifierMetadataStore.save.mock.callCount(), 1)
    })
  })

  describe('createAuthzRequest', () => {
    it('creates request for Presentation Exchange', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          jwt_vc_json: {
            alg_values_supported: ['ES256'],
          },
          jwt_vp_json: {
            alg_values_supported: ['ES256'],
          },
          ldp_vp: {
            proof_type: ['JsonWebSignature2020'],
          },
        },
      })
      const presentationDefinition = {
        id: 'test-pd-id',
        input_descriptors: [
          {
            id: 'test_credential',
            constraints: {
              fields: [
                {
                  path: ['$.type[*]'],
                  filter: {
                    type: 'string',
                    const: 'TestCredential',
                  },
                },
              ],
            },
          },
        ],
      }

      mock.method(mockVerifierMetadataStore, 'fetch', async () => metadata)
      mock.method(mockCnonceProvider, 'generate', async () => 'nonce-123')
      mock.method(mockCnonceStoreProvider, 'save', async () => { })
      mock.method(
        mockCredentialQueryProvider,
        'generate',
        async (options: CredentialQueryGenerationOptions) => {
          assert.equal(options.kind, 'presentation-exchange')
          return PresentationExchange(options.query)
        }
      )

      const req = await verifierFlow.createAuthzRequest(
        ClientId('did:key:verifier'),
        'vp_token',
        'redirect_uri:did:key:verifier',
        'direct_post',
        { presentation_definition: presentationDefinition },
        false,
        {}
      )

      AuthorizationRequest(req)
      assert.equal(req.response_type, 'vp_token')
      assert.equal(req.response_mode, 'direct_post')
      assert.equal(req.nonce, 'nonce-123')
    })

    it('creates request for Dcql', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          jwt_vc_json: {
            alg_values_supported: ['ES256'],
          },
          jwt_vp_json: {
            alg_values_supported: ['ES256'],
          },
          ldp_vp: {
            proof_type: ['JsonWebSignature2020'],
          },
          'dc+sd-jwt': {
            'sd-jwt_alg_values': ['ES256', 'ES384'],
            'kb-jwt_alg_values': ['ES256', 'ES384'],
          },
        },
      })
      const query = {
        credentials: [
          {
            id: 'my_credential',
            format: 'dc+sd-jwt',
            meta: {
              vct_values: ['https://credentials.example.com/identity_credential'],
            },
            claims: [
              { path: ['last_name'] },
              { path: ['first_name'] },
              { path: ['address', 'street_address'] },
            ],
          },
        ],
      }

      mock.method(mockVerifierMetadataStore, 'fetch', async () => metadata)
      mock.method(mockCnonceProvider, 'generate', async () => 'nonce-123')
      mock.method(mockCnonceStoreProvider, 'save', async () => { })
      mock.method(
        mockCredentialQueryProvider,
        'generate',
        async (options: CredentialQueryGenerationOptions) => {
          assert.equal(options.kind, 'dcql')
          return Dcql(options.query)
        }
      )
      mock.method(mockTransactionDataProvider, 'generate', (type: string, ids: string[]) => {
        const data = {
          type,
          credential_ids: ids,
        }
        return base64url.encode(JSON.stringify(data))
      })

      const req = await verifierFlow.createAuthzRequest(
        ClientId('did:key:verifier'),
        'vp_token',
        'redirect_uri:did:key:verifier',
        'direct_post',
        { dcql_query: query },
        false,
        {}
      )

      AuthorizationRequest(req)
      assert.equal(req.response_type, 'vp_token')
      assert.equal(req.response_mode, 'direct_post')
      assert.equal(req.nonce, 'nonce-123')
    })

    it('should throw VERIFIER_NOT_FOUND if metadata missing', async () => {
      const presentationDefinition = {
        id: 'test-pd-id',
        input_descriptors: [
          {
            id: 'test_credential',
            constraints: {
              fields: [
                {
                  path: ['$.type[*]'],
                  filter: {
                    type: 'string',
                    const: 'TestCredential',
                  },
                },
              ],
            },
          },
        ],
      }
      mock.method(mockVerifierMetadataStore, 'fetch', async () => null)
      await assert.rejects(
        verifierFlow.createAuthzRequest(
          ClientId('https://example.com'),
          'vp_token',
          'redirect_uri:https://example.com',
          'direct_post',
          { presentation_definition: presentationDefinition },
          false,
          {}
        ),
        { name: 'VERIFIER_NOT_FOUND' }
      )
    })

    it('should save RequestObject and returns request_uri when request_uri is used', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          jwt_vc_json: {
            alg_values_supported: ['ES256'],
          },
          jwt_vp_json: {
            alg_values_supported: ['ES256'],
          },
          ldp_vp: {
            proof_type: ['JsonWebSignature2020'],
          },
        },
      })
      const presentationDefinition = {
        id: 'test-pd-id',
        input_descriptors: [
          {
            id: 'test_credential',
            constraints: {
              fields: [
                {
                  path: ['$.type[*]'],
                  filter: {
                    type: 'string',
                    const: 'TestCredential',
                  },
                },
              ],
            },
          },
        ],
      }
      mock.method(mockVerifierMetadataStore, 'fetch', async () => metadata)
      mock.method(
        mockCredentialQueryProvider,
        'generate',
        async (options: CredentialQueryGenerationOptions) => {
          assert.equal(options.kind, 'presentation-exchange')
          return PresentationExchange(options.query)
        }
      )
      mock.method(mockRequestObjectIdProvider, 'generate', async () => '1234')
      mock.method(mockRequestObjectStoreProvider, 'save', async () => { })

      const req = await verifierFlow.createAuthzRequest(
        ClientId('https://example.com'),
        'vp_token',
        'redirect_uri:https://example.com',
        'direct_post',
        { presentation_definition: presentationDefinition },
        true,
        { base_url: 'https://example.com' }
      )

      AuthorizationRequest(req)
      assert.equal(typeof req.request_uri, 'string')
      assert.equal(
        req.request_uri,
        'https://example.com/request.jwt/1234',
        'request_uri should be composed with base_url, verifierId, and generated requestObjectId'
      )
      assert.equal(mockCnonceProvider.generate.mock.callCount(), 0)
      assert.equal(mockCnonceStoreProvider.save.mock.callCount(), 0)
      assert.equal(mockRequestObjectIdProvider.generate.mock.callCount(), 1)
      assert.equal(mockRequestObjectStoreProvider.save.mock.callCount(), 1)
    })

    it('should throw INVALID_REQUEST when request_uri is true and base_url is not present', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          jwt_vc_json: {
            alg_values_supported: ['ES256'],
          },
          jwt_vp_json: {
            alg_values_supported: ['ES256'],
          },
          ldp_vp: {
            proof_type: ['JsonWebSignature2020'],
          },
        },
      })
      const presentationDefinition = {
        id: 'test-pd-id',
        input_descriptors: [
          {
            id: 'test_credential',
            constraints: {
              fields: [
                {
                  path: ['$.type[*]'],
                  filter: {
                    type: 'string',
                    const: 'TestCredential',
                  },
                },
              ],
            },
          },
        ],
      }
      mock.method(mockVerifierMetadataStore, 'fetch', async () => metadata)
      mock.method(
        mockCredentialQueryProvider,
        'generate',
        async (options: CredentialQueryGenerationOptions) => {
          assert.equal(options.kind, 'presentation-exchange')
          return PresentationExchange(options.query)
        }
      )
      mock.method(mockRequestObjectIdProvider, 'generate', async () => 'reqobj-123')
      mock.method(mockRequestObjectStoreProvider, 'save', async () => { })

      await assert.rejects(
        verifierFlow.createAuthzRequest(
          ClientId('https://example.com'),
          'vp_token',
          'redirect_uri:https://example.com',
          'direct_post',
          { presentation_definition: presentationDefinition },
          true,
          {}
        ),
        { name: 'INVALID_REQUEST' }
      )
    })

    it('should throw INVALID_REQUEST when neither request_uri nor base_url is present', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          jwt_vc_json: {
            alg_values_supported: ['ES256'],
          },
          jwt_vp_json: {
            alg_values_supported: ['ES256'],
          },
          ldp_vp: {
            proof_type: ['JsonWebSignature2020'],
          },
        },
      })
      const presentationDefinition = {
        id: 'test-pd-id',
        input_descriptors: [
          {
            id: 'test_credential',
            constraints: {
              fields: [
                {
                  path: ['$.type[*]'],
                  filter: {
                    type: 'string',
                    const: 'TestCredential',
                  },
                },
              ],
            },
          },
        ],
      }
      mock.method(mockVerifierMetadataStore, 'fetch', async () => metadata)
      mock.method(
        mockCredentialQueryProvider,
        'generate',
        async (options: CredentialQueryGenerationOptions) => {
          assert.equal(options.kind, 'presentation-exchange')
          return PresentationExchange(options.query)
        }
      )
      mock.method(mockRequestObjectIdProvider, 'generate', async () => 'reqobj-123')
      mock.method(mockRequestObjectStoreProvider, 'save', async () => { })

      await assert.rejects(
        verifierFlow.createAuthzRequest(
          ClientId('https://example.com'),
          'vp_token',
          'redirect_uri:https://example.com',
          'direct_post',
          { presentation_definition: presentationDefinition },
          true,
          {}
        ),
        { name: 'INVALID_REQUEST' }
      )
    })
  })
  describe('createAuthzRequest', () => {
    it('should include transaction_data for dc+sd-jwt format in presentation exchange', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          'dc+sd-jwt': {},
        },
      })
      const presentationDefinition = {
        id: 'test-pd-id',
        input_descriptors: [
          {
            id: 'test_credential',
            format: { 'dc+sd-jwt': { alg: ['ES256'] } },
            constraints: {
              limit_disclosure: 'required',
              fields: [
                {
                  path: ['$.type[*]'],
                  filter: {
                    type: 'string',
                    const: 'TestCredential',
                  },
                },
              ],
            },
          },
        ],
      }

      mock.method(mockVerifierMetadataStore, 'fetch', async () => metadata)
      mock.method(mockCnonceProvider, 'generate', async () => 'nonce-123')
      mock.method(mockCnonceStoreProvider, 'save', async () => { })
      mock.method(
        mockCredentialQueryProvider,
        'generate',
        async (options: CredentialQueryGenerationOptions) => {
          return PresentationExchange(options.query as PresentationExchange)
        }
      )
      mock.method(mockTransactionDataProvider, 'generate', (type: string, ids: string[]) => {
        const data = {
          type,
          credential_ids: ids,
        }
        return base64url.encode(JSON.stringify(data))
      })

      const req = await verifierFlow.createAuthzRequest(
        ClientId('did:key:verifier'),
        'vp_token',
        'redirect_uri:did:key:verifier',
        'direct_post',
        { presentation_definition: presentationDefinition },
        false,
        { transaction_data: { type: 'test_transaction' } }
      )

      AuthorizationRequest(req)
      assert.equal(req.response_type, 'vp_token')
      assert.equal(req.response_mode, 'direct_post')
      assert.equal(req.nonce, 'nonce-123')
      assert.ok(req.transaction_data)
      assert.equal(req.transaction_data.length, 1)
      const decoded = JSON.parse(base64url.decode(req.transaction_data[0]))
      assert.equal(decoded.type, 'test_transaction')
      assert.deepEqual(decoded.credential_ids, ['test_credential'])
    })
  })

  describe('verifyPresentations', () => {
    it('should verify a presentation', async () => {
      const verifierId = ClientId('https://example.com')
      const holderDid = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
      const vpToken = makeJwt(
        { alg: 'ES256', kid: `${holderDid}#${holderDid}` },
        {
          vp: {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiablePresentation'],
            verifiableCredential: [
              makeJwt(
                { alg: 'ES256', kid: 'did:example:issuer#key-1' },
                {
                  vc: minimalVc,
                  sub: holderDid,
                }
              ),
            ],
          },
          nonce: 'nonce-123',
        }
      )
      const response = AuthorizationResponse({
        vp_token: vpToken,
        presentation_submission: {
          id: 'ps-id',
          definition_id: 'pd-id',
          descriptor_map: [],
        },
      })

      mock.method(mockVerifierMetadataStore, 'fetch', async () =>
        VerifierMetadata({
          client_name: 'test',
          vp_formats: {
            jwt_vc_json: {
              alg_values_supported: ['ES256'],
            },
            jwt_vp_json: {
              alg_values_supported: ['ES256'],
            },
          },
        })
      )
      mock.method(mockCnonceStoreProvider, 'validate', async () => true)
      mock.method(mockCnonceStoreProvider, 'revoke', async () => { })
      mock.method(mockCredentialProvider, 'verify', async () => true)
      mock.method(mockDidProvider, 'canHandle', () => true)
      mock.method(mockDidProvider, 'resolveDid', async () => ({
        id: holderDid,
        verificationMethod: [
          {
            id: `${holderDid}#${holderDid}`,
            type: 'JsonWebKey2020',
            controller: holderDid,
            publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'test' },
          },
        ],
      }))
      mock.method(mockJwtSignatureProvider, 'verify', async () => true)
      mock.method(mockHolderBindingProvider, 'verify', async () => true)

      await assert.doesNotReject(verifierFlow.verifyPresentations(verifierId, response))

      assert.equal(mockVerifierMetadataStore.fetch.mock.callCount(), 1)
      assert.equal(mockCnonceStoreProvider.validate.mock.callCount(), 1)
      assert.equal(mockCnonceStoreProvider.revoke.mock.callCount(), 1)
      assert.equal(mockCredentialProvider.verify.mock.callCount(), 1)
      assert.equal(mockDidProvider.resolveDid.mock.callCount(), 1)
      assert.equal(mockJwtSignatureProvider.verify.mock.callCount(), 1)
      assert.equal(mockHolderBindingProvider.verify.mock.callCount(), 1)
    })
  })
})
