import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { before, beforeEach, describe, it, mock } from 'node:test'
import { AuthorizationRequest } from '../src/authorization-request.types'
import { AuthorizationResponse } from '../src/authorization-response.types'
import { ClientId } from '../src/client-id.types'
import { ClientIdentifier } from '../src/client-id-scheme.types'
import { Dcql } from '../src/dcql.type'
import {
  CnonceProvider,
  CnonceStoreProvider,
  CredentialQueryProvider,
  RequestObjectIdProvider,
  RequestObjectStoreProvider,
  VerifierEncryptionKeyStoreProvider,
  VerifierMetadataStoreProvider,
  VerifierSignatureKeyProvider,
  VerifierSignatureKeyStoreProvider,
  VerifierCertificateStoreProvider,
  CertificateProvider,
  VerifyVerifiablePresentationProvider,
  TransactionIdProvider,
  VerifierTransactionDataStoreProvider,
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
    single: true,
    generate: mock.fn(),
  } satisfies CredentialQueryProvider

  const mockVerifyVerifiablePresentationProvider = {
    kind: 'verify-verifiable-presentation-provider',
    name: 'mock-verify-verifiable-presentation-provider',
    single: false,
    verify: mock.fn(),
    canHandle: mock.fn(),
  } satisfies VerifyVerifiablePresentationProvider

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
    canHandle: mock.fn(),
  } satisfies VerifierSignatureKeyProvider

  const mockKeyStoreProvider = {
    kind: 'verifier-signature-key-store-provider',
    name: 'mock-verifier-signature-key-store-provider',
    single: true,
    save: mock.fn(),
    fetch: mock.fn(),
    sign: mock.fn(),
  } satisfies VerifierSignatureKeyStoreProvider

  const mockEncryptionKeyStoreProvider = {
    kind: 'verifier-encryption-key-store-provider',
    name: 'mock-verifier-encryption-key-store-provider',
    single: true,
    save: mock.fn(),
    fetch: mock.fn(),
  } satisfies VerifierEncryptionKeyStoreProvider

  const mockCertificateStoreProvider = {
    kind: 'verifier-certificate-store-provider',
    name: 'mock-verifier-certificate-store-provider',
    single: true,
    save: mock.fn(),
    fetch: mock.fn(),
  } satisfies VerifierCertificateStoreProvider

  const mockCertificateProvider = {
    kind: 'certificate-provider',
    name: 'mock-certificate-provider',
    single: true,
    validate: mock.fn(),
    getPublicKey: mock.fn(),
  } satisfies CertificateProvider

  const mockTransactionIdProvider = {
    kind: 'transaction-id-provider',
    name: 'mock-transaction-id-provider',
    single: true,
    generate: mock.fn(),
  } satisfies TransactionIdProvider

  const mockVerifierTransactionDataStoreProvider = {
    kind: 'verifier-transaction-store-provider',
    name: 'mock-verifier-transaction-store-provider',
    single: true,
    fetch: mock.fn(),
    save: mock.fn(),
    delete: mock.fn(),
  } satisfies VerifierTransactionDataStoreProvider

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
        mockRequestObjectStoreProvider,
        mockRequestObjectIdProvider,
        mockTransactionDataProvider,
        mockKeyProvider,
        mockKeyStoreProvider,
        mockEncryptionKeyStoreProvider,
        mockCertificateStoreProvider,
        mockCertificateProvider,
        mockVerifyVerifiablePresentationProvider,
        mockTransactionIdProvider,
        mockVerifierTransactionDataStoreProvider,
      ],
    })
    verifierFlow = initializeVerifierFlow(context)
  })

  describe('createVerifierMetadata', () => {
    const encryptionJwk = {
      kty: 'RSA',
      crv: 'P-256',
      x: 'enc-x',
      y: 'enc-y',
      alg: 'RSA-OAEP-256',
      kid: 'enc-key-1',
      use: 'enc' as const,
    }

    it('should generate signing keys and persist encryption jwk when options are omitted', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          jwt_vc_json: { alg_values_supported: ['ES256'] },
          jwt_vp_json: { alg_values_supported: ['ES256'] },
        },
      })
      let savedMetadata: VerifierMetadata | undefined

      mock.method(mockVerifierMetadataStore, 'fetch', async () => null)
      mock.method(mockKeyStoreProvider, 'save', async () => {})
      mock.method(mockEncryptionKeyStoreProvider, 'save', async () => {})
      mock.method(mockEncryptionKeyStoreProvider, 'fetch', async () => encryptionJwk)
      mock.method(
        mockVerifierMetadataStore,
        'save',
        async (_id: ClientId, value: VerifierMetadata) => {
          savedMetadata = value
        }
      )

      await verifierFlow.createVerifierMetadata(ClientId('https://example.com'), metadata)

      assert.equal(mockKeyStoreProvider.save.mock.callCount(), 1)
      assert.equal(mockEncryptionKeyStoreProvider.save.mock.callCount(), 1)
      assert.equal(mockEncryptionKeyStoreProvider.fetch.mock.callCount(), 1)
      assert.equal(mockVerifierMetadataStore.save.mock.callCount(), 1)
      assert.deepEqual(savedMetadata?.jwks, { keys: [encryptionJwk] })
    })

    it('should persist provided verifier keys before saving metadata', async () => {
      const events: string[] = []
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          jwt_vc_json: { alg_values_supported: ['ES256'] },
          jwt_vp_json: { alg_values_supported: ['ES256'] },
        },
      })
      const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()

      mock.method(mockVerifierMetadataStore, 'fetch', async () => null)
      mock.method(mockKeyStoreProvider, 'save', async () => {
        events.push('key')
      })
      mock.method(mockEncryptionKeyStoreProvider, 'save', async () => {
        events.push('enc-key')
      })
      mock.method(mockEncryptionKeyStoreProvider, 'fetch', async () => encryptionJwk)
      mock.method(mockVerifierMetadataStore, 'save', async () => {
        events.push('metadata')
      })

      await verifierFlow.createVerifierMetadata(ClientId('https://example.com'), metadata, {
        format: 'pem',
        alg: 'ES256',
        publicKey: publicKeyPem,
        privateKey: 'private-key',
      })

      assert.deepEqual(events, ['enc-key', 'key', 'metadata'])
    })

    it('should throw INTERNAL_SERVER_ERROR when encryption key generation fails', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          jwt_vc_json: { alg_values_supported: ['ES256'] },
          jwt_vp_json: { alg_values_supported: ['ES256'] },
        },
      })

      mock.method(mockVerifierMetadataStore, 'fetch', async () => null)
      mock.method(mockKeyStoreProvider, 'save', async () => {})
      mock.method(mockEncryptionKeyStoreProvider, 'save', async () => {})
      mock.method(mockEncryptionKeyStoreProvider, 'fetch', async () => null)

      await assert.rejects(
        verifierFlow.createVerifierMetadata(ClientId('https://example.com'), metadata),
        {
          name: 'INTERNAL_SERVER_ERROR',
          message: 'Failed to generate encryption key pair.',
        }
      )
    })
  })

  describe('findVerifierMetadata', () => {
    it('should find verifier metadata', async () => {
      const verifierId = ClientId('https://example.com')
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: {
          jwt_vc_json: { alg_values_supported: ['ES256'] },
          jwt_vp_json: { alg_values_supported: ['ES256'] },
        },
      })

      mock.method(mockVerifierMetadataStore, 'fetch', async (id: ClientId) => {
        assert.equal(id, verifierId)
        return metadata
      })

      const found = await verifierFlow.findVerifierMetadata(verifierId)

      assert.deepEqual(found, metadata)
      assert.equal(mockVerifierMetadataStore.fetch.mock.callCount(), 1)
    })

    it('should return null if verifier metadata is not found', async () => {
      const verifierId = ClientId('https://example.com/not-found')

      mock.method(mockVerifierMetadataStore, 'fetch', async (id: ClientId) => {
        assert.equal(id, verifierId)
        return null
      })

      const found = await verifierFlow.findVerifierMetadata(verifierId)

      assert.strictEqual(found, null)
      assert.equal(mockVerifierMetadataStore.fetch.mock.callCount(), 1)
    })
  })

  describe('createAuthzRequest', () => {
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
      mock.method(mockCnonceStoreProvider, 'save', async () => {})
      mock.method(mockCredentialQueryProvider, 'generate', async (query: unknown) =>
        Dcql(query as Dcql)
      )
      mock.method(mockTransactionDataProvider, 'generate', (type: string, ids: string[]) => {
        const data = {
          type,
          credential_ids: ids,
        }
        return base64url.encode(JSON.stringify(data))
      })
      mock.method(mockTransactionIdProvider, 'generate', async () => 'txn-id-123')
      mock.method(mockVerifierTransactionDataStoreProvider, 'save', async () => {})

      const req = await verifierFlow.createAuthzRequest(
        ClientId('did:key:verifier'),
        'vp_token',
        'redirect_uri:did:key:verifier',
        'direct_post',
        { dcql_query: query },
        false,
        {}
      )

      AuthorizationRequest(req.request)
      if ('request_uri' in req.request) throw new Error('unexpected request_uri flow')
      assert.equal(req.request.response_type, 'vp_token')
      assert.equal(req.request.response_mode, 'direct_post')
      assert.equal(req.request.nonce, 'nonce-123')
    })

    it('should throw VERIFIER_NOT_FOUND if metadata missing', async () => {
      mock.method(mockVerifierMetadataStore, 'fetch', async () => null)
      await assert.rejects(
        verifierFlow.createAuthzRequest(
          ClientId('https://example.com'),
          'vp_token',
          'redirect_uri:https://example.com',
          'direct_post',
          {
            dcql_query: {
              credentials: [{ id: 'test_credential', format: 'jwt_vc_json' }],
            },
          },
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
          jwt_vc_json: { alg_values_supported: ['ES256'] },
        },
      })
      mock.method(mockVerifierMetadataStore, 'fetch', async () => metadata)
      mock.method(mockCnonceProvider, 'generate', async () => 'nonce-req-uri')
      mock.method(mockCnonceStoreProvider, 'save', async () => {})
      mock.method(mockCredentialQueryProvider, 'generate', async (query: unknown) =>
        Dcql(query as Dcql)
      )
      mock.method(mockRequestObjectIdProvider, 'generate', async () => '1234')
      mock.method(mockRequestObjectStoreProvider, 'save', async () => {})
      mock.method(mockTransactionIdProvider, 'generate', async () => 'txn-id-123')
      mock.method(mockVerifierTransactionDataStoreProvider, 'save', async () => {})

      const req = await verifierFlow.createAuthzRequest(
        ClientId('https://example.com'),
        'vp_token',
        'redirect_uri:https://example.com',
        'direct_post',
        {
          dcql_query: {
            credentials: [
              {
                id: 'test_credential',
                format: 'jwt_vc_json',
                meta: { type_values: [['VerifiableCredential']] },
                claims: [{ path: ['vc', 'credentialSubject', 'id'] }],
              },
            ],
          },
        },
        true,
        { base_url: 'https://example.com' }
      )

      AuthorizationRequest(req.request)
      if (!('request_uri' in req.request)) throw new Error('expected request_uri flow')
      assert.equal(typeof req.request.request_uri, 'string')
      assert.equal(
        req.request.request_uri,
        'https://example.com/request.jwt/1234',
        'request_uri should be composed with base_url, verifierId, and generated requestObjectId'
      )
      assert.equal(mockCnonceProvider.generate.mock.callCount(), 1)
      assert.equal(mockCnonceStoreProvider.save.mock.callCount(), 1)
      assert.equal(mockRequestObjectIdProvider.generate.mock.callCount(), 1)
      assert.equal(mockRequestObjectStoreProvider.save.mock.callCount(), 1)
    })

    it('should throw INVALID_REQUEST when request_uri is true and base_url is not present', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: { jwt_vc_json: { alg_values_supported: ['ES256'] } },
      })
      mock.method(mockVerifierMetadataStore, 'fetch', async () => metadata)
      mock.method(mockCredentialQueryProvider, 'generate', async (query: unknown) =>
        Dcql(query as Dcql)
      )
      mock.method(mockRequestObjectIdProvider, 'generate', async () => 'reqobj-123')
      mock.method(mockRequestObjectStoreProvider, 'save', async () => {})

      await assert.rejects(
        verifierFlow.createAuthzRequest(
          ClientId('https://example.com'),
          'vp_token',
          'redirect_uri:https://example.com',
          'direct_post',
          {
            dcql_query: {
              credentials: [
                {
                  id: 'test_credential',
                  format: 'jwt_vc_json',
                  meta: { type_values: [['VerifiableCredential']] },
                  claims: [{ path: ['vc', 'credentialSubject', 'id'] }],
                },
              ],
            },
          },
          true,
          {}
        ),
        { name: 'INVALID_REQUEST' }
      )
    })
  })
  describe('createAuthzRequest', () => {
    it('should include transaction_data for dc+sd-jwt format in dcql query', async () => {
      const metadata = VerifierMetadata({
        client_name: 'Test Verifier',
        vp_formats: { 'dc+sd-jwt': {} },
      })

      mock.method(mockVerifierMetadataStore, 'fetch', async () => metadata)
      mock.method(mockCnonceProvider, 'generate', async () => 'nonce-123')
      mock.method(mockCnonceStoreProvider, 'save', async () => {})
      mock.method(mockCredentialQueryProvider, 'generate', async (query: unknown) =>
        Dcql(query as Dcql)
      )
      mock.method(mockTransactionDataProvider, 'generate', (type: string, ids: string[]) => {
        const data = { type, credential_ids: ids }
        return base64url.encode(JSON.stringify(data))
      })
      mock.method(mockTransactionIdProvider, 'generate', async () => 'txn-id-123')
      mock.method(mockVerifierTransactionDataStoreProvider, 'save', async () => {})

      const req = await verifierFlow.createAuthzRequest(
        ClientId('did:key:verifier'),
        'vp_token',
        'redirect_uri:did:key:verifier',
        'direct_post',
        {
          dcql_query: {
            credentials: [
              {
                id: 'test_credential',
                format: 'dc+sd-jwt',
                meta: { vct_values: ['TestCredential'] },
                claims: [{ path: ['given_name'] }],
              },
            ],
          },
        },
        false,
        { transaction_data: { type: 'test_transaction' } }
      )

      AuthorizationRequest(req.request)
      if ('request_uri' in req.request) throw new Error('unexpected request_uri flow')
      assert.equal(req.request.response_type, 'vp_token')
      assert.equal(req.request.response_mode, 'direct_post')
      assert.equal(req.request.nonce, 'nonce-123')
      assert.ok(req.request.transaction_data)
      assert.equal(req.request.transaction_data.length, 1)
      const decoded = JSON.parse(base64url.decode(req.request.transaction_data[0]))
      assert.equal(decoded.type, 'test_transaction')
      assert.deepEqual(decoded.credential_ids, ['test_credential'])
    })
  })

  describe('verifyPresentations', () => {
    it('should verify a presentation(jwt_vp_json)', async () => {
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
                { vc: minimalVc, sub: holderDid }
              ),
            ],
          },
          nonce: 'nonce-123',
        }
      )
      const response = AuthorizationResponse({
        vp_token: { my_vp_cred: [vpToken] },
      })
      const vpPayload = {
        vp: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiablePresentation'],
          verifiableCredential: [makeJwt({ alg: 'ES256', typ: 'JWT' }, minimalVc)],
        },
        nonce: 'nonce-123',
      }

      mock.method(mockVerifierMetadataStore, 'fetch', async () =>
        VerifierMetadata({
          client_name: 'test',
          vp_formats: { jwt_vc_json: { alg_values_supported: ['ES256'] } },
        })
      )
      mock.method(mockVerifierTransactionDataStoreProvider, 'fetch', async () => ({
        dcqlQuery: { dcql_query: { credentials: [{ id: 'my_vp_cred', format: 'jwt_vc_json' }] } },
        clientId: ClientIdentifier(`redirect_uri:${verifierId}`),
        verifierId,
      }))
      mock.method(mockVerifyVerifiablePresentationProvider, 'canHandle', () => true)
      mock.method(mockVerifyVerifiablePresentationProvider, 'verify', async () => vpPayload)

      const result = await verifierFlow.verifyPresentations(response, 'txn-123')
      assert.deepEqual(result, { my_vp_cred: [vpPayload] })

      assert.equal(mockVerifierMetadataStore.fetch.mock.callCount(), 1)
      assert.equal(mockVerifyVerifiablePresentationProvider.verify.mock.callCount(), 1)
      assert.equal(
        mockVerifyVerifiablePresentationProvider.verify.mock.calls[0].arguments[0],
        vpToken
      )
      assert.deepEqual(mockVerifyVerifiablePresentationProvider.verify.mock.calls[0].arguments[1], {
        kind: 'jwt_vp_json',
        expectedAud: ClientIdentifier(`redirect_uri:${verifierId}`),
        expectedNonce: undefined,
      })
    })

    it('should throw INVALID_VP_TOKEN when a required credential query is missing from vp_token', async () => {
      const verifierId = ClientId('https://example.com')

      mock.method(mockVerifierMetadataStore, 'fetch', async () =>
        VerifierMetadata({
          client_name: 'test',
          vp_formats: { jwt_vc_json: { alg_values_supported: ['ES256'] } },
        })
      )
      mock.method(mockVerifierTransactionDataStoreProvider, 'fetch', async () => ({
        dcqlQuery: {
          dcql_query: {
            credentials: [
              { id: 'cred_a', format: 'jwt_vc_json' },
              { id: 'cred_b', format: 'jwt_vc_json' },
            ],
          },
        },
        verifierId,
      }))
      mock.method(mockVerifyVerifiablePresentationProvider, 'canHandle', () => true)
      mock.method(mockVerifyVerifiablePresentationProvider, 'verify', async () => ({}))

      const vpToken = makeJwt({ alg: 'ES256' }, { vp: {}, nonce: 'n' })
      const response = AuthorizationResponse({ vp_token: { cred_a: [vpToken] } })

      await assert.rejects(verifierFlow.verifyPresentations(response, 'txn-123'), {
        name: 'INVALID_VP_TOKEN',
      })
    })

    it('should throw INVALID_VP_TOKEN when vp_token array is empty for a credential query', async () => {
      const verifierId = ClientId('https://example.com')

      mock.method(mockVerifierMetadataStore, 'fetch', async () =>
        VerifierMetadata({
          client_name: 'test',
          vp_formats: { jwt_vc_json: { alg_values_supported: ['ES256'] } },
        })
      )
      mock.method(mockVerifierTransactionDataStoreProvider, 'fetch', async () => ({
        dcqlQuery: {
          dcql_query: {
            credentials: [{ id: 'cred_a', format: 'jwt_vc_json' }],
          },
        },
        verifierId,
      }))

      const response = AuthorizationResponse({ vp_token: { cred_a: [] } })

      await assert.rejects(verifierFlow.verifyPresentations(response, 'txn-123'), {
        name: 'INVALID_VP_TOKEN',
      })
    })

    it('should throw INVALID_VP_TOKEN when no option of a required credential_set is fully presented', async () => {
      const verifierId = ClientId('https://example.com')

      mock.method(mockVerifierMetadataStore, 'fetch', async () =>
        VerifierMetadata({
          client_name: 'test',
          vp_formats: { jwt_vc_json: { alg_values_supported: ['ES256'] } },
        })
      )
      mock.method(mockVerifierTransactionDataStoreProvider, 'fetch', async () => ({
        dcqlQuery: {
          dcql_query: {
            credentials: [
              { id: 'cred_a', format: 'jwt_vc_json' },
              { id: 'cred_b', format: 'jwt_vc_json' },
              { id: 'cred_c', format: 'jwt_vc_json' },
            ],
            credential_sets: [{ options: [['cred_a'], ['cred_b', 'cred_c']], required: true }],
          },
        },
        verifierId,
      }))
      mock.method(mockVerifyVerifiablePresentationProvider, 'canHandle', () => true)
      mock.method(mockVerifyVerifiablePresentationProvider, 'verify', async () => ({}))

      // cred_b のみ提示 → option A (cred_a) も option B (cred_b + cred_c) も未充足
      const vpToken = makeJwt({ alg: 'ES256' }, { vp: {}, nonce: 'n' })
      const response = AuthorizationResponse({ vp_token: { cred_b: [vpToken] } })

      await assert.rejects(verifierFlow.verifyPresentations(response, 'txn-123'), {
        name: 'INVALID_VP_TOKEN',
      })
    })

    it('should verify a presentation when response state matches transaction state', async () => {
      const verifierId = ClientId('https://example.com')
      const vpToken = makeJwt({ alg: 'ES256' }, { vp: {}, nonce: 'n' })
      const response = AuthorizationResponse({
        vp_token: { cred_a: [vpToken] },
        state: 'expected-state',
      })

      mock.method(mockVerifierMetadataStore, 'fetch', async () =>
        VerifierMetadata({
          client_name: 'test',
          vp_formats: { jwt_vc_json: { alg_values_supported: ['ES256'] } },
        })
      )
      mock.method(mockVerifierTransactionDataStoreProvider, 'fetch', async () => ({
        dcqlQuery: { dcql_query: { credentials: [{ id: 'cred_a', format: 'jwt_vc_json' }] } },
        clientId: ClientIdentifier(`redirect_uri:${verifierId}`),
        verifierId,
        state: 'expected-state',
      }))
      mock.method(mockVerifyVerifiablePresentationProvider, 'canHandle', () => true)
      mock.method(mockVerifyVerifiablePresentationProvider, 'verify', async () => ({}))

      await verifierFlow.verifyPresentations(response, 'txn-123')
    })

    it('should throw INVALID_REQUEST when response state does not match transaction state', async () => {
      const verifierId = ClientId('https://example.com')
      const vpToken = makeJwt({ alg: 'ES256' }, { vp: {}, nonce: 'n' })
      const response = AuthorizationResponse({
        vp_token: { cred_a: [vpToken] },
        state: 'wrong-state',
      })

      mock.method(mockVerifierMetadataStore, 'fetch', async () =>
        VerifierMetadata({
          client_name: 'test',
          vp_formats: { jwt_vc_json: { alg_values_supported: ['ES256'] } },
        })
      )
      mock.method(mockVerifierTransactionDataStoreProvider, 'fetch', async () => ({
        dcqlQuery: { dcql_query: { credentials: [{ id: 'cred_a', format: 'jwt_vc_json' }] } },
        clientId: ClientIdentifier(`redirect_uri:${verifierId}`),
        verifierId,
        state: 'expected-state',
      }))

      await assert.rejects(verifierFlow.verifyPresentations(response, 'txn-123'), {
        name: 'INVALID_REQUEST',
      })
    })

    it('should throw INVALID_REQUEST when response state is absent but transaction has state', async () => {
      const verifierId = ClientId('https://example.com')
      const vpToken = makeJwt({ alg: 'ES256' }, { vp: {}, nonce: 'n' })
      const response = AuthorizationResponse({ vp_token: { cred_a: [vpToken] } })

      mock.method(mockVerifierMetadataStore, 'fetch', async () =>
        VerifierMetadata({
          client_name: 'test',
          vp_formats: { jwt_vc_json: { alg_values_supported: ['ES256'] } },
        })
      )
      mock.method(mockVerifierTransactionDataStoreProvider, 'fetch', async () => ({
        dcqlQuery: { dcql_query: { credentials: [{ id: 'cred_a', format: 'jwt_vc_json' }] } },
        clientId: ClientIdentifier(`redirect_uri:${verifierId}`),
        verifierId,
        state: 'expected-state',
      }))

      await assert.rejects(verifierFlow.verifyPresentations(response, 'txn-123'), {
        name: 'INVALID_REQUEST',
      })
    })
  })
})
