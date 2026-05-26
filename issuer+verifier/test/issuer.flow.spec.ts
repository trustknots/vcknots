import assert from 'node:assert/strict'
import { before, beforeEach, describe, it, mock } from 'node:test'
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialIssuerMetadata,
} from '../src/credential-issuer.types'
import { CredentialOffer } from '../src/credential-offer.types'
import { CredentialFormats, CredentialRequest } from '../src/credential-request.types'
import { IssuerFlow, initializeIssuerFlow } from '../src/issuer.flows'
import {
  NonceProvider,
  NonceStoreProvider,
  CredentialOfferProvider,
  CredentialProofProvider,
  IssueCredentialProvider,
  IssuerMetadataStoreProvider,
  IssuerSignatureKeyStoreProvider,
  PreAuthorizedCodeProvider,
  PreAuthorizedCodeStoreProvider,
  TransactionCodeProvider,
  IssuanceContextStoreProvider,
} from '../src/providers'
import { VcknotsContext, initializeContext } from '../src/vcknots.context'
import { ProofTypes } from '../src/proofs.types'

describe('IssuerFlow', () => {
  let context: VcknotsContext
  let issuerFlow: IssuerFlow

  const mockIssuerMetadataProvider = {
    kind: 'issuer-metadata-store-provider',
    name: 'mock-issuer-metaedata-store-provider',
    single: true,
    save: mock.fn(),
    fetch: mock.fn(),
  } satisfies IssuerMetadataStoreProvider

  const mockPreAuthCodeProvider = {
    kind: 'pre-authorized-code-provider',
    name: 'mock-pre-authorized-code-provider',
    single: true,
    generate: mock.fn(),
  } satisfies PreAuthorizedCodeProvider

  const mockPreAuthCodeStoreProvider = {
    kind: 'pre-authorized-code-store-provider',
    name: 'mock-pre-authorized-code-store-provider',
    single: true,
    save: mock.fn(),
    consume: mock.fn(),
  } satisfies PreAuthorizedCodeStoreProvider

  const mockIssuanceContextStoreProvider = {
    kind: 'issuance-context-store-provider',
    name: 'mock-issuance-context-store-provider',
    single: true,
    save: mock.fn(),
    fetch: mock.fn(),
    delete: mock.fn(),
  } satisfies IssuanceContextStoreProvider

  const mockIssuerKeyStoreProvider = {
    kind: 'issuer-signature-key-store-provider',
    name: 'mock-issuer-key-store-provider',
    single: true,
    save: mock.fn(),
    fetch: mock.fn(),
    sign: mock.fn(),
  } satisfies IssuerSignatureKeyStoreProvider

  const mockCredentialOfferProvider = {
    kind: 'credential-offer-provider',
    name: 'mock-credential-offer-provider',
    single: true,
    create: mock.fn(),
  } satisfies CredentialOfferProvider

  const mockIssueCredentialProvider = {
    kind: 'issue-credential-provider',
    name: 'mock-issue-credential-provider',
    single: false,
    createCredential: mock.fn(),
    canHandle: mock.fn(),
  } satisfies IssueCredentialProvider

  const mockCredentialProofProvider = {
    kind: 'credential-proof-provider',
    name: 'mock-credential-proof-provider',
    single: false,
    verifyProof: mock.fn(),
    canHandle: mock.fn(),
  } satisfies CredentialProofProvider

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
    revoke: mock.fn(async () => true),
    consume: mock.fn(async () => true),
  } satisfies NonceStoreProvider

  const mockTransactionCodeProvider = {
    kind: 'transaction-code-provider',
    name: 'mock-transaction-code-provider',
    single: true,
    generate: mock.fn(),
  } satisfies TransactionCodeProvider

  const createCredentialRequest = (
    overrides: Partial<CredentialRequest> = {}
  ): CredentialRequest => ({
    credential_configuration_id: 'University_Degree',
    proofs: {
      jwt: ['dummy-proof-jwt'],
    },
    ...overrides,
  })

  beforeEach(() => {
    mock.reset()
  })

  before(() => {
    context = initializeContext({
      providers: [
        mockIssuerMetadataProvider,
        mockPreAuthCodeProvider,
        mockPreAuthCodeStoreProvider,
        mockIssuanceContextStoreProvider,
        mockIssueCredentialProvider,
        mockIssuerKeyStoreProvider,
        mockCredentialOfferProvider,
        mockCredentialProofProvider,
        mockNonceProvider,
        mockNonceStoreProvider,
        mockTransactionCodeProvider,
      ],
    })
    issuerFlow = initializeIssuerFlow(context)
  })

  it('should find issuer metadata', async () => {
    const issuer = CredentialIssuer('did:example:issuer')
    const metadata: CredentialIssuerMetadata = {
      credential_issuer: CredentialIssuer('did:example:issuer'),
      credential_endpoint: 'https://example.com/credentials',
      credential_configurations_supported: {
        University_Degree: {
          format: 'jwt_vc_json',
          credential_definition: {
            type: ['VCKnots'],
            credentialSubject: {},
          },
          credential_signing_alg_values_supported: ['ES256'],
        },
      },
    }
    mock.method(mockIssuerMetadataProvider, 'fetch', async (_id: CredentialIssuer) => {
      return metadata
    })

    const found = await issuerFlow.findIssuerMetadata(issuer)

    assert.deepEqual(found, metadata)
    assert.equal(mockIssuerMetadataProvider.fetch.mock.callCount(), 1)
  })

  it('should return null if issuer metadata is not found', async () => {
    const issuer = CredentialIssuer('did:example:nonexistent')

    mock.method(mockIssuerMetadataProvider, 'fetch', async () => null)

    const found = await issuerFlow.findIssuerMetadata(issuer)

    assert.strictEqual(found, null)
  })

  it('should find JWT VC issuer metadata with JWKS', async () => {
    const issuer = CredentialIssuer('did:example:issuer')
    const metadata: CredentialIssuerMetadata = {
      credential_issuer: issuer,
      credential_endpoint: 'https://example.com/credentials',
      credential_configurations_supported: {},
    }
    const keys = await generateKeyPair('ES256', { extractable: true })
    const expectedJwk = await exportJWK(keys.publicKey)
    const expectedKid = await calculateJwkThumbprint(expectedJwk)
    mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keys.publicKey)

    const found = await issuerFlow.findJwtVcIssuerMetadata(issuer)

    assert.deepStrictEqual(found, {
      issuer: issuer,
      jwks: {
        keys: [{ ...expectedJwk, kid: expectedKid }],
      },
    })
    assert.equal(mockIssuerMetadataProvider.fetch.mock.callCount(), 1)
    assert.equal(mockIssuerKeyStoreProvider.fetch.mock.callCount(), 1)
  })

  it('should find JWT VC issuer metadata without JWKS if no keys are found', async () => {
    const issuer = CredentialIssuer('did:example:issuer')
    const metadata: CredentialIssuerMetadata = {
      credential_issuer: issuer,
      credential_endpoint: 'https://example.com/credentials',
      credential_configurations_supported: {},
    }
    mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => null)

    const found = await issuerFlow.findJwtVcIssuerMetadata(issuer)

    assert.deepStrictEqual(found, {
      issuer: issuer,
    })
    assert.equal(mockIssuerMetadataProvider.fetch.mock.callCount(), 1)
    assert.equal(mockIssuerKeyStoreProvider.fetch.mock.callCount(), 1)
  })

  it('should return null if issuer metadata is not found for JWT VC issuer metadata', async () => {
    const issuer = CredentialIssuer('did:example:nonexistent')
    mock.method(mockIssuerMetadataProvider, 'fetch', async () => null)

    const found = await issuerFlow.findJwtVcIssuerMetadata(issuer)

    assert.strictEqual(found, null)
    assert.equal(mockIssuerMetadataProvider.fetch.mock.callCount(), 1)
  })

  it('should save metadata and generate/save a key pair', async () => {
    const issuer = CredentialIssuer('did:example:issuer')
    const metadata: CredentialIssuerMetadata = {
      credential_issuer: issuer,
      credential_endpoint: 'https://example.com/credentials',
      credential_configurations_supported: {
        University_Degree: {
          format: 'jwt_vc_json',
          credential_definition: {
            type: ['VCKnots'],
            credentialSubject: {},
          },
          credential_signing_alg_values_supported: ['ES256'],
        },
      },
    }

    await issuerFlow.createIssuerMetadata(metadata)

    assert.equal(mockIssuerMetadataProvider.save.mock.callCount(), 1, 'store.save should be called')
    assert.deepStrictEqual(mockIssuerMetadataProvider.save.mock.calls[0].arguments[0], metadata)

    assert.equal(
      mockIssuerKeyStoreProvider.save.mock.callCount(),
      1,
      'keyStore.save should be called'
    )
    assert.deepStrictEqual(mockIssuerKeyStoreProvider.save.mock.calls[0].arguments[0], issuer)
    assert.deepStrictEqual(mockIssuerKeyStoreProvider.save.mock.calls[0].arguments[1], 'ES256')
  })

  it('should throw if no key generator can handle the algorithm', async () => {
    const metadata: CredentialIssuerMetadata = {
      credential_issuer: CredentialIssuer('did:example:issuer'),
      credential_endpoint: 'https://example.com/credentials',
      credential_configurations_supported: {
        University_Degree: {
          format: 'jwt_vc_json',
          credential_definition: {
            type: ['VCKnots'],
            credentialSubject: {},
          },
          credential_signing_alg_values_supported: ['RS256'],
        },
      },
    }
    mock.method(mockIssuerKeyStoreProvider, 'save', async () => {
      throw Object.assign(new Error('No provider found which can handle: RS256'), {
        name: 'provider_not_found',
      })
    })

    await assert.rejects(issuerFlow.createIssuerMetadata(metadata), {
      name: 'provider_not_found',
      message: 'No provider found which can handle: RS256',
    })
  })

  const issuer = CredentialIssuer('did:example:issuer')
  const configurations = [CredentialConfigurationId('VerifiableId')]

  it('should throw "unsupported_grant_type" if usePreAuth is false', async () => {
    const suspects = async () => {
      return await issuerFlow.offerCredential(issuer, configurations, {
        usePreAuth: false,
      })
    }

    assert.rejects(suspects, 'unsupported_grant_type')
  })

  it('should throw "invalid_credential_request" if credential_configuration_ids is not an array of unique strings', async () => {
    const duplicateConfigurations = [
      CredentialConfigurationId('VerifiableId'),
      CredentialConfigurationId('VerifiableId'),
    ]
    const suspects = async () => {
      return await issuerFlow.offerCredential(issuer, duplicateConfigurations, {
        usePreAuth: true,
      })
    }
    const metadata = CredentialIssuerMetadata({
      credential_issuer: issuer,
      credential_endpoint: 'https://example.com/credentials',
      credential_configurations_supported: {
        VerifiableId: {
          format: 'jwt_vc_json',
          credential_definition: {
            type: ['VCKnots'],
          },
          credential_signing_alg_values_supported: ['ES256'],
        },
      },
    })
    mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

    await assert.rejects(suspects, {
      name: 'invalid_credential_request',
      message: 'credential_configuration_ids must be unique.',
    })
  })

  it('should throw "issuer_not_found" if issuer metadata is not found when usePreAuth is true', async () => {
    mock.method(mockIssuerMetadataProvider, 'fetch', async () => null)

    const suspects = async () => {
      return await issuerFlow.offerCredential(issuer, configurations, { usePreAuth: true })
    }

    assert.rejects(suspects, 'issuer_not_found')
  })

  it('should create a credential offer with pre-authorized code', async () => {
    const metadata = CredentialIssuerMetadata({
      credential_issuer: issuer,
      credential_endpoint: 'https://example.com/credentials',
      credential_configurations_supported: {
        VerifiableId: {
          format: 'jwt_vc_json',
          credential_definition: {
            type: ['VCKnots'],
            credentialSubject: {},
          },
          credential_signing_alg_values_supported: ['ES256'],
        },
      },
    })
    const options = {
      usePreAuth: true,
    }
    const code = 'PREAUTHCODE'
    const offer = CredentialOffer({
      credential_issuer: issuer,
      credential_configuration_ids: [CredentialConfigurationId('University_Degree')],
    })
    mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
    mock.method(mockPreAuthCodeProvider, 'generate', async () => code)
    mock.method(mockPreAuthCodeStoreProvider, 'save', async () => {})
    mock.method(mockCredentialOfferProvider, 'create', async () => offer)

    const result = await issuerFlow.offerCredential(issuer, configurations, options)

    assert.ok(result)
    assert.equal(mockIssuerMetadataProvider.fetch.mock.callCount(), 1)
    assert.equal(mockPreAuthCodeProvider.generate.mock.callCount(), 1)
    assert.equal(mockPreAuthCodeStoreProvider.save.mock.callCount(), 1)
    assert.equal(mockCredentialOfferProvider.create.mock.callCount(), 1)
  })
  it('should create a credential offer with pre-authorized code with authz server', async () => {
    const metadata = CredentialIssuerMetadata({
      credential_issuer: issuer,
      credential_endpoint: 'https://example.com/credentials',
      authorization_servers: ['https://example.com/auth'],
      credential_configurations_supported: {
        VerifiableId: {
          format: 'jwt_vc_json',
          credential_definition: {
            type: ['VCKnots'],
            credentialSubject: {},
          },
          credential_signing_alg_values_supported: ['ES256'],
        },
      },
    })
    const options = {
      usePreAuth: true,
      authorization_server: 'https://example.com/auth',
    }
    const code = 'PREAUTHCODE'
    const offer = CredentialOffer({
      credential_issuer: issuer,
      authorization_server: 'https://example.com/auth',
      credential_configuration_ids: [CredentialConfigurationId('VerifiableId')],
    })
    mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
    mock.method(mockPreAuthCodeProvider, 'generate', async () => code)
    mock.method(mockPreAuthCodeStoreProvider, 'save', async () => {})
    mock.method(mockCredentialOfferProvider, 'create', async () => offer)

    const result = await issuerFlow.offerCredential(issuer, configurations, options)

    assert.ok(result)
    assert.equal(mockIssuerMetadataProvider.fetch.mock.callCount(), 1)
    assert.equal(mockPreAuthCodeProvider.generate.mock.callCount(), 1)
    assert.equal(mockPreAuthCodeStoreProvider.save.mock.callCount(), 1)
    assert.equal(mockCredentialOfferProvider.create.mock.callCount(), 1)
  })
  it(`should throw 'invalid_credential_request'  error when the provided authorization server is not found in the issuer metadata`, async () => {
    const metadata = CredentialIssuerMetadata({
      credential_issuer: issuer,
      credential_endpoint: 'https://example.com/credentials',
      authorization_servers: ['https://example.com/auth'],
      credential_configurations_supported: {
        VerifiableId: {
          format: 'jwt_vc_json',
          credential_definition: {
            type: ['VCKnots'],
            credentialSubject: {},
          },
          credential_signing_alg_values_supported: ['ES256'],
        },
      },
    })

    mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

    const suspects = async () => {
      return await issuerFlow.offerCredential(issuer, configurations, {
        usePreAuth: true,
        authorizationServer: 'https://example.com/failed',
      })
    }

    await assert.rejects(suspects, {
      name: 'invalid_credential_request',
      message: `Authorization server https://example.com/failed is not supported by issuer ${issuer}.`,
    })
  })

  it('should create a credential offer with txCode when txCode options are provided', async () => {
    const metadata: CredentialIssuerMetadata = {
      credential_issuer: issuer,
      credential_endpoint: 'https://example.com/credentials',
      credential_configurations_supported: {
        VerifiableId: {
          format: 'jwt_vc_json',
          credential_definition: {
            type: ['VCKnots'],
            credentialSubject: {},
          },
          credential_signing_alg_values_supported: ['ES256'],
        },
      },
    }
    const options = {
      usePreAuth: true,
      txCode: {
        input_mode: 'numeric' as const,
        length: 4,
        description: 'transaction code',
      },
      ttlSec: 600,
    }
    const code = 'PREAUTHCODE'
    const txCode = 1234
    const offer = CredentialOffer({
      credential_issuer: issuer,
      credential_configuration_ids: [CredentialConfigurationId('University_Degree')],
    })

    mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
    mock.method(mockPreAuthCodeProvider, 'generate', async () => code)
    mock.method(mockTransactionCodeProvider, 'generate', () => txCode)
    mock.method(mockPreAuthCodeStoreProvider, 'save', async () => {})
    mock.method(mockCredentialOfferProvider, 'create', async () => offer)

    const result = await issuerFlow.offerCredential(issuer, configurations, options)

    assert.strictEqual(result.tx_code, txCode)
    assert.equal(mockTransactionCodeProvider.generate.mock.callCount(), 1)
    assert.deepStrictEqual(mockTransactionCodeProvider.generate.mock.calls[0].arguments, [
      'numeric',
      4,
      'transaction code',
    ])
    assert.deepStrictEqual(mockPreAuthCodeStoreProvider.save.mock.calls[0].arguments, [
      code,
      configurations,
      txCode,
      {
        ttlSec: 600,
        tx_code_input_mode: 'numeric',
      },
    ])
    assert.deepStrictEqual(mockCredentialOfferProvider.create.mock.calls[0].arguments[2], {
      usePreAuth: true,
      code,
      txCode: {
        inputMode: options.txCode.input_mode,
        length: options.txCode.length,
        description: options.txCode.description,
      },
    })
  })

  describe('createNonce', () => {
    it('should create nonce, save to store, and return nonce string', async () => {
      const generatedNonce = { nonce: 'abc123def456', nonce_expires_in: 300000 }
      mock.method(mockNonceProvider, 'generate', async () => generatedNonce)
      mock.method(mockNonceStoreProvider, 'save', async () => {})

      const result = await issuerFlow.createNonce()

      assert.strictEqual(result, 'abc123def456')
      assert.equal(mockNonceProvider.generate.mock.callCount(), 1)
      assert.equal(mockNonceStoreProvider.save.mock.callCount(), 1)
      assert.deepStrictEqual(mockNonceStoreProvider.save.mock.calls[0].arguments[0], generatedNonce)
    })

    it('should pass ttlMs to generate when provided', async () => {
      const generatedNonce = { nonce: 'ttl-nonce', nonce_expires_in: 60000 }
      mock.method(mockNonceProvider, 'generate', async () => generatedNonce)
      mock.method(mockNonceStoreProvider, 'save', async () => {})

      await issuerFlow.createNonce(60000)

      assert.equal(mockNonceProvider.generate.mock.callCount(), 1)
      assert.deepStrictEqual(mockNonceProvider.generate.mock.calls[0].arguments[0], {
        nonce_expires_in: 60000,
      })
    })
  })

  describe('validateNonce', () => {
    it('should return true when nonce is valid', async () => {
      mock.method(mockNonceStoreProvider, 'validate', async () => true)

      const result = await issuerFlow.validateNonce('valid-nonce')

      assert.strictEqual(result, true)
      assert.equal(mockNonceStoreProvider.validate.mock.callCount(), 1)
      assert.deepStrictEqual(mockNonceStoreProvider.validate.mock.calls[0].arguments[0], {
        nonce: 'valid-nonce',
      })
    })

    it('should return false when nonce is invalid', async () => {
      mock.method(mockNonceStoreProvider, 'validate', async () => false)

      const result = await issuerFlow.validateNonce('invalid-nonce')

      assert.strictEqual(result, false)
      assert.equal(mockNonceStoreProvider.validate.mock.callCount(), 1)
    })

    it('should revoke nonce and return result', async () => {
      mock.method(mockNonceStoreProvider, 'revoke', async () => true)

      const result = await issuerFlow.revokeNonce('revocable-nonce')

      assert.strictEqual(result, true)
      assert.equal(mockNonceStoreProvider.revoke.mock.callCount(), 1)
      assert.deepStrictEqual(mockNonceStoreProvider.revoke.mock.calls[0].arguments[0], {
        nonce: 'revocable-nonce',
      })
    })
  })

  describe('issueCredential', () => {
    it('should issue a credential for a valid request', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: {
              jwt: {
                proof_signing_alg_values_supported: ['ES256K'],
              },
            },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'nonce' },
      }
      const keys = await generateKeyPair('ES256', { extractable: true })

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(
        mockIssueCredentialProvider,
        'createCredential',
        async () =>
          ({
            '@context': ['https://www.w3.org/ns/credentials/v2'],
            type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            issuer: issuer,
            issuanceDate: '2021-01-01T19:23:24Z',
            credentialSubject: {
              id: 'did:example:user#key-1',
              degree: {
                type: 'BachelorDegree',
                name: 'Bachelor of Science and Arts',
              },
            },
          }) as const
      )
      mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keys.publicKey)
      const issuedCredential = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        issuer: issuer,
        issuanceDate: '2021-01-01T19:23:24Z',
        credentialSubject: {
          id: 'did:example:user#key-1',
          degree: {
            type: 'BachelorDegree',
            name: 'Bachelor of Science and Arts',
          },
        },
      }
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => issuedCredential)
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )

      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])
      // 2. Act
      const response = await issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
        alg: 'ES256',
      })

      // 3. Assert
      assert.ok(response)
      assert.equal(response.credentials?.length, 1)
      assert.deepStrictEqual(response.credentials?.[0]?.credential, issuedCredential)

      // Check if mocks were called
      assert.equal(mockIssuerMetadataProvider.fetch.mock.callCount(), 1)
      assert.equal(mockCredentialProofProvider.verifyProof.mock.callCount(), 1)
      assert.equal(mockIssueCredentialProvider.createCredential.mock.callCount(), 1)
      assert.deepStrictEqual(
        mockIssueCredentialProvider.createCredential.mock.calls[0].arguments[2],
        {
          subject: 'did:example:user#key-1',
          claims: undefined,
          keyAlg: 'ES256',
          proofHeader: verifiedProof.header,
        }
      )
    })
    it('should throw "invalid_credential_request" if jti is missing', async () => {
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: {
              jwt: {
                proof_signing_alg_values_supported: ['ES256K'],
              },
            },
          },
        },
      }
      const credentialRequest = createCredentialRequest()

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, '', { alg: 'ES256' }),
        {
          name: 'invalid_credential_request',
          message: 'jti is missing.',
        }
      )

      assert.strictEqual(mockIssuanceContextStoreProvider.fetch.mock.callCount(), 0)
      assert.strictEqual(mockCredentialProofProvider.verifyProof.mock.callCount(), 0)
      assert.strictEqual(mockIssueCredentialProvider.createCredential.mock.callCount(), 0)
    })

    it('should throw "invalid_credential_request" if issuance context for jti is not found', async () => {
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: {
              jwt: {
                proof_signing_alg_values_supported: ['ES256K'],
              },
            },
          },
        },
      }
      const credentialRequest = createCredentialRequest()

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => null)

      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'missing-jti', {
          alg: 'ES256',
        }),
        {
          name: 'invalid_credential_request',
          message: 'Issuance context for this jti was not found',
        }
      )

      assert.strictEqual(mockIssuanceContextStoreProvider.fetch.mock.callCount(), 1)
      assert.deepStrictEqual(mockIssuanceContextStoreProvider.fetch.mock.calls[0].arguments, [
        'missing-jti',
      ])
      assert.strictEqual(mockCredentialProofProvider.verifyProof.mock.callCount(), 0)
      assert.strictEqual(mockIssueCredentialProvider.createCredential.mock.callCount(), 0)
    })

    it('should throw "invalid_credential_request" if requested credential configuration is not allowed for the jti', async () => {
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: {
              jwt: {
                proof_signing_alg_values_supported: ['ES256K'],
              },
            },
          },
        },
      }
      const credentialRequest = createCredentialRequest()

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => [
        'EmployeeID_JWT' as CredentialConfigurationId,
      ])

      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
          alg: 'ES256',
        }),
        {
          name: 'invalid_credential_request',
          message: 'Requested credential_configuration_id is not allowed for this jti.',
        }
      )

      assert.strictEqual(mockIssuanceContextStoreProvider.fetch.mock.callCount(), 1)
      assert.strictEqual(mockCredentialProofProvider.verifyProof.mock.callCount(), 0)
      assert.strictEqual(mockIssueCredentialProvider.createCredential.mock.callCount(), 0)
    })

    it('should pass auth-code JWT verify context to credential proof provider when proofJwt is omitted', async () => {
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: {
              jwt: {
                proof_signing_alg_values_supported: ['ES256K'],
              },
            },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'nonce' },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => 'signed.jwt')
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])
      await issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
        alg: 'ES256',
      })

      assert.equal(mockCredentialProofProvider.verifyProof.mock.callCount(), 1)
      const verifyArgs = mockCredentialProofProvider.verifyProof.mock.calls[0].arguments
      assert.strictEqual(verifyArgs[0], 'dummy-proof-jwt')
      assert.deepStrictEqual(verifyArgs[1], {
        usePreAuth: false,
        credentialIssuer: issuer,
        clientId: undefined,
      })
    })

    it('should pass pre-auth JWT verify context when options.proofJwt.usePreAuth is true', async () => {
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: {
              jwt: {
                proof_signing_alg_values_supported: ['ES256K'],
              },
            },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { aud: issuer, nonce: 'nonce' },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => 'signed.jwt')
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      await issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
        alg: 'ES256',
        proofJwt: { usePreAuth: true },
      })

      assert.deepStrictEqual(mockCredentialProofProvider.verifyProof.mock.calls[0].arguments[1], {
        usePreAuth: true,
        credentialIssuer: issuer,
      })
    })

    it('should pass clientId in JWT verify context for authorization-code-style flow', async () => {
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: {
              jwt: {
                proof_signing_alg_values_supported: ['ES256K'],
              },
            },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'nonce' },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => 'signed.jwt')
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      await issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
        alg: 'ES256',
        proofJwt: { usePreAuth: false, clientId: 'oauth-client-1' },
      })

      assert.deepStrictEqual(mockCredentialProofProvider.verifyProof.mock.calls[0].arguments[1], {
        usePreAuth: false,
        credentialIssuer: issuer,
        clientId: 'oauth-client-1',
      })
    })

    it('should issue a credential with claims for a valid request', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: {
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
              credentialSubject: {
                given_name: {},
                family_name: {},
              },
            },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: {
              jwt: {
                proof_signing_alg_values_supported: ['ES256K'],
              },
            },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const claims = {
        given_name: 'John',
        family_name: 'Doe',
      }
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'nonce' },
      }
      const signedCredential = 'signed.credential.jwt'
      const keys = await generateKeyPair('ES256', { extractable: true })
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(
        mockIssueCredentialProvider,
        'createCredential',
        async () => 'signed.credential.jwt'
      )
      mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keys.publicKey)
      mock.method(mockIssuerKeyStoreProvider, 'sign', async () => signedCredential)
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      // 2. Act
      const response = await issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
        alg: 'ES256',
        claims,
      })

      // 3. Assert
      assert.ok(response)
      assert.equal(mockIssueCredentialProvider.createCredential.mock.callCount(), 1)
      const createCredentialArgs =
        mockIssueCredentialProvider.createCredential.mock.calls[0].arguments
      assert.deepStrictEqual(createCredentialArgs[2], {
        subject: 'did:example:user#key-1',
        claims,
        keyAlg: 'ES256',
        proofHeader: verifiedProof.header,
      })
    })

    it('should throw "issuer_not_found" if issuer metadata is not found', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const credentialRequest = createCredentialRequest()

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => null)

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', { alg: 'ES256' }),
        {
          name: 'issuer_not_found',
        }
      )
      assert.equal(mockIssuerMetadataProvider.fetch.mock.callCount(), 1)
    })

    it('should throw "invalid_credential_request" if credential configuration id is not specified', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          University_Degree: {
            format: 'jwt_vc_json',
            credential_definition: {
              type: ['VCKnots'],
              credentialSubject: {},
            },
            credential_signing_alg_values_supported: ['ES256'],
          },
        },
      }
      const credentialRequest = createCredentialRequest({
        credential_configuration_id: undefined,
      })

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', { alg: 'ES256' }),
        {
          name: 'invalid_credential_request',
          message: 'Credential configuration id is not specified.',
        }
      )
    })

    it('should throw "unknown_credential_configuration" if requested configuration is not supported', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          Some_Other_Degree: {
            format: 'jwt_vc_json',
            credential_definition: {
              type: ['VerifiableCredential', 'SomeOtherCredential'],
              credentialSubject: {},
            },
            credential_signing_alg_values_supported: ['ES256'],
          },
        },
      }
      const credentialRequest = createCredentialRequest()

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', { alg: 'ES256' }),
        {
          name: 'unknown_credential_configuration',
        }
      )
    })

    it('should throw "unknown_credential_configuration" if requested configuration id is not supported', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        credential_configurations_supported: {
          Some_Other_Degree: {
            // Different type
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: {
              type: ['VerifiableCredential', 'SomeOtherCredential'],
            },
          },
        },
      }
      const credentialRequest = createCredentialRequest()

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', { alg: 'ES256' }),
        {
          name: 'unknown_credential_configuration',
        }
      )
    })

    it('should throw "invalid_credential_request" if proofs are missing', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest({
        proofs: undefined,
      })
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
          alg: 'ES256',
        }),
        {
          name: 'invalid_credential_request',
          message: 'Proof is required to issue credential.',
        }
      )
    })

    it('should throw if proofs object has no supported proof entries', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest({
        proofs: {} as CredentialRequest['proofs'],
      })
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', { alg: 'ES256' }),
        {
          message: 'Unsupported proof type',
        }
      )
    })

    it('should throw "invalid_credential_request" if proof type is not supported in metadata', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            proof_types_supported: { 'some-other-type': {} }, // jwt is not supported
          },
        },
      }
      const credentialRequest = createCredentialRequest({
        proofs: { jwt: ['dummy-jwt'] },
      })
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', { alg: 'ES256' }),
        {
          name: 'invalid_credential_request',
          message: 'Request contain no proofs supported by credential configuration.',
        }
      )
    })

    it('should throw "invalid_proof" if proof verification fails', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest({
        proofs: { jwt: ['dummy-jwt'] },
      })
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => null) // Verification fails
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', { alg: 'ES256' }),
        {
          name: 'invalid_proof',
          message: 'Failed to verify Proof.',
        }
      )
    })

    it('should issue a credential when verified proof header has no kid (e.g. jwk/x5c binding)', async () => {
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest({
        proofs: { jwt: ['dummy-jwt'] },
      })
      const verifiedProofWithoutKid = {
        header: { alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'nonce' },
      }
      const signedCredential = 'signed.credential.jwt'
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProofWithoutKid)
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => signedCredential)
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])
      const response = await issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
        alg: 'ES256',
      })

      assert.ok(response)
      assert.equal(response.credentials?.[0]?.credential, signedCredential)
      assert.equal(mockIssueCredentialProvider.createCredential.mock.callCount(), 1)
      assert.deepStrictEqual(
        mockIssueCredentialProvider.createCredential.mock.calls[0].arguments[2],
        {
          subject: undefined,
          claims: undefined,
          keyAlg: 'ES256',
          proofHeader: verifiedProofWithoutKid.header,
        }
      )
    })

    it('should issue a credential when a valid c_nonce proof is provided', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'generated-cnonce' },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockNonceStoreProvider, 'validate', async () => true)
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => ({ id: 'cred-id' }))
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])
      const nonceSaveCallCountBefore = mockNonceStoreProvider.save.mock.callCount()

      // 2. Act
      const response = await issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
        alg: 'ES256',
        cnonce: { c_nonce_expires_in: 300 },
      })

      // 3. Assert
      assert.ok(response)
      assert.equal(response.credentials?.length, 1)
      assert.equal(mockNonceStoreProvider.validate.mock.callCount(), 1)
      assert.equal(mockNonceStoreProvider.revoke.mock.callCount(), 1)
      assert.deepStrictEqual(mockNonceStoreProvider.validate.mock.calls.at(-1)?.arguments.at(0), {
        nonce: 'generated-cnonce',
      })
      assert.deepStrictEqual(mockNonceStoreProvider.revoke.mock.calls.at(-1)?.arguments.at(0), {
        nonce: 'generated-cnonce',
      })
      assert.equal(mockNonceStoreProvider.save.mock.callCount(), nonceSaveCallCountBefore)
    })

    it('should still issue a credential even if cnonce revoke returns false', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'generated-cnonce' },
      }

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockNonceStoreProvider, 'validate', async () => true)
      mock.method(mockNonceStoreProvider, 'revoke', async () => false)
      mock.method(
        mockIssueCredentialProvider,
        'createCredential',
        async () => 'signed.credential.jwt'
      )
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])
      const nonceSaveCallCountBefore = mockNonceStoreProvider.save.mock.callCount()

      // 2. Act
      const response = await issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
        alg: 'ES256',
        cnonce: { c_nonce_expires_in: 300 },
      })

      // 3. Assert
      assert.ok(response)
      assert.equal(response.credentials?.length, 1)
      assert.equal(mockNonceStoreProvider.validate.mock.callCount(), 1)
      assert.equal(mockNonceStoreProvider.revoke.mock.callCount(), 1)
      assert.deepStrictEqual(mockNonceStoreProvider.validate.mock.calls.at(-1)?.arguments.at(0), {
        nonce: 'generated-cnonce',
      })
      assert.deepStrictEqual(mockNonceStoreProvider.revoke.mock.calls.at(-1)?.arguments.at(0), {
        nonce: 'generated-cnonce',
      })
      assert.equal(mockNonceStoreProvider.save.mock.callCount(), nonceSaveCallCountBefore)
    })

    it('should throw "invalid_nonce" if cnonce is invalid', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'generated-cnonce' },
      }

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockNonceStoreProvider, 'validate', async () => false) // Nonce is invalid
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
          alg: 'ES256',
          cnonce: { c_nonce_expires_in: 300 },
        }),
        { name: 'invalid_nonce', message: 'Nonce not found.' }
      )
    })

    it('should throw "unsupported_issuer_key_alg" if signing alg is not supported', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            credential_signing_alg_values_supported: ['ES256'], // Only ES256 is supported
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1' },
        payload: { iss: 'did:example:user', aud: issuer },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => {
        throw Object.assign(new Error('Unsupported key algorithm.'), {
          name: 'unsupported_issuer_key_alg',
        })
      })
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', { alg: 'RS256' }), // Requesting unsupported alg
        { name: 'unsupported_issuer_key_alg' }
      )
    })

    it('should allow signing alg check to pass when credential_signing_alg_values_supported is absent', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1' },
        payload: { iss: 'did:example:user', aud: issuer },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => {
        throw Object.assign(new Error('Issuer key not found.'), {
          name: 'authz_issuer_key_not_found',
        })
      })
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])
      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', { alg: 'ES256' }),
        { name: 'authz_issuer_key_not_found' }
      )
    })

    it('should issue a credential even if signing key is not found', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1' },
        payload: { iss: 'did:example:user', aud: issuer },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      const issuedCredential = { id: 'cred-id' }
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => issuedCredential)
      mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => null) // No keys found
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      const response = await issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
        alg: 'ES256',
      })

      assert.deepStrictEqual(response, {
        credentials: [{ credential: issuedCredential }],
      })
    })

    it('should issue a credential even if signing returns null', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata = {
        credential_issuer: issuer,
        credential_configurations_supported: {
          University_Degree: {
            format: CredentialFormats.JWT_VC_JSON,
            credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256K'] } },
          },
        },
      }
      const credentialRequest = createCredentialRequest()
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1' },
        payload: { iss: 'did:example:user', aud: issuer },
      }
      const keys = await generateKeyPair('ES256', { extractable: true })
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      const issuedCredential = { id: 'cred-id' }
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => issuedCredential)
      mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keys.publicKey)
      mock.method(mockIssuerKeyStoreProvider, 'sign', async () => null) // Signing returns null
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mock.method(mockIssuanceContextStoreProvider, 'fetch', async () => ['University_Degree'])

      const response = await issuerFlow.issueCredential(issuer, credentialRequest, 'test-jti', {
        alg: 'ES256',
      })

      assert.deepStrictEqual(response, {
        credentials: [{ credential: issuedCredential }],
      })
    })
  })
  describe('rejectInsecureIssuerMetadata', () => {
    const insecureMetadata: CredentialIssuerMetadata = {
      credential_issuer: CredentialIssuer('did:example:issuer'),
      credential_endpoint: 'http://example.com/credentials',
      credential_configurations_supported: {},
    }

    it('should throw insecure_http_not_allowed for http credential_endpoint', async () => {
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => insecureMetadata)

      await assert.rejects(issuerFlow.findIssuerMetadata(CredentialIssuer('did:example:issuer')), {
        name: 'insecure_http_not_allowed',
        message:
          'CredentialIssuerMetadata contains insecure http url in credential_endpoint: http://example.com/credentials',
      })
    })

    it('should throw insecure_http_not_allowed for http deferred_credential_endpoint', async () => {
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: CredentialIssuer('did:example:issuer'),
        credential_endpoint: 'https://example.com/credentials',
        deferred_credential_endpoint: 'http://example.com/deferred',
        credential_configurations_supported: {},
      }

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      await assert.rejects(issuerFlow.findIssuerMetadata(CredentialIssuer('did:example:issuer')), {
        name: 'insecure_http_not_allowed',
        message:
          'CredentialIssuerMetadata contains insecure http url in deferred_credential_endpoint: http://example.com/deferred',
      })
    })

    it('should allow insecure http when debug is true', async () => {
      const debugContext = initializeContext({
        providers: [
          mockIssuerMetadataProvider,
          mockPreAuthCodeProvider,
          mockPreAuthCodeStoreProvider,
          mockIssueCredentialProvider,
          mockIssuerKeyStoreProvider,
          mockCredentialOfferProvider,
          mockCredentialProofProvider,
          mockNonceProvider,
          mockNonceStoreProvider,
          mockTransactionCodeProvider,
        ],
        debug: true,
      })

      const debugIssuerFlow = initializeIssuerFlow(debugContext)

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => insecureMetadata)

      const result = await debugIssuerFlow.findIssuerMetadata(
        CredentialIssuer('did:example:issuer')
      )

      assert.deepStrictEqual(result, insecureMetadata)
    })
  })
})
