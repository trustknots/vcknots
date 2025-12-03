import assert from 'node:assert/strict'
import { before, describe, it, mock } from 'node:test'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialIssuerMetadata,
} from '../src/credential-issuer.types'
import { CredentialOffer } from '../src/credential-offer.types'
import { CredentialFormats, CredentialRequest, ProofTypes } from '../src/credential-request.types'
import { IssuerFlow, initializeIssuerFlow } from '../src/issuer.flows'
import {
  CnonceProvider,
  CnonceStoreProvider,
  CredentialOfferProvider,
  CredentialProofProvider,
  IssueCredentialProvider,
  IssuerMetadataStoreProvider,
  IssuerSignatureKeyProvider,
  IssuerSignatureKeyStoreProvider,
  PreAuthorizedCodeProvider,
  PreAuthorizedCodeStoreProvider,
} from '../src/providers'
import { SignatureKeyPair } from '../src/signature-key.types'
import { Jwk } from '../src/jwk.type'
import { VcknotsContext, initializeContext } from '../src/vcknots.context'

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
    validate: mock.fn(),
    delete: mock.fn(),
  } satisfies PreAuthorizedCodeStoreProvider

  const mockIssuerKeyStoreProvider = {
    kind: 'issuer-signature-key-store-provider',
    name: 'mock-issuer-key-store-provider',
    single: true,
    save: mock.fn(),
    fetch: mock.fn(),
  } satisfies IssuerSignatureKeyStoreProvider

  const mockIssuerSignatureKeyProvider = {
    kind: 'issuer-signature-key-provider',
    name: 'mock-issuer-signature-key-provider',
    single: false,
    generate: mock.fn(),
    sign: mock.fn(),
    canHandle: mock.fn(),
  } satisfies IssuerSignatureKeyProvider

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

  before(() => {
    context = initializeContext({
      providers: [
        mockIssuerMetadataProvider,
        mockPreAuthCodeProvider,
        mockPreAuthCodeStoreProvider,
        mockIssueCredentialProvider,
        mockIssuerKeyStoreProvider,
        mockIssuerSignatureKeyProvider,
        mockCredentialOfferProvider,
        mockCredentialProofProvider,
        mockCnonceProvider,
        mockCnonceStoreProvider,
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
    const keyPair: SignatureKeyPair = {
      privateKey: { alg: 'ES256', kty: 'EC' } as Jwk,
      publicKey: { alg: 'ES256', kty: 'EC', kid: 'key-1' } as Jwk,
    }
    mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])

    const found = await issuerFlow.findJwtVcIssuerMetadata(issuer)

    assert.deepStrictEqual(found, {
      issuer: issuer,
      jwks: {
        keys: [keyPair.publicKey],
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
    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [])

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
    const keyPair: SignatureKeyPair = {
      privateKey: { alg: 'ES256', kty: 'EC' } as Jwk,
      publicKey: { alg: 'ES256', kty: 'EC' } as Jwk,
    }
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')
    mockIssuerSignatureKeyProvider.generate.mock.mockImplementation(async () => keyPair)

    await issuerFlow.createIssuerMetadata(metadata)

    assert.equal(mockIssuerMetadataProvider.save.mock.callCount(), 1, 'store.save should be called')
    assert.deepStrictEqual(mockIssuerMetadataProvider.save.mock.calls[0].arguments[0], metadata)

    assert.equal(
      mockIssuerSignatureKeyProvider.generate.mock.callCount(),
      1,
      'keyGenerator.generateKeyPair should be called'
    )

    assert.equal(
      mockIssuerKeyStoreProvider.save.mock.callCount(),
      1,
      'keyStore.save should be called'
    )
    assert.deepStrictEqual(mockIssuerKeyStoreProvider.save.mock.calls[0].arguments[0], issuer)
    assert.deepStrictEqual(mockIssuerKeyStoreProvider.save.mock.calls[0].arguments[1], [keyPair])
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
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation(() => false)

    await assert.rejects(issuerFlow.createIssuerMetadata(metadata), {
      name: 'PROVIDER_NOT_FOUND',
      message: 'No provider found which can handle: RS256',
    })
  })

  const issuer = CredentialIssuer('did:example:issuer')
  const configurations = [CredentialConfigurationId('VerifiableId')]

  it('should throw "FEATURE_NOT_IMPLEMENTED_YET" if usePreAuth is false', async () => {
    const suspects = async () => {
      return await issuerFlow.offerCredential(issuer, configurations, {
        usePreAuth: false,
      })
    }

    assert.rejects(suspects, 'FEATURE_NOT_IMPLEMENTED_YET')
  })

  it('should throw "ISSUER_NOT_FOUND" if issuer metadata is not found when usePreAuth is true', async () => {
    mock.method(mockIssuerMetadataProvider, 'fetch', async () => null)

    const suspects = async () => {
      return await issuerFlow.offerCredential(issuer, configurations, { usePreAuth: true })
    }

    assert.rejects(suspects, 'ISSUER_NOT_FOUND')
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: {
          type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        },
        proof: {
          proof_type: ProofTypes.JWT,
          jwt: 'dummy-proof-jwt',
        },
      }
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'nonce' },
      }
      const keyPair: SignatureKeyPair = {
        privateKey: { alg: 'ES256', kty: 'EC' } as Jwk,
        publicKey: { alg: 'ES256', kty: 'EC' } as Jwk,
      }
      const signedCredential = 'signed.credential.jwt'

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
      mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
      mock.method(
        mockIssuerSignatureKeyProvider,
        'sign',
        async (privatekey: Jwk, alg: string, payload: unknown, header: unknown) => signedCredential
      )
      mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )

      // 2. Act
      const response = await issuerFlow.issueCredential(issuer, credentialRequest, { alg: 'ES256' })

      // 3. Assert
      assert.ok(response)
      assert.strictEqual(
        response.credential,
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6e30sInN1YiI6ImRpZDpleGFtcGxlOnVzZXIja2V5LTEifQ.signed.credential.jwt'
      )
      assert.strictEqual(response.c_nonce, undefined)
      assert.ok(response.c_nonce_expires_in)

      // Check if mocks were called
      assert.equal(mockIssuerMetadataProvider.fetch.mock.callCount(), 1)
      assert.equal(mockCredentialProofProvider.verifyProof.mock.callCount(), 1)
      assert.equal(mockIssueCredentialProvider.createCredential.mock.callCount(), 1)
      assert.equal(mockIssuerKeyStoreProvider.fetch.mock.callCount(), 1)
      assert.equal(mockIssuerSignatureKeyProvider.sign.mock.callCount(), 1)
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: {
          type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        },
        proof: {
          proof_type: ProofTypes.JWT,
          jwt: 'dummy-proof-jwt',
        },
      }
      const claims = {
        given_name: 'John',
        family_name: 'Doe',
      }
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'nonce' },
      }
      const keyPair: SignatureKeyPair = {
        privateKey: { alg: 'ES256', kty: 'EC' } as Jwk,
        publicKey: { alg: 'ES256', kty: 'EC' } as Jwk,
      }
      const signedCredential = 'signed.credential.jwt'

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
              given_name: 'John',
              family_name: 'Doe',
            },
          }) as const
      )
      mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
      mock.method(
        mockIssuerSignatureKeyProvider,
        'sign',
        async (privatekey: Jwk, alg: string, payload: unknown, header: unknown) => signedCredential
      )
      mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )

      // 2. Act
      const response = await issuerFlow.issueCredential(issuer, credentialRequest, {
        alg: 'ES256',
        claims,
      })

      // 3. Assert
      assert.ok(response)
      assert.equal(mockIssueCredentialProvider.createCredential.mock.callCount(), 1)
      const createCredentialArgs =
        mockIssueCredentialProvider.createCredential.mock.calls[0].arguments
      assert.deepStrictEqual(createCredentialArgs[3], claims)
    })

    it('should throw "ISSUER_NOT_FOUND" if issuer metadata is not found', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: {
          type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        },
        proof: {
          proof_type: ProofTypes.JWT,
          jwt: 'dummy-proof-jwt',
        },
      }

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => null)

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, { alg: 'ES256' }),
        {
          name: 'ISSUER_NOT_FOUND',
        }
      )
      assert.equal(mockIssuerMetadataProvider.fetch.mock.callCount(), 1)
    })

    it('should throw "INVALID_REQUEST" if format is not specified', async () => {
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
      const credentialRequest: CredentialRequest = {
        // format is missing
        credential_definition: {
          type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        },
        proof: {
          proof_type: ProofTypes.JWT,
          jwt: 'dummy-proof-jwt',
        },
      }

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, { alg: 'ES256' }),
        {
          name: 'INVALID_REQUEST',
          message: 'Credential request format is not specified.',
        }
      )
    })

    it('should throw "UNSUPPORTED_CREDENTIAL_TYPE" if no configurations are supported', async () => {
      // 1. Arrange
      const issuer = CredentialIssuer('did:example:issuer')
      const metadata: CredentialIssuerMetadata = {
        credential_issuer: issuer,
        credential_endpoint: 'https://example.com/credentials',
        // credential_configurations_supported is missing
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: {
          type: ['VerifiableCredential', 'UniversityDegreeCredential'],
        },
        proof: {
          proof_type: ProofTypes.JWT,
          jwt: 'dummy-proof-jwt',
        },
      }

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, { alg: 'ES256' }),
        {
          name: 'UNSUPPORTED_CREDENTIAL_TYPE',
        }
      )
    })

    it('should throw "UNSUPPORTED_CREDENTIAL_TYPE" if requested type is not supported', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: {
          type: ['VerifiableCredential', 'UniversityDegreeCredential'], // This one is not in metadata
        },
        proof: {
          proof_type: ProofTypes.JWT,
          jwt: 'dummy-proof-jwt',
        },
      }

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, { alg: 'ES256' }),
        {
          name: 'UNSUPPORTED_CREDENTIAL_TYPE',
        }
      )
    })

    it('should throw "INVALID_CREDENTIAL_REQUEST" if proof is missing', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
        // proof is missing
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      // 2. Act & 3. Assert
      await assert.rejects(issuerFlow.issueCredential(issuer, credentialRequest), {
        name: 'INVALID_CREDENTIAL_REQUEST',
        message: 'No proof object found.',
      })
    })

    it('should throw "INVALID_CREDENTIAL_REQUEST" if proof jwt is missing', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
        proof: { proof_type: ProofTypes.JWT, jwt: undefined }, // jwt is missing
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      // 2. Act & 3. Assert
      await assert.rejects(issuerFlow.issueCredential(issuer, credentialRequest), {
        name: 'INVALID_CREDENTIAL_REQUEST',
        message: 'No proof object found.',
      })
    })

    it('should throw "INVALID_CREDENTIAL_REQUEST" if proof type is not supported in metadata', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
        proof: { proof_type: ProofTypes.JWT, jwt: 'dummy-jwt' },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)

      // 2. Act & 3. Assert
      await assert.rejects(issuerFlow.issueCredential(issuer, credentialRequest), {
        name: 'INVALID_CREDENTIAL_REQUEST',
        message: 'Request contain no proofs supported by credential configuration.',
      })
    })

    it('should throw "INVALID_PROOF" if proof verification fails', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
        proof: { proof_type: ProofTypes.JWT, jwt: 'dummy-jwt' },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => null) // Verification fails
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )

      // 2. Act & 3. Assert
      await assert.rejects(issuerFlow.issueCredential(issuer, credentialRequest), {
        name: 'INVALID_PROOF',
        message: 'Failed to verify Proof.',
      })
    })

    it('should throw "INVALID_PROOF" if verified proof has no kid in header', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
        proof: { proof_type: ProofTypes.JWT, jwt: 'dummy-jwt' },
      }
      const verifiedProofWithoutKid = {
        header: { alg: 'ES256K' }, // kid is missing
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'nonce' },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProofWithoutKid)
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )

      // 2. Act & 3. Assert
      await assert.rejects(issuerFlow.issueCredential(issuer, credentialRequest), {
        name: 'INVALID_PROOF',
        message: 'Unsupported proof header.',
      })
    })

    it('should issue a credential with a new c_nonce when a valid one is provided', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
        proof: { proof_type: ProofTypes.JWT, jwt: 'dummy-proof-jwt' },
      }
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'valid-nonce' },
      }
      const keyPair = {
        privateKey: { alg: 'ES256' },
        publicKey: { alg: 'ES256' },
      } as SignatureKeyPair
      const newNonce = 'new-nonce-123'

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockCnonceStoreProvider, 'validate', async () => true) // Nonce is valid
      mock.method(mockCnonceStoreProvider, 'revoke', async () => {})
      mock.method(mockCnonceProvider, 'generate', async () => newNonce)
      mock.method(mockCnonceStoreProvider, 'save', async () => {})
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => ({ id: 'cred-id' }))
      mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
      mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signed.credential.jwt')
      mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )

      // 2. Act
      const response = await issuerFlow.issueCredential(issuer, credentialRequest, {
        alg: 'ES256',
        cnonce: { c_nonce_expires_in: 300 },
      })

      // 3. Assert
      assert.ok(response)
      assert.equal(response.c_nonce, newNonce)
      assert.equal(mockCnonceStoreProvider.validate.mock.callCount(), 1)
      assert.equal(mockCnonceStoreProvider.revoke.mock.callCount(), 1)
      assert.equal(mockCnonceProvider.generate.mock.callCount(), 1)
      assert.equal(mockCnonceStoreProvider.save.mock.callCount(), 1)
    })

    it('should throw "INVALID_PROOF" if cnonce is invalid', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
        proof: { proof_type: ProofTypes.JWT, jwt: 'dummy-proof-jwt' },
      }
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1', alg: 'ES256K' },
        payload: { iss: 'did:example:user', aud: issuer, nonce: 'invalid-nonce' },
      }

      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockCnonceStoreProvider, 'validate', async () => false) // Nonce is invalid
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, {
          alg: 'ES256',
          cnonce: { c_nonce_expires_in: 300 },
        }),
        { name: 'INVALID_PROOF', message: 'Nonce not found.' }
      )
    })

    it('should throw "UNSUPPORTED_ISSUER_KEY_ALG" if signing alg is not supported', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
        proof: { proof_type: ProofTypes.JWT, jwt: 'dummy-proof-jwt' },
      }
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1' },
        payload: { iss: 'did:example:user', aud: issuer },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => ({ id: 'cred-id' }))
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, { alg: 'RS256' }), // Requesting unsupported alg
        { name: 'UNSUPPORTED_ISSUER_KEY_ALG' }
      )
    })

    it('should throw "AUTHZ_ISSUER_KEY_NOT_FOUND" if signing key is not found', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
        proof: { proof_type: ProofTypes.JWT, jwt: 'dummy-proof-jwt' },
      }
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1' },
        payload: { iss: 'did:example:user', aud: issuer },
      }
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => ({ id: 'cred-id' }))
      mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => []) // No keys found
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, { alg: 'ES256' }),
        { name: 'AUTHZ_ISSUER_KEY_NOT_FOUND' }
      )
    })

    it('should throw "INTERNAL_SERVER_ERROR" if signing fails', async () => {
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
      const credentialRequest: CredentialRequest = {
        format: CredentialFormats.JWT_VC_JSON,
        credential_definition: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] },
        proof: { proof_type: ProofTypes.JWT, jwt: 'dummy-proof-jwt' },
      }
      const verifiedProof = {
        header: { kid: 'did:example:user#key-1' },
        payload: { iss: 'did:example:user', aud: issuer },
      }
      const keyPair = {
        privateKey: { alg: 'ES256' },
        publicKey: { alg: 'ES256' },
      } as SignatureKeyPair
      mock.method(mockIssuerMetadataProvider, 'fetch', async () => metadata)
      mock.method(mockCredentialProofProvider, 'verifyProof', async () => verifiedProof)
      mock.method(mockIssueCredentialProvider, 'createCredential', async () => ({ id: 'cred-id' }))
      mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
      mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => null) // Signing returns null
      mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')
      mockCredentialProofProvider.canHandle.mock.mockImplementation(
        (type) => type === ProofTypes.JWT
      )
      mockIssueCredentialProvider.canHandle.mock.mockImplementation(
        (format) => format === CredentialFormats.JWT_VC_JSON
      )

      // 2. Act & 3. Assert
      await assert.rejects(
        issuerFlow.issueCredential(issuer, credentialRequest, { alg: 'ES256' }),
        { name: 'INTERNAL_SERVER_ERROR' }
      )
    })
  })
})
