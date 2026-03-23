import assert from 'node:assert/strict'
import { describe, it, mock } from 'node:test'
import { CredentialConfiguration, CredentialIssuer } from '../../src/credential-issuer.types'
import { VcknotsError } from '../../src/errors/vcknots.error'
import { Jwk } from '../../src/jwk.type'
import { CredentialFormats } from '../../src/credential-request.types'
import { SignatureKeyPair } from '../../src/signature-key.types'
import { issueCredentialJwt } from '../../src/providers/issue-credential-jwt-vc-json.provider'
import {
  IssueCredentialProvider,
  IssuerSignatureKeyProvider,
  IssuerSignatureKeyStoreProvider,
} from '../../src/providers/provider.types'
import { WithProviderRegistry } from '../../src/providers/provider.registry'

const decodeJwtSegment = (segment: string) =>
  JSON.parse(Buffer.from(segment, 'base64url').toString())

describe('issueCredential', () => {
  const credentialIssuer = CredentialIssuer('https://issuer.example.com')
  const configuration: CredentialConfiguration = {
    format: 'jwt_vc_json',
    credential_definition: {
      type: ['VerifiableCredential', 'UniversityDegreeCredential'],
      credentialSubject: {
        given_name: {
          display: [
            {
              name: 'Given Name',
              locale: 'en-US',
            },
          ],
        },
        family_name: {
          display: [
            {
              name: 'Surname',
              locale: 'en-US',
            },
          ],
        },
        degree: {},
        gpa: {
          display: [
            {
              name: 'GPA',
            },
          ],
        },
      },
    },
    display: [
      {
        name: 'University Degree',
        locale: 'en-US',
        logo: {
          uri: 'https://example.com/logo.png',
          alt_text: 'University Logo',
        },
        background_color: '#12107c',
        text_color: '#FFFFFF',
      },
    ],
  }

  const createProvider = () => {
    const provider = issueCredentialJwt() as IssueCredentialProvider & WithProviderRegistry
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

    provider.providers = {
      get(kind) {
        if (kind === 'issuer-signature-key-store-provider') {
          return mockIssuerKeyStoreProvider
        }
        if (kind === 'issuer-signature-key-provider') {
          return [mockIssuerSignatureKeyProvider]
        }
        throw new Error(`Unexpected provider kind: ${kind}`)
      },
      select() {
        throw new Error('select is not used in this provider')
      },
    } as WithProviderRegistry['providers']

    return { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider }
  }

  it('should have correct kind, name, and single properties', () => {
    const { provider } = createProvider()

    assert.equal(provider.kind, 'issue-credential-provider')
    assert.equal(provider.name, 'default-issue-credential-w3c-jwt-vc-json-provider')
    assert.strictEqual(provider.single, false)
  })

  it('should handle jwt_vc_json format', () => {
    const { provider } = createProvider()

    assert.ok(provider.canHandle(CredentialFormats.JWT_VC_JSON))
  })

  it('should not handle other formats', () => {
    const { provider } = createProvider()

    assert.ok(!provider.canHandle(CredentialFormats.LDP_VC))
  })

  it('should create a signed verifiable credential jwt', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()
    const keyPair: SignatureKeyPair = {
      privateKey: { alg: 'ES256', kty: 'EC', kid: 'issuer-key-1' } as Jwk,
      publicKey: { alg: 'ES256', kty: 'EC', kid: 'issuer-key-1' } as Jwk,
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signedjwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    const credential = await provider.createCredential(credentialIssuer, configuration, {
      subject: 'did:example:123#key-1',
      keyAlg: 'ES256',
    })

    const [headerSegment, payloadSegment, signature] = credential.split('.')
    const header = decodeJwtSegment(headerSegment)
    const payload = decodeJwtSegment(payloadSegment)

    assert.equal(signature, 'signedjwt')
    assert.deepStrictEqual(header, { alg: 'ES256', typ: 'JWT' })
    assert.equal(payload.iss, credentialIssuer)
    assert.equal(payload.sub, 'did:example:123#key-1')
    assert.equal(payload.vc.id.startsWith(`${credentialIssuer}/vc/`), true)
    assert.deepEqual(payload.vc.type, ['VerifiableCredential', 'UniversityDegreeCredential'])
    assert.equal(payload.vc.credentialSubject.id, 'did:example:123#key-1')
    assert.equal(mockIssuerKeyStoreProvider.fetch.mock.callCount(), 1)
    assert.equal(mockIssuerSignatureKeyProvider.sign.mock.callCount(), 1)
  })

  it('should create a signed verifiable credential jwt with claims', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()
    const keyPair: SignatureKeyPair = {
      privateKey: { alg: 'ES256', kty: 'EC' } as Jwk,
      publicKey: { alg: 'ES256', kty: 'EC' } as Jwk,
    }
    const claims = {
      given_name: 'John',
      family_name: 'Doe',
      degree: 'Bachelor of Science',
      gpa: '4.0',
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signedjwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    const credential = await provider.createCredential(credentialIssuer, configuration, {
      subject: 'did:example:123#key-1',
      claims,
    })

    const payload = decodeJwtSegment(credential.split('.')[1])

    assert.equal(payload.vc.credentialSubject.given_name, 'John')
    assert.equal(payload.vc.credentialSubject.family_name, 'Doe')
    assert.equal(payload.vc.credentialSubject.degree, 'Bachelor of Science')
    assert.equal(payload.vc.credentialSubject.gpa, '4.0')
  })

  it('should throw error if mandatory claim is missing', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()
    const configurationWithMandatory: CredentialConfiguration = {
      ...configuration,
      credential_definition: {
        ...configuration.credential_definition,
        credentialSubject: {
          ...configuration.credential_definition.credentialSubject,
          given_name: {
            ...configuration.credential_definition.credentialSubject?.given_name,
            mandatory: true,
          },
        },
      },
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signedjwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    await assert.rejects(
      provider.createCredential(credentialIssuer, configurationWithMandatory, {
        subject: 'did:example:123#key-1',
        claims: { family_name: 'Doe' },
      }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_CLAIMS')
        return true
      }
    )
  })

  it('should throw error if a mandatory claim is missing when multiple mandatory claims exist', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()
    const configurationWithMandatory: CredentialConfiguration = {
      ...configuration,
      credential_definition: {
        ...configuration.credential_definition,
        credentialSubject: {
          ...configuration.credential_definition.credentialSubject,
          given_name: {
            ...configuration.credential_definition.credentialSubject?.given_name,
            mandatory: true,
          },
          family_name: {
            ...configuration.credential_definition.credentialSubject?.family_name,
            mandatory: true,
          },
        },
      },
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signedjwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    await assert.rejects(
      provider.createCredential(credentialIssuer, configurationWithMandatory, {
        subject: 'did:example:123#key-1',
        claims: { given_name: 'John' },
      }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_CLAIMS')
        return true
      }
    )
  })

  it('should cast claims to correct type', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()
    const configurationWithTypes: CredentialConfiguration = {
      ...configuration,
      credential_definition: {
        ...configuration.credential_definition,
        credentialSubject: {
          ...configuration.credential_definition.credentialSubject,
          given_name: {
            value_type: 'string',
          },
          age: {
            value_type: 'number',
          },
        },
      },
    }
    const keyPair: SignatureKeyPair = {
      privateKey: { alg: 'ES256', kty: 'EC' } as Jwk,
      publicKey: { alg: 'ES256', kty: 'EC' } as Jwk,
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signedjwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    const credential = await provider.createCredential(credentialIssuer, configurationWithTypes, {
      subject: 'did:example:123#key-1',
      claims: {
        given_name: 123,
        age: '25',
      },
    })

    const payload = decodeJwtSegment(credential.split('.')[1])

    assert.equal(typeof payload.vc.credentialSubject.given_name, 'string')
    assert.equal(payload.vc.credentialSubject.given_name, '123')
    assert.equal(typeof payload.vc.credentialSubject.age, 'number')
    assert.equal(payload.vc.credentialSubject.age, 25)
  })

  it('should omit subject fields if subject is not provided', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()
    const keyPair: SignatureKeyPair = {
      privateKey: { alg: 'ES256', kty: 'EC' } as Jwk,
      publicKey: { alg: 'ES256', kty: 'EC' } as Jwk,
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signedjwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    const credential = await provider.createCredential(credentialIssuer, configuration)
    const payload = decodeJwtSegment(credential.split('.')[1])

    assert.equal(payload.sub, undefined)
    assert.equal(payload.vc.credentialSubject.id, undefined)
  })

  it('should use identifier option for credential id', async () => {
    const provider = issueCredentialJwt({
      identifier: () => 'https://issuer.example.com/custom/vc/123',
    }) as IssueCredentialProvider & WithProviderRegistry
    const keyPair: SignatureKeyPair = {
      privateKey: { alg: 'ES256', kty: 'EC' } as Jwk,
      publicKey: { alg: 'ES256', kty: 'EC' } as Jwk,
    }
    const mockIssuerKeyStoreProvider = {
      kind: 'issuer-signature-key-store-provider',
      name: 'mock-issuer-key-store-provider',
      single: true,
      save: mock.fn(),
      fetch: mock.fn(async () => [keyPair]),
    } satisfies IssuerSignatureKeyStoreProvider
    const mockIssuerSignatureKeyProvider = {
      kind: 'issuer-signature-key-provider',
      name: 'mock-issuer-signature-key-provider',
      single: false,
      generate: mock.fn(),
      sign: mock.fn(async () => 'signedjwt'),
      canHandle: mock.fn((alg) => alg === 'ES256'),
    } satisfies IssuerSignatureKeyProvider

    provider.providers = {
      get(kind) {
        if (kind === 'issuer-signature-key-store-provider') {
          return mockIssuerKeyStoreProvider
        }
        if (kind === 'issuer-signature-key-provider') {
          return [mockIssuerSignatureKeyProvider]
        }
        throw new Error(`Unexpected provider kind: ${kind}`)
      },
      select() {
        throw new Error('select is not used in this provider')
      },
    } as WithProviderRegistry['providers']

    const credential = await provider.createCredential(credentialIssuer, configuration)
    const payload = decodeJwtSegment(credential.split('.')[1])

    assert.equal(payload.vc.id, 'https://issuer.example.com/custom/vc/123')
  })

  it('should throw if signing alg is not supported', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()
    const keyPair: SignatureKeyPair = {
      privateKey: { alg: 'ES256', kty: 'EC' } as Jwk,
      publicKey: { alg: 'ES256', kty: 'EC' } as Jwk,
    }
    const config = {
      ...configuration,
      credential_signing_alg_values_supported: ['ES256'],
    } satisfies CredentialConfiguration

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signedjwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    await assert.rejects(provider.createCredential(credentialIssuer, config, { keyAlg: 'RS256' }), {
      name: 'UNSUPPORTED_ISSUER_KEY_ALG',
    })
  })

  it('should throw if issuer key is not found', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signedjwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    await assert.rejects(
      provider.createCredential(credentialIssuer, configuration, { keyAlg: 'ES256' }),
      {
        name: 'AUTHZ_ISSUER_KEY_NOT_FOUND',
      }
    )
  })

  it('should throw if signing fails', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()
    const keyPair: SignatureKeyPair = {
      privateKey: { alg: 'ES256', kty: 'EC' } as Jwk,
      publicKey: { alg: 'ES256', kty: 'EC' } as Jwk,
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => null)
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    await assert.rejects(
      provider.createCredential(credentialIssuer, configuration, { keyAlg: 'ES256' }),
      {
        name: 'INTERNAL_SERVER_ERROR',
      }
    )
  })

  it('should reject invalid identifier option at construction time', () => {
    assert.throws(
      () =>
        issueCredentialJwt({
          identifier: () => 'not-a-url',
        }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_OPTIONS')
        return true
      }
    )
  })
})
