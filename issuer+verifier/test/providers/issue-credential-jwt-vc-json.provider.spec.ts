import assert from 'node:assert/strict'
import { describe, it, mock } from 'node:test'
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose'
import {
  CredentialConfigurationSupported,
  CredentialIssuer,
} from '../../src/credential-issuer.types'
import { VcknotsError } from '../../src/errors/vcknots.error'
import { CredentialFormats } from '../../src/credential-request.types'
import { issueCredentialJwt } from '../../src/providers/issue-credential-jwt-vc-json.provider'
import {
  IssueCredentialProvider,
  IssuerSignatureKeyStoreProvider,
} from '../../src/providers/provider.types'
import { WithProviderRegistry } from '../../src/providers/provider.registry'

const decodeJwtSegment = (segment: string) =>
  JSON.parse(Buffer.from(segment, 'base64url').toString())

describe('issueCredential', () => {
  const credentialIssuer = CredentialIssuer('https://issuer.example.com')
  const configuration: CredentialConfigurationSupported = {
    format: 'jwt_vc_json',
    credential_definition: {
      type: ['VerifiableCredential', 'UniversityDegreeCredential'],
    },
    credential_metadata: {
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
      claims: [
        {
          path: ['given_name'],
          display: [
            {
              name: 'Given Name',
              locale: 'en-US',
            },
          ],
        },
        {
          path: ['family_name'],
          display: [
            {
              name: 'Surname',
              locale: 'en-US',
            },
          ],
        },
        {
          path: ['degree'],
        },
        {
          path: ['gpa'],
          display: [
            {
              name: 'GPA',
            },
          ],
        },
      ],
    },
  }

  const createProvider = () => {
    const provider = issueCredentialJwt() as IssueCredentialProvider & WithProviderRegistry
    const mockIssuerKeyStoreProvider = {
      kind: 'issuer-signature-key-store-provider',
      name: 'mock-issuer-key-store-provider',
      single: true,
      save: mock.fn(),
      fetch: mock.fn(),
      sign: mock.fn(),
    } satisfies IssuerSignatureKeyStoreProvider

    provider.providers = {
      get(kind) {
        if (kind === 'issuer-signature-key-store-provider') {
          return mockIssuerKeyStoreProvider
        }
        throw new Error(`Unexpected provider kind: ${kind}`)
      },
      select() {
        throw new Error('select is not used in this provider')
      },
    } as WithProviderRegistry['providers']

    return { provider, mockIssuerKeyStoreProvider }
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
    const { provider, mockIssuerKeyStoreProvider } = createProvider()
    const keyPair = await generateKeyPair('ES256', { extractable: true })
    const expectedJwk = await exportJWK(keyPair.publicKey)
    const expectedKid = await calculateJwkThumbprint(expectedJwk)

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keyPair.publicKey)
    mock.method(mockIssuerKeyStoreProvider, 'sign', async () => 'signedjwt')

    const credential = await provider.createCredential(credentialIssuer, configuration, {
      subject: 'did:example:123#key-1',
      keyAlg: 'ES256',
    })

    const [headerSegment, payloadSegment, signature] = credential.split('.')
    const header = decodeJwtSegment(headerSegment)
    const payload = decodeJwtSegment(payloadSegment)

    assert.equal(signature, 'signedjwt')
    assert.deepStrictEqual(header, { alg: 'ES256', kid: expectedKid, typ: 'JWT' })
    assert.equal(payload.iss, credentialIssuer)
    assert.equal(payload.sub, 'did:example:123#key-1')
    assert.equal(payload.vc.id.startsWith(`${credentialIssuer}/vc/`), true)
    assert.deepEqual(payload.vc.type, ['VerifiableCredential', 'UniversityDegreeCredential'])
    assert.equal(payload.vc.credentialSubject.id, 'did:example:123#key-1')
    assert.equal(mockIssuerKeyStoreProvider.fetch.mock.callCount(), 1)
    assert.equal(mockIssuerKeyStoreProvider.sign.mock.callCount(), 1)
  })

  it('should create a signed verifiable credential jwt with claims', async () => {
    const { provider, mockIssuerKeyStoreProvider } = createProvider()
    const keyPair = await generateKeyPair('ES256', { extractable: true })
    const claims = {
      given_name: 'John',
      family_name: 'Doe',
      degree: 'Bachelor of Science',
      gpa: '4.0',
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keyPair.publicKey)
    mock.method(mockIssuerKeyStoreProvider, 'sign', async () => 'signedjwt')

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
    const { provider, mockIssuerKeyStoreProvider } = createProvider()
    const keyPair = await generateKeyPair('ES256', { extractable: true })
    const configurationWithMandatory: CredentialConfigurationSupported = {
      ...configuration,
      credential_metadata: {
        ...configuration.credential_metadata,
        claims: configuration.credential_metadata?.claims?.map((claim) =>
          claim.path[0] === 'given_name' ? { ...claim, mandatory: true } : claim
        ),
      },
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keyPair.publicKey)
    mock.method(mockIssuerKeyStoreProvider, 'sign', async () => 'signedjwt')

    await assert.rejects(
      provider.createCredential(credentialIssuer, configurationWithMandatory, {
        subject: 'did:example:123#key-1',
        claims: { family_name: 'Doe' },
      }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'invalid_claims')
        return true
      }
    )
  })

  it('should throw error if mandatory claim is missing when claims are omitted', async () => {
    const { provider } = createProvider()
    const configurationWithMandatory: CredentialConfigurationSupported = {
      ...configuration,
      credential_metadata: {
        ...configuration.credential_metadata,
        claims: configuration.credential_metadata?.claims?.map((claim) =>
          claim.path[0] === 'given_name' ? { ...claim, mandatory: true } : claim
        ),
      },
    }

    await assert.rejects(
      provider.createCredential(credentialIssuer, configurationWithMandatory, {
        subject: 'did:example:123#key-1',
      }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'invalid_claims')
        return true
      }
    )
  })

  it('should throw error if a mandatory claim is missing when multiple mandatory claims exist', async () => {
    const { provider, mockIssuerKeyStoreProvider } = createProvider()
    const keyPair = await generateKeyPair('ES256', { extractable: true })
    const configurationWithMandatory: CredentialConfigurationSupported = {
      ...configuration,
      credential_metadata: {
        ...configuration.credential_metadata,
        claims: configuration.credential_metadata?.claims?.map((claim) =>
          ['given_name', 'family_name'].includes(claim.path[0])
            ? { ...claim, mandatory: true }
            : claim
        ),
      },
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keyPair.publicKey)
    mock.method(mockIssuerKeyStoreProvider, 'sign', async () => 'signedjwt')

    await assert.rejects(
      provider.createCredential(credentialIssuer, configurationWithMandatory, {
        subject: 'did:example:123#key-1',
        claims: { given_name: 'John' },
      }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'invalid_claims')
        return true
      }
    )
  })

  it('should map nested claims using credential metadata paths', async () => {
    const { provider, mockIssuerKeyStoreProvider } = createProvider()
    const keyPair = await generateKeyPair('ES256', { extractable: true })
    const nestedConfiguration: CredentialConfigurationSupported = {
      ...configuration,
      credential_metadata: {
        ...configuration.credential_metadata,
        claims: [
          {
            path: ['name', 'given'],
            mandatory: true,
          },
          {
            path: ['name', 'family'],
          },
        ],
      },
    }
    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keyPair.publicKey)
    mock.method(mockIssuerKeyStoreProvider, 'sign', async () => 'signedjwt')

    const credential = await provider.createCredential(credentialIssuer, nestedConfiguration, {
      subject: 'did:example:123#key-1',
      claims: {
        name: {
          given: 'John',
          family: 'Doe',
        },
      },
    })

    const payload = decodeJwtSegment(credential.split('.')[1])

    assert.deepEqual(payload.vc.credentialSubject.name, {
      given: 'John',
      family: 'Doe',
    })
  })

  it('should reject dangerous claim path segments', async () => {
    const { provider } = createProvider()
    const unsafeConfiguration: CredentialConfigurationSupported = {
      ...configuration,
      credential_metadata: {
        ...configuration.credential_metadata,
        claims: [
          {
            path: ['__proto__', 'polluted'],
          },
        ],
      },
    }

    await assert.rejects(
      provider.createCredential(credentialIssuer, unsafeConfiguration, {
        claims: {
          __proto__: {
            polluted: 'value',
          },
        },
      }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'invalid_claims')
        assert.match(err.message, /Unsupported claim path segment/)
        return true
      }
    )
  })

  it('should omit subject fields if subject is not provided', async () => {
    const { provider, mockIssuerKeyStoreProvider } = createProvider()
    const keyPair = await generateKeyPair('ES256', { extractable: true })

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keyPair.publicKey)
    mock.method(mockIssuerKeyStoreProvider, 'sign', async () => 'signedjwt')

    const credential = await provider.createCredential(credentialIssuer, configuration)
    const payload = decodeJwtSegment(credential.split('.')[1])

    assert.equal(payload.sub, undefined)
    assert.equal(payload.vc.credentialSubject.id, undefined)
  })

  it('should use identifier option for credential id', async () => {
    const keyPair = await generateKeyPair('ES256', { extractable: true })
    const provider = issueCredentialJwt({
      identifier: () => 'https://issuer.example.com/custom/vc/123',
    }) as IssueCredentialProvider & WithProviderRegistry
    const mockIssuerKeyStoreProvider = {
      kind: 'issuer-signature-key-store-provider',
      name: 'mock-issuer-key-store-provider',
      single: true,
      save: mock.fn(),
      fetch: mock.fn(async () => keyPair.publicKey),
      sign: mock.fn(async () => 'signedjwt'),
    } satisfies IssuerSignatureKeyStoreProvider

    provider.providers = {
      get(kind) {
        if (kind === 'issuer-signature-key-store-provider') {
          return mockIssuerKeyStoreProvider
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
    const { provider, mockIssuerKeyStoreProvider } = createProvider()
    const keyPair = await generateKeyPair('ES256', { extractable: true })
    const config = {
      ...configuration,
      credential_signing_alg_values_supported: ['ES256'],
    } satisfies CredentialConfigurationSupported

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keyPair.publicKey)
    mock.method(mockIssuerKeyStoreProvider, 'sign', async () => 'signedjwt')

    await assert.rejects(provider.createCredential(credentialIssuer, config, { keyAlg: 'RS256' }), {
      name: 'unsupported_issuer_key_alg',
    })
  })

  it('should throw if issuer key is not found', async () => {
    const { provider, mockIssuerKeyStoreProvider } = createProvider()

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => null)
    mock.method(mockIssuerKeyStoreProvider, 'sign', async () => 'signedjwt')

    await assert.rejects(
      provider.createCredential(credentialIssuer, configuration, { keyAlg: 'ES256' }),
      {
        name: 'authz_issuer_key_not_found',
      }
    )
  })

  it('should throw if signing fails', async () => {
    const { provider, mockIssuerKeyStoreProvider } = createProvider()
    const keyPair = await generateKeyPair('ES256', { extractable: true })

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => keyPair.publicKey)
    mock.method(mockIssuerKeyStoreProvider, 'sign', async () => null)

    await assert.rejects(
      provider.createCredential(credentialIssuer, configuration, { keyAlg: 'ES256' }),
      {
        name: 'internal_server_error',
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
        assert.equal(err.name, 'invalid_options')
        return true
      }
    )
  })
})

