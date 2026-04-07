import assert from 'node:assert/strict'
import { describe, it, mock } from 'node:test'
import { calculateJwkThumbprint } from 'jose'

import {
  CredentialConfigurationSupported,
  CredentialIssuer,
} from '../../src/credential-issuer.types'
import { CredentialFormats } from '../../src/credential-request.types'
import { VcknotsError } from '../../src/errors/vcknots.error'
import { Jwk } from '../../src/jwk.type'
import { issueCredentialSDJWT } from '../../src/providers/issue-credential-dc-sd-jwt.provider'
import {
  IssueCredentialProvider,
  IssuerSignatureKeyProvider,
  IssuerSignatureKeyStoreProvider,
} from '../../src/providers/provider.types'
import { WithProviderRegistry } from '../../src/providers/provider.registry'
import { SignatureKeyPair } from '../../src/signature-key.types'

const decodeJwtSegment = (segment: string) =>
  JSON.parse(Buffer.from(segment, 'base64url').toString())

const decodeDisclosure = (disclosure: string) =>
  JSON.parse(Buffer.from(disclosure, 'base64url').toString()) as [string, string, unknown]

describe('issueCredentialSDJWT', () => {
  const credentialIssuer = CredentialIssuer('https://issuer.example.com')
  const holderJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'ezZgKwMueAyZLHUgSpzNkbOWDgjJXTAOJn8MftOnayQ',
    y: 'Fy_U4KyZQf-9jKpFJtH6OFFRXmwAcveyfuoDp1hSOFo',
  }
  const proofHeader = {
    alg: 'ES256',
    jwk: holderJwk,
  }
  const keyPair: SignatureKeyPair = {
    privateKey: {
      alg: 'ES256',
      kty: 'EC',
      crv: 'P-256',
      d: 'w3JFeaJ7TqG0p7qJ2Y2k1V3H8K0sHfYt7G0vG0p7m0Q',
      x: 'ezZgKwMueAyZLHUgSpzNkbOWDgjJXTAOJn8MftOnayQ',
      y: 'Fy_U4KyZQf-9jKpFJtH6OFFRXmwAcveyfuoDp1hSOFo',
    } as Jwk,
    publicKey: {
      alg: 'ES256',
      kty: 'EC',
      crv: 'P-256',
      x: 'ezZgKwMueAyZLHUgSpzNkbOWDgjJXTAOJn8MftOnayQ',
      y: 'Fy_U4KyZQf-9jKpFJtH6OFFRXmwAcveyfuoDp1hSOFo',
    } as Jwk,
  }
  const configuration: CredentialConfigurationSupported = {
    format: 'dc+sd-jwt',
    vct: 'https://issuer.example.com/credentials/university-degree',
    cryptographic_binding_methods_supported: ['jwk'],
    credential_metadata: {
      claims: [
        { path: ['given_name'], mandatory: true },
        { path: ['family_name'] },
        { path: ['degree', 'type'] },
        { path: ['issuing_country'] },
      ],
    },
  }

  const createProvider = () => {
    const provider = issueCredentialSDJWT() as IssueCredentialProvider & WithProviderRegistry
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

  it('should have correct metadata and support dc+sd-jwt format', () => {
    const { provider } = createProvider()

    assert.equal(provider.kind, 'issue-credential-provider')
    assert.equal(provider.name, 'issue-credential-dc-sd-jwt-provider')
    assert.equal(provider.single, false)
    assert.equal(provider.canHandle(CredentialFormats.DC_SD_JWT), true)
    assert.equal(provider.canHandle(CredentialFormats.JWT_VC_JSON), false)
  })

  it('should create a signed SD-JWT with disclosures and non-disclosable claims', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()
    const expectedKid = await calculateJwkThumbprint(keyPair.publicKey)

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signed-sd-jwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    const credential = await provider.createCredential(credentialIssuer, configuration, {
      subject: 'did:example:holder',
      proofHeader,
      claims: {
        given_name: 'Alice',
        family_name: 'Anderson',
        degree: {
          type: 'BachelorDegree',
        },
        issuing_country: 'JP',
      },
      nonDisclosableClaims: ['issuing_country'],
    })

    const [jwt, ...disclosureParts] = credential.split('~')
    const disclosures = disclosureParts.filter(Boolean)
    const [headerSegment, payloadSegment, signature] = jwt.split('.')
    const header = decodeJwtSegment(headerSegment)
    const payload = decodeJwtSegment(payloadSegment)
    const decodedDisclosures = disclosures.map(decodeDisclosure)

    assert.equal(signature, 'signed-sd-jwt')
    assert.deepEqual(header, { alg: 'ES256', kid: expectedKid, typ: 'dc+sd-jwt' })
    assert.equal(payload.iss, credentialIssuer)
    assert.equal(payload.vct, configuration.vct)
    assert.equal(payload.sub, 'did:example:holder')
    assert.deepEqual(payload.cnf, { jwk: holderJwk })
    assert.equal(payload.issuing_country, 'JP')
    assert.equal(payload.given_name, undefined)
    assert.equal(payload.family_name, undefined)
    assert.equal(payload.degree, undefined)
    assert.equal(payload._sd_alg, 'sha-256')
    assert.equal(Array.isArray(payload._sd), true)
    assert.equal(payload._sd.length, 3)
    assert.equal(disclosures.length, 3)
    assert.deepEqual(decodedDisclosures.map(([, claimName, value]) => [claimName, value]).sort(), [
      ['degree', { type: 'BachelorDegree' }],
      ['family_name', 'Anderson'],
      ['given_name', 'Alice'],
    ])
    assert.equal(mockIssuerKeyStoreProvider.fetch.mock.callCount(), 1)
    assert.equal(mockIssuerSignatureKeyProvider.sign.mock.callCount(), 1)
  })

  it('should create a compact SD-JWT without disclosures when no claims are provided', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()
    const noBindingConfiguration: CredentialConfigurationSupported = {
      format: 'dc+sd-jwt',
      vct: 'https://issuer.example.com/credentials/minimal',
    }

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signed-sd-jwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    const credential = await provider.createCredential(credentialIssuer, noBindingConfiguration)
    const parts = credential.split('.')
    const payload = decodeJwtSegment(parts[1])

    assert.equal(parts.length, 3)
    assert.equal(credential.includes('~'), false)
    assert.equal(payload.cnf, undefined)
    assert.equal(payload._sd, undefined)
    assert.equal(payload._sd_alg, undefined)
  })

  it('should reject invalid configuration', async () => {
    const { provider } = createProvider()

    await assert.rejects(
      provider.createCredential(credentialIssuer, {
        format: 'jwt_vc_json',
      } as CredentialConfigurationSupported),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_CONFIGURATION')
        return true
      }
    )
  })

  it('should require proofHeader when cryptographic binding is supported', async () => {
    const { provider } = createProvider()

    await assert.rejects(
      provider.createCredential(credentialIssuer, configuration, {
        claims: { given_name: 'Alice' },
      }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_OPTIONS')
        return true
      }
    )
  })

  it('should reject missing mandatory claims', async () => {
    const { provider } = createProvider()

    await assert.rejects(
      provider.createCredential(credentialIssuer, configuration, {
        proofHeader,
        claims: {
          family_name: 'Anderson',
        },
      }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_CLAIMS')
        return true
      }
    )
  })

  it('should reject missing mandatory claims when claims are omitted', async () => {
    const { provider } = createProvider()

    await assert.rejects(
      provider.createCredential(credentialIssuer, configuration, {
        proofHeader,
      }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_CLAIMS')
        return true
      }
    )
  })

  it('should reject dangerous claim path segments', async () => {
    const { provider } = createProvider()
    const unsafeConfiguration: CredentialConfigurationSupported = {
      ...configuration,
      credential_metadata: {
        claims: [
          {
            path: ['constructor', 'prototype'],
          },
        ],
      },
    }

    await assert.rejects(
      provider.createCredential(credentialIssuer, unsafeConfiguration, {
        proofHeader,
        claims: {
          constructor: {
            prototype: 'value',
          },
        },
      }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_CLAIMS')
        assert.match(err.message, /Unsupported claim path segment/)
        return true
      }
    )
  })

  it('should throw if issuer key is not found', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => 'signed-sd-jwt')
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    await assert.rejects(
      provider.createCredential(credentialIssuer, configuration, {
        proofHeader,
        keyAlg: 'ES256',
        claims: {
          given_name: 'Alice',
        },
      }),
      {
        name: 'AUTHZ_ISSUER_KEY_NOT_FOUND',
      }
    )
  })

  it('should throw if signing fails', async () => {
    const { provider, mockIssuerKeyStoreProvider, mockIssuerSignatureKeyProvider } =
      createProvider()

    mock.method(mockIssuerKeyStoreProvider, 'fetch', async () => [keyPair])
    mock.method(mockIssuerSignatureKeyProvider, 'sign', async () => null)
    mockIssuerSignatureKeyProvider.canHandle.mock.mockImplementation((alg) => alg === 'ES256')

    await assert.rejects(
      provider.createCredential(credentialIssuer, configuration, {
        proofHeader,
        keyAlg: 'ES256',
        claims: {
          given_name: 'Alice',
        },
      }),
      {
        name: 'INTERNAL_SERVER_ERROR',
      }
    )
  })

  it('should reject invalid identifier option at construction time', () => {
    assert.throws(
      () =>
        issueCredentialSDJWT({
          identifier: () => 'not-a-url',
        }),
      (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_OPTIONS')
        return true
      }
    )
  })
})
