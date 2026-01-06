import assert from 'node:assert'
import { afterEach, beforeEach, describe, test, mock } from 'node:test'
import * as jose from 'jose'
import {
  CnonceStoreProvider,
  DidProvider,
  HolderBindingProvider,
  JwtSignatureProvider,
  VerifyCredentialProvider,
} from '../../src/providers/provider.types'
import { verifyVerifiablePresentation } from '../../src/providers/verify-presentation-jwt-vp-json.provider'
import { VerifiableCredential } from '../../src/credential.types'
import { DidDocument } from '../../src/did.types'

describe('verifyVerifiablePresentation provider', () => {
  let provider: ReturnType<typeof verifyVerifiablePresentation>
  let mockCnonceStore: CnonceStoreProvider
  let mockCredentialVerifier: VerifyCredentialProvider
  let mockDidProvider: DidProvider
  let mockJwtSignatureProvider: JwtSignatureProvider
  let mockHolderBindingProvider: HolderBindingProvider

  let holderKeyPair: jose.GenerateKeyPairResult
  let holderDid: string
  let holderJwk: jose.JWK

  let vc: VerifiableCredential
  let vcJwt: string

  beforeEach(async () => {
    holderKeyPair = await jose.generateKeyPair('ES256')
    holderJwk = await jose.exportJWK(holderKeyPair.publicKey)
    const thumbprint = await jose.calculateJwkThumbprint(holderJwk)
    holderDid = `did:key:${thumbprint}`

    vc = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: 'https://issuer.example.com',
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: holderDid,
      },
    }

    const issuerKeyPair = await jose.generateKeyPair('ES256')
    vcJwt = await new jose.SignJWT({ vc: { ...vc } } as jose.JWTPayload)
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer('https://issuer.example.com')
      .sign(issuerKeyPair.privateKey)

    mockCnonceStore = {
      kind: 'cnonce-store-provider',
      name: 'mock-cnonce-store',
      single: true,
      validate: mock.fn(async (nonce: string) => nonce === 'test-nonce'),
      revoke: mock.fn(async () => {}),
      save: mock.fn(async () => {}),
    }

    mockCredentialVerifier = {
      kind: 'verify-verifiable-credential-provider',
      name: 'mock-credential-verifier',
      single: true,
      verify: mock.fn(async () => true),
      canHandle: mock.fn(() => true),
    }

    const didDoc: DidDocument = {
      id: holderDid,
      verificationMethod: [
        {
          id: `${holderDid}#${thumbprint}`,
          type: 'JsonWebKey2020',
          controller: holderDid,
          // biome-ignore lint/suspicious/noExplicitAny: <explanation>
          publicKeyJwk: holderJwk as any,
        },
      ],
    }

    mockDidProvider = {
      kind: 'did-provider',
      name: 'mock-did-provider',
      single: false,
      resolveDid: mock.fn(async () => didDoc),
      canHandle: mock.fn((method: string) => method === 'key'),
    }

    mockJwtSignatureProvider = {
      kind: 'jwt-signature-provider',
      name: 'mock-jwt-signature-provider',
      single: true,
      verify: mock.fn(async () => true),
    }

    mockHolderBindingProvider = {
      kind: 'holder-binding-provider',
      name: 'mock-holder-binding-provider',
      single: true,
      verify: mock.fn(async () => true),
    }

    provider = verifyVerifiablePresentation()
    mock.method(provider.providers, 'get', (name: string) => {
      if (name === 'cnonce-store-provider') return mockCnonceStore
      if (name === 'verify-verifiable-credential-provider') return mockCredentialVerifier
      if (name === 'did-provider') return [mockDidProvider]
      if (name === 'jwt-signature-provider') return mockJwtSignatureProvider
      if (name === 'holder-binding-provider') return mockHolderBindingProvider
      return undefined
    })
  })

  afterEach(() => {
    mock.restoreAll()
  })

  const createVpJwt = async (payload: object, kid?: string | null) => {
    const protectedHeader: jose.JWTHeaderParameters = { alg: 'ES256' }
    if (kid !== null) {
      protectedHeader.kid = kid ?? `${holderDid}#${await jose.calculateJwkThumbprint(holderJwk)}`
    }
    return await new jose.SignJWT(payload as jose.JWTPayload)
      .setProtectedHeader(protectedHeader)
      .sign(holderKeyPair.privateKey)
  }

  test('should successfully verify a valid presentation', async () => {
    const vpJwt = await createVpJwt({
      nonce: 'test-nonce',
      vp: {
        verifiableCredential: [vcJwt],
      },
    })

    const result = await provider.verify(vpJwt, { kind: 'jwt_vp_json' })
    assert.strictEqual(result, true)
  })

  test('should throw an error for unsupported kind', async () => {
    await assert.rejects(
      // biome-ignore lint/suspicious/noExplicitAny: <explanation>
      provider.verify('dummy-vp', { kind: 'ldp_vp' } as any),
      { name: 'ILLEGAL_ARGUMENT', message: 'ldp_vp is not supported.' }
    )
  })

  test('should throw an error for invalid vp_token', async () => {
    await assert.rejects(provider.verify('invalid-jwt', { kind: 'jwt_vp_json' }), {
      name: 'INVALID_VP_TOKEN',
    })
  })

  test('should throw an error for invalid nonce', async () => {
    const vpJwt = await createVpJwt({
      nonce: 'invalid-nonce',
      vp: { verifiableCredential: [vcJwt] },
    })
    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'INVALID_NONCE',
      message: 'nonce is not valid.',
    })
  })

  test('should throw an error if no verifiableCredential', async () => {
    const vpJwt = await createVpJwt({
      nonce: 'test-nonce',
      vp: { verifiableCredential: [] },
    })
    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'INVALID_CREDENTIAL',
      message: 'No credentials is included',
    })
  })

  test('should throw if vc is not a string', async () => {
    const vpJwt = await createVpJwt({
      nonce: 'test-nonce',
      vp: { verifiableCredential: [{}] },
    })
    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'ILLEGAL_ARGUMENT',
      message: 'VC represented as object is not supported.',
    })
  })

  test('should throw if credential verification fails', async () => {
    mock.method(mockCredentialVerifier, 'verify', async () => false)
    const vpJwt = await createVpJwt({
      nonce: 'test-nonce',
      vp: { verifiableCredential: [vcJwt] },
    })
    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'INVALID_CREDENTIAL',
      message: 'credential is not valid.',
    })
  })

  test('should throw if kid is missing', async () => {
    const vpJwt = await createVpJwt(
      {
        nonce: 'test-nonce',
        vp: { verifiableCredential: [vcJwt] },
      },
      null
    )

    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'INVALID_VP_TOKEN',
      message: /Missing key id in the header/,
    })
  })

  test('should throw if did method is unsupported', async () => {
    const vpJwt = await createVpJwt(
      {
        nonce: 'test-nonce',
        vp: { verifiableCredential: [vcJwt] },
      },
      'did:unsupported:123'
    )

    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'PROVIDER_NOT_FOUND',
      message: 'No provider found which can handle: unsupported',
    })
  })

  test('should throw if did resolving fails', async () => {
    mock.method(mockDidProvider, 'resolveDid', async () => null)
    const vpJwt = await createVpJwt({
      nonce: 'test-nonce',
      vp: { verifiableCredential: [vcJwt] },
    })
    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'INVALID_VP_TOKEN',
      message: /Cannot resolve DID/,
    })
  })

  test('should throw if verificationMethod is not found for kid', async () => {
    const didDocWithDifferentKid = {
      id: holderDid,
      // biome-ignore lint/suspicious/noExplicitAny: <explanation>
      verificationMethod: [
        {
          id: 'did:key:another#key',
          type: 'JsonWebKey2020',
          controller: holderDid,
          publicKeyJwk: holderJwk as any,
        },
      ],
    }
    mock.method(mockDidProvider, 'resolveDid', async () => didDocWithDifferentKid)
    const vpJwt = await createVpJwt({
      nonce: 'test-nonce',
      vp: { verifiableCredential: [vcJwt] },
    })
    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'INVALID_VP_TOKEN',
      message: /Cannot find verification method/,
    })
  })

  test('should throw if publicKeyJwk is missing in verificationMethod', async () => {
    const didDocWithoutJwk: DidDocument = {
      id: holderDid,
      verificationMethod: [
        {
          id: `${holderDid}#${await jose.calculateJwkThumbprint(holderJwk)}`,
          type: 'JsonWebKey2020',
          controller: holderDid,
        },
      ],
    }
    mock.method(mockDidProvider, 'resolveDid', async () => didDocWithoutJwk)
    const vpJwt = await createVpJwt({
      nonce: 'test-nonce',
      vp: { verifiableCredential: [vcJwt] },
    })
    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'INVALID_VP_TOKEN',
      message: /Cannot find verification method/,
    })
  })

  test('should throw if jwt signature verification fails', async () => {
    mock.method(mockJwtSignatureProvider, 'verify', async () => false)
    const vpJwt = await createVpJwt({
      nonce: 'test-nonce',
      vp: { verifiableCredential: [vcJwt] },
    })
    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'INVALID_PROOF',
      message: 'jwt is not valid.',
    })
  })

  test('should throw if holder binding verification fails', async () => {
    mock.method(mockHolderBindingProvider, 'verify', async () => false)
    const vpJwt = await createVpJwt({
      nonce: 'test-nonce',
      vp: { verifiableCredential: [vcJwt] },
    })
    await assert.rejects(provider.verify(vpJwt, { kind: 'jwt_vp_json' }), {
      name: 'HOLDER_BINDING_FAILED',
      message: 'Holder binding verification failed.',
    })
  })
})
