import { X509Certificate } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import assert from 'node:assert/strict'
import { describe, it, before, mock } from 'node:test'
import {
  credentialProofJWT,
  OID4VCI_JWT_PROOF_TYP,
} from '../../src/providers/credential-proof-jwt.provider'
import type { CredentialProofJwtVerifyContext } from '../../src/credential-proof-jwt.types'
import { CredentialIssuer } from '../../src/credential-issuer.types'
import type { CredentialProofProvider, DidProvider } from '../../src/providers/provider.types'
import type { WithProviderRegistry } from '../../src/providers/provider.registry'
import { certificate } from '../../src/providers/certificate.provider'
import {
  exportJWK,
  generateKeyPair,
  importPKCS8,
  type JWTHeaderParameters,
  type JWTPayload,
  SignJWT,
} from 'jose'
import { raise, type VcknotsError } from '../../src/errors/vcknots.error'
import type { DidDocument, JsonWebKey } from '../../src/did.types'

describe('CredentialProofJwtProvider', () => {
  const resolveSamplePath = (fileName: string): string => {
    const candidates = [
      join(process.cwd(), 'server/samples/certificate-openid-test', fileName),
      join(process.cwd(), '../server/samples/certificate-openid-test', fileName),
    ]
    const path = candidates.find((candidate) => existsSync(candidate))
    assert(path, `sample file not found: ${fileName}`)
    return path
  }

  const certificatePem = readFileSync(resolveSamplePath('certificate_openid.pem'), 'utf-8')
  const privateKeyPem = readFileSync(resolveSamplePath('private_key_openid.pem'), 'utf-8')

  let keys: { publicKey: CryptoKey; privateKey: CryptoKey }
  let publicKeyJwk: JsonWebKey
  let x5cPrivateKey: CryptoKey
  let x5cHeaderValue: string
  const credentialIssuer = CredentialIssuer('https://issuer.example.com')
  const clientId = 'test-client'
  const testDid = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
  // Note: The kid should contain the full DID and fragment.
  const testKid = `${testDid}#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH`

  const preAuthCtx: CredentialProofJwtVerifyContext = {
    usePreAuth: true,
    credentialIssuer,
  }
  const preAuthRegisteredClientCtx: CredentialProofJwtVerifyContext = {
    usePreAuth: true,
    credentialIssuer,
    clientId,
  }
  const authCodeCtx: CredentialProofJwtVerifyContext = {
    usePreAuth: false,
    credentialIssuer,
    clientId,
  }

  const mockDidProvider: DidProvider = {
    kind: 'did-provider',
    name: 'mock-did-provider',
    single: false,
    canHandle: (didMethod: string) => didMethod === 'key',
    resolveDid: mock.fn(async (did: string): Promise<DidDocument> => {
      if (did === testKid) {
        return {
          '@context': 'https://www.w3.org/ns/did/v1',
          id: testDid,
          verificationMethod: [
            {
              id: testKid,
              type: 'JsonWebKey2020',
              controller: testDid,
              publicKeyJwk: publicKeyJwk as JsonWebKey,
            },
          ],
          authentication: [testKid],
        }
      }
      // Using raise to throw a VcknotsError, which is more aligned with the app's error handling.
      throw raise('invalid_proof', { message: `did ${did} not found.` })
    }),
  }

  const createTestProof = async (
    payload: JWTPayload,
    alg: string,
    kid: string,
    customHeader?: Partial<JWTHeaderParameters>
  ) => {
    return await new SignJWT(payload)
      .setProtectedHeader({ alg, kid, typ: OID4VCI_JWT_PROOF_TYP, ...customHeader })
      .setIssuedAt()
      .sign(keys.privateKey)
  }

  const createTestProofWithHeader = async (
    payload: JWTPayload,
    protectedHeader: JWTHeaderParameters,
    signKey: CryptoKey = keys.privateKey
  ) => {
    return await new SignJWT(payload)
      .setProtectedHeader(protectedHeader)
      .setIssuedAt()
      .sign(signKey)
  }

  before(async () => {
    keys = await generateKeyPair('ES256')
    const jwk = await exportJWK(keys.publicKey)
    assert(jwk.kty, 'kty must be defined')
    publicKeyJwk = jwk as JsonWebKey
    x5cPrivateKey = await importPKCS8(privateKeyPem, 'ES256')
    x5cHeaderValue = new X509Certificate(certificatePem).raw.toString('base64')
  })

  it('should have correct properties', () => {
    const provider = credentialProofJWT()
    assert.equal(provider.kind, 'credential-proof-provider')
    assert.equal(provider.name, 'default-credential-proof-jwt-provider')
    assert.strictEqual(provider.single, false)
  })

  it('should handle "jwt" proof type', () => {
    const provider = credentialProofJWT()
    assert.ok(provider.canHandle('jwt'))
    assert.ok(!provider.canHandle('ldp_vp'))
  })

  describe('verifyProof', () => {
    const prohibitedProofJwtAlgMessage =
      'Proof JWT alg must not be "none" or a symmetric (MAC) algorithm.'
    const mutualExclusiveKidJwkX5cMessage =
      'Proof JWT header: kid, jwk, and x5c are mutually exclusive (OID4VCI 1.0 §F.1).'
    const missingKidJwkX5cMessage =
      'Proof JWT header must contain one of kid, jwk, or x5c (OID4VCI 1.0 §F.1).'

    const setupProvider = (): CredentialProofProvider & WithProviderRegistry => {
      const provider = credentialProofJWT()
      // Mock the get method of the provider registry
      mock.method(provider.providers, 'get', (name: string) => {
        if (name === 'did-provider') {
          return [mockDidProvider]
        }
        if (name === 'certificate-provider') {
          return certificate()
        }
        return []
      })
      return provider
    }

    it('should verify a valid proof for pre-authorized code flow', async () => {
      const provider = setupProvider()
      const payload = { aud: credentialIssuer, nonce: 'test-nonce' }
      const proof = await createTestProof(payload, 'ES256', testKid, 'openid4vci-proof+jwt')

      const result = await provider.verifyProof(proof, preAuthCtx)

      assert.ok(result)
      assert.equal(result.payload.aud, credentialIssuer)
      assert.equal(result.payload.nonce, 'test-nonce')
      assert.equal(result.header.alg, 'ES256')
      assert.equal(result.header.typ, OID4VCI_JWT_PROOF_TYP)
      assert.equal(result.header.kid, testKid)
      assert.strictEqual(result.payload.iss, undefined)
    })

    it('should verify a valid proof for authorization code flow', async () => {
      const provider = setupProvider()
      const payload = { iss: clientId, aud: credentialIssuer, nonce: 'test-nonce' }
      const proof = await createTestProof(payload, 'ES256', testKid, 'openid4vci-proof+jwt')

      const result = await provider.verifyProof(proof, authCodeCtx)

      assert.ok(result)
      assert.equal(result.payload.iss, clientId)
      assert.equal(result.payload.aud, credentialIssuer)
    })

    it('should verify auth-code flow when iss claim is omitted (OPTIONAL per OID4VCI)', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { aud: credentialIssuer, nonce: 'test-nonce' },
        'ES256',
        testKid
      )
      const result = await provider.verifyProof(proof, authCodeCtx)
      assert.ok(result)
      assert.strictEqual(result.payload.iss, undefined)
    })

    it('should throw invalid_proof for malformed JWT', async () => {
      const provider = setupProvider()
      await assert.rejects(provider.verifyProof('invalid-jwt'), (err: VcknotsError) => {
        assert.equal(err.name, 'invalid_proof')
        return true
      })
    })

    const unverifiedProofJwt = (
      header: Record<string, unknown>,
      payload: Record<string, unknown>
    ): string => {
      const enc = (obj: Record<string, unknown>) =>
        Buffer.from(JSON.stringify(obj)).toString('base64url')
      return `${enc(header)}.${enc(payload)}.x`
    }

    it('should throw invalid_proof if alg is none', async () => {
      const provider = setupProvider()
      const proof = unverifiedProofJwt(
        { alg: 'none', typ: OID4VCI_JWT_PROOF_TYP, kid: testKid },
        { aud: credentialIssuer, iat: Math.floor(Date.now() / 1000) }
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: prohibitedProofJwtAlgMessage,
      })
    })

    it('should throw invalid_proof if alg is None (case-insensitive)', async () => {
      const provider = setupProvider()
      const proof = unverifiedProofJwt(
        { alg: 'None', typ: OID4VCI_JWT_PROOF_TYP, kid: testKid },
        { aud: credentialIssuer, iat: Math.floor(Date.now() / 1000) }
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: prohibitedProofJwtAlgMessage,
      })
    })

    it('should throw invalid_proof if alg is HS256', async () => {
      const provider = setupProvider()
      const proof = unverifiedProofJwt(
        { alg: 'HS256', typ: OID4VCI_JWT_PROOF_TYP, kid: testKid },
        { aud: credentialIssuer, iat: Math.floor(Date.now() / 1000) }
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: prohibitedProofJwtAlgMessage,
      })
    })

    it('should throw invalid_proof if alg is hs384 (HMAC / symmetric family)', async () => {
      const provider = setupProvider()
      const proof = unverifiedProofJwt(
        { alg: 'hs384', typ: OID4VCI_JWT_PROOF_TYP, kid: testKid },
        { aud: credentialIssuer, iat: Math.floor(Date.now() / 1000) }
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: prohibitedProofJwtAlgMessage,
      })
    })

    it('should verify a valid proof when jwk is used in header', async () => {
      const provider = setupProvider()
      const proof = await createTestProofWithHeader(
        { aud: credentialIssuer, nonce: 'test-nonce' },
        { alg: 'ES256', jwk: publicKeyJwk, typ: OID4VCI_JWT_PROOF_TYP }
      )

      const result = await provider.verifyProof(proof, preAuthCtx)

      assert.ok(result)
      assert.equal(result.payload.aud, credentialIssuer)
      assert.deepEqual(result.header.jwk, publicKeyJwk)
      assert.equal(result.header.typ, OID4VCI_JWT_PROOF_TYP)
    })

    it('should verify a valid proof when x5c is used in header', async () => {
      const provider = setupProvider()
      const proof = await createTestProofWithHeader(
        { aud: credentialIssuer, nonce: 'test-nonce' },
        { alg: 'ES256', typ: OID4VCI_JWT_PROOF_TYP, x5c: [x5cHeaderValue] },
        x5cPrivateKey
      )

      const result = await provider.verifyProof(proof, preAuthCtx)

      assert.ok(result)
      assert.equal(result.payload.aud, credentialIssuer)
      assert.deepEqual(result.header.x5c, [x5cHeaderValue])
      assert.equal(result.header.typ, OID4VCI_JWT_PROOF_TYP)
    })

    it('should throw invalid_proof if key reference header is missing', async () => {
      const provider = setupProvider()
      const proof = await createTestProofWithHeader(
        { aud: credentialIssuer, nonce: 'test-nonce' },
        { alg: 'ES256', typ: OID4VCI_JWT_PROOF_TYP }
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: missingKidJwkX5cMessage,
      })
    })

    it('should throw invalid_proof if kid and jwk are both present', async () => {
      const provider = setupProvider()
      const proof = await createTestProofWithHeader(
        { aud: credentialIssuer, nonce: 'test-nonce' },
        { alg: 'ES256', kid: testKid, jwk: publicKeyJwk, typ: OID4VCI_JWT_PROOF_TYP }
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: mutualExclusiveKidJwkX5cMessage,
      })
    })

    it('should throw invalid_proof if kid and x5c are both present', async () => {
      const provider = setupProvider()
      const proof = await createTestProofWithHeader(
        { aud: credentialIssuer, nonce: 'test-nonce' },
        { alg: 'ES256', kid: testKid, typ: OID4VCI_JWT_PROOF_TYP, x5c: [x5cHeaderValue] },
        x5cPrivateKey
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: mutualExclusiveKidJwkX5cMessage,
      })
    })

    it('should throw invalid_proof if jwk and x5c are both present', async () => {
      const provider = setupProvider()
      const proof = await createTestProofWithHeader(
        { aud: credentialIssuer, nonce: 'test-nonce' },
        { alg: 'ES256', jwk: publicKeyJwk, typ: OID4VCI_JWT_PROOF_TYP, x5c: [x5cHeaderValue] },
        x5cPrivateKey
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: mutualExclusiveKidJwkX5cMessage,
      })
    })

    it('should throw invalid_proof if header jwk contains private key material', async () => {
      const provider = setupProvider()
      const privateJwk = { ...publicKeyJwk, d: 'private-key-material' }
      const proof = await createTestProofWithHeader(
        { aud: credentialIssuer, nonce: 'test-nonce' },
        { alg: 'ES256', jwk: privateJwk, typ: OID4VCI_JWT_PROOF_TYP },
        keys.privateKey
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: 'Proof JWT header jwk must contain a public key only.',
      })
    })

    it('should throw invalid_proof if typ is not openid4vci-proof+jwt', async () => {
      const provider = setupProvider()
      const proof = await createTestProof({ aud: credentialIssuer }, 'ES256', testKid, {
        typ: 'JWT',
      })
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: `Proof JWT header typ must be "${OID4VCI_JWT_PROOF_TYP}".`,
      })
    })

    it('should throw invalid_proof if typ is missing in header', async () => {
      const provider = setupProvider()
      const proof = await new SignJWT({ aud: credentialIssuer })
        .setProtectedHeader({ alg: 'ES256', kid: testKid })
        .setIssuedAt()
        .sign(keys.privateKey)
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: `Proof JWT header typ must be "${OID4VCI_JWT_PROOF_TYP}".`,
      })
    })

    it('should throw invalid_proof for invalid DID format in kid', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { aud: credentialIssuer },
        'ES256',
        'invalid-did',
        'openid4vci-proof+jwt'
      )
      await assert.rejects(provider.verifyProof(proof), {
        name: 'invalid_proof',
        message: 'Invalid DID format: invalid-did',
      })
    })

    it('should throw invalid_proof if no suitable DID provider is found', async () => {
      const provider = credentialProofJWT()
      // Mock the get method for this specific test to simulate no providers
      mock.method(provider.providers, 'get', () => {
        return []
      })
      // No provider registered
      const proof = await createTestProof(
        { aud: credentialIssuer },
        'ES256',
        testKid,
        'openid4vci-proof+jwt'
      )
      await assert.rejects(provider.verifyProof(proof), (err: VcknotsError) => {
        assert.equal(err.name, 'invalid_proof')
        assert.equal(err.message, 'No kid or unsupported did type detected.')
        return true
      })
    })

    it('should throw error if DID resolution fails', async () => {
      const provider = setupProvider()
      const unknownKid = 'did:key:unknown#unknown'
      const proof = await createTestProof(
        { aud: credentialIssuer },
        'ES256',
        unknownKid,
        'openid4vci-proof+jwt'
      )
      // The provider is expected to propagate the error from the DID provider.
      await assert.rejects(provider.verifyProof(proof), { name: 'invalid_proof' })
    })

    it('should throw invalid_proof if resolved DID doc is invalid (missing verificationMethod)', async () => {
      const provider = setupProvider()
      const invalidDidProvider: DidProvider = {
        ...mockDidProvider,
        resolveDid: async () =>
          ({ id: 'did:key:123', '@context': 'https://www.w3.org/ns/did/v1' }) as DidDocument,
      }
      mock.method(provider.providers, 'get', () => [invalidDidProvider])
      const proof = await createTestProof(
        { aud: credentialIssuer },
        'ES256',
        testKid,
        'openid4vci-proof+jwt'
      )
      await assert.rejects(provider.verifyProof(proof), {
        name: 'invalid_proof',
        message: 'Unsupported did type detected.',
      })
    })

    it('should throw invalid_proof for invalid signature', async () => {
      const provider = setupProvider()
      const otherKeys = await generateKeyPair('ES256')
      const proof = await new SignJWT({ aud: credentialIssuer })
        .setProtectedHeader({ alg: 'ES256', kid: testKid, typ: OID4VCI_JWT_PROOF_TYP })
        .setIssuedAt()
        .sign(otherKeys.privateKey) // Signed with a different key
      await assert.rejects(
        provider.verifyProof(proof),
        (err: Error & { name?: string; message?: string; cause?: { code?: string } }) => {
          assert.equal(err.name, 'invalid_proof')
          assert.match(err.message ?? '', /^Proof JWT verification failed:/)
          // jose throws JWSSignatureVerificationFailed as the wrapped cause
          assert.equal(err.cause?.code, 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED')
          return true
        }
      )
    })

    it('should throw invalid_proof when proof JWT iat exceeds factory maxTokenAge', async () => {
      const provider = setupProvider()
      const issuedAt = new Date(Date.now() - 400 * 1000)
      const proof = await new SignJWT({ aud: credentialIssuer, nonce: 'n' })
        .setProtectedHeader({ alg: 'ES256', kid: testKid, typ: OID4VCI_JWT_PROOF_TYP })
        .setIssuedAt(issuedAt)
        .sign(keys.privateKey)
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: 'Proof JWT is outside the allowed issuance time window.',
      })
    })

    it('should verify when iat is within a larger factory maxTokenAgeSeconds', async () => {
      const provider = credentialProofJWT({ maxTokenAgeSeconds: 600 })
      mock.method(provider.providers, 'get', (name: string) => {
        if (name === 'did-provider') {
          return [mockDidProvider]
        }
        return []
      })
      const issuedAt = new Date(Date.now() - 400 * 1000)
      const proof = await new SignJWT({ aud: credentialIssuer, nonce: 'n' })
        .setProtectedHeader({ alg: 'ES256', kid: testKid, typ: OID4VCI_JWT_PROOF_TYP })
        .setIssuedAt(issuedAt)
        .sign(keys.privateKey)
      const result = await provider.verifyProof(proof, preAuthCtx)
      assert.ok(result)
    })

    it('should throw invalid_proof if payload claims are invalid (missing aud)', async () => {
      const provider = setupProvider()
      const proof = await createTestProof({ iss: clientId }, 'ES256', testKid) // Missing aud
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: 'Unsupported Proof Payload.',
      })
    })

    it('should throw invalid_proof if iss is present in anonymous pre-auth flow', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { iss: clientId, aud: credentialIssuer },
        'ES256',
        testKid,
        'openid4vci-proof+jwt'
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message:
          'iss claim must be omitted when using an access token obtained through anonymous access.',
      })
    })

    it('should verify pre-auth flow when access token client_id matches iss', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { iss: clientId, aud: credentialIssuer, nonce: 'n' },
        'ES256',
        testKid
      )
      const result = await provider.verifyProof(proof, preAuthRegisteredClientCtx)
      assert.ok(result)
      assert.equal(result?.payload.iss, clientId)
    })

    it('should throw invalid_proof if iss does not match access token client_id in pre-auth flow', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { iss: 'wrong-client', aud: credentialIssuer, nonce: 'n' },
        'ES256',
        testKid
      )
      await assert.rejects(provider.verifyProof(proof, preAuthRegisteredClientCtx), {
        name: 'invalid_proof',
        message: 'iss claim must match the client_id of the Client making the Credential request.',
      })
    })

    it('should throw invalid_proof if iss is non-string in anonymous pre-auth flow', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { aud: credentialIssuer, nonce: 'n', iss: 12345 } as unknown as JWTPayload,
        'ES256',
        testKid
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message:
          'iss claim must be omitted when using an access token obtained through anonymous access.',
      })
    })

    it('should verify auth-code flow when iss equals credential issuer identifier', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { iss: credentialIssuer, aud: credentialIssuer, nonce: 'n' },
        'ES256',
        testKid
      )
      const result = await provider.verifyProof(proof, authCodeCtx)
      assert.ok(result)
      assert.equal(result?.payload.iss, credentialIssuer)
    })

    it('should throw invalid_proof if iss is non-string in anonymous pre-auth flow when iss is present', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { aud: credentialIssuer, nonce: 'n', iss: 99 } as unknown as JWTPayload,
        'ES256',
        testKid
      )
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message:
          'iss claim must be omitted when using an access token obtained through anonymous access.',
      })
    })

    it('should throw invalid_proof if iss is non-string in registered-client pre-auth flow', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { aud: credentialIssuer, nonce: 'n', iss: 12345 } as unknown as JWTPayload,
        'ES256',
        testKid
      )
      await assert.rejects(provider.verifyProof(proof, preAuthRegisteredClientCtx), {
        name: 'invalid_proof',
        message: 'iss claim must match the client_id of the Client making the Credential request.',
      })
    })

    it('should verify auth-code flow when iss equals credential issuer identifier', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { iss: credentialIssuer, aud: credentialIssuer, nonce: 'n' },
        'ES256',
        testKid
      )
      const result = await provider.verifyProof(proof, authCodeCtx)
      assert.ok(result)
      assert.equal(result?.payload.iss, credentialIssuer)
    })

    it('should throw invalid_proof if iss is non-string in auth-code flow when iss is present', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { aud: credentialIssuer, nonce: 'n', iss: 99 } as unknown as JWTPayload,
        'ES256',
        testKid
      )
      await assert.rejects(provider.verifyProof(proof, authCodeCtx), {
        name: 'invalid_proof',
        message:
          'iss claim must be the client_id of the Client making the Credential request or the Credential Issuer Identifier.',
      })
    })

    it('should throw invalid_proof if iss is neither client_id nor credential issuer in auth-code flow', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { iss: 'wrong-client', aud: credentialIssuer },
        'ES256',
        testKid,
        'openid4vci-proof+jwt'
      )
      await assert.rejects(provider.verifyProof(proof, authCodeCtx), {
        name: 'invalid_proof',
        message:
          'iss claim must be the client_id of the Client making the Credential request or the Credential Issuer Identifier.',
      })
    })

    it('should throw invalid_proof if aud does not match credential_issuer', async () => {
      const provider = setupProvider()
      const proof = await createTestProof({ aud: 'wrong-issuer' }, 'ES256', testKid)
      await assert.rejects(provider.verifyProof(proof, preAuthCtx), {
        name: 'invalid_proof',
        message: 'aud claim must be the Credential Issuer Identifier.',
      })
    })

    it('should throw invalid_proof when verifyProof is called without OID4VCI context', async () => {
      const provider = setupProvider()
      const proof = await createTestProof({ aud: credentialIssuer }, 'ES256', testKid)
      await assert.rejects(provider.verifyProof(proof), {
        name: 'invalid_proof',
        message:
          'Credential proof verification requires credentialIssuer and usePreAuth (OID4VCI). Pass CredentialProofJwtVerifyContext as the second argument to verifyProof().',
      })
    })

    it('should verify when verifyProof receives context', async () => {
      const provider = setupProvider()
      const payload = { aud: credentialIssuer, nonce: 'test-nonce' }
      const proof = await createTestProof(payload, 'ES256', testKid)
      const result = await provider.verifyProof(proof, preAuthCtx)
      assert.ok(result)
      assert.equal(result?.payload.aud, credentialIssuer)
    })
  })
})

