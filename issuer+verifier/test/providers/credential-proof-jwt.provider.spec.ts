import assert from 'node:assert/strict'
import { describe, it, before, mock } from 'node:test'
import {
  credentialProofJWT,
  CredentialProofProviderOptions,
} from '../../src/providers/credential-proof-jwt.provider'
import { CredentialProofProvider, DidProvider } from '../../src/providers/provider.types'
import { WithProviderRegistry } from '../../src/providers/provider.registry'
import { generateKeyPair, SignJWT, exportJWK, JWTPayload } from 'jose'
import { VcknotsError, raise } from '../../src/errors/vcknots.error'
import { DidDocument, JsonWebKey } from '../../src/did.types'

describe('CredentialProofJwtProvider', () => {
  let keys: { publicKey: CryptoKey; privateKey: CryptoKey }
  let publicKeyJwk: JsonWebKey
  const credentialIssuer = 'https://issuer.example.com'
  const clientId = 'test-client'
  const testDid = 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH'
  // Note: The kid should contain the full DID and fragment.
  const testKid = `${testDid}#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH`

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
      throw raise('INVALID_PROOF', { message: `did ${did} not found.` })
    }),
  }

  const createTestProof = async (
    payload: JWTPayload,
    alg: string,
    kid: string,
    typ: string,
    customHeader?: object
  ) => {
    return await new SignJWT(payload)
      .setProtectedHeader({ alg, kid, typ, ...customHeader })
      .setIssuedAt()
      .sign(keys.privateKey)
  }

  before(async () => {
    keys = await generateKeyPair('ES256')
    const jwk = await exportJWK(keys.publicKey)
    assert(jwk.kty, 'kty must be defined')
    publicKeyJwk = jwk as JsonWebKey
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
    const setupProvider = (
      options?: CredentialProofProviderOptions
    ): CredentialProofProvider & WithProviderRegistry => {
      const provider = credentialProofJWT(options)
      // Mock the get method of the provider registry
      mock.method(provider.providers, 'get', (name: string) => {
        if (name === 'did-provider') {
          return [mockDidProvider]
        }
        return []
      })
      return provider
    }

    it('should verify a valid proof for pre-authorized code flow', async () => {
      const provider = setupProvider({ usePreAuth: true, credentialIssuer })
      const payload = { aud: credentialIssuer, nonce: 'test-nonce' }
      const proof = await createTestProof(payload, 'ES256', testKid, 'openid4vci-proof+jwt')

      const result = await provider.verifyProof(proof)

      assert.ok(result)
      assert.equal(result.payload.aud, credentialIssuer)
      assert.equal(result.payload.nonce, 'test-nonce')
      assert.equal(result.header.alg, 'ES256')
      assert.equal(result.header.kid, testKid)
      assert.strictEqual(result.payload.iss, undefined)
    })

    it('should verify a valid proof for authorization code flow', async () => {
      const provider = setupProvider({ usePreAuth: false, credentialIssuer, clientId })
      const payload = { iss: clientId, aud: credentialIssuer, nonce: 'test-nonce' }
      const proof = await createTestProof(payload, 'ES256', testKid, 'openid4vci-proof+jwt')

      const result = await provider.verifyProof(proof)

      assert.ok(result)
      assert.equal(result.payload.iss, clientId)
      assert.equal(result.payload.aud, credentialIssuer)
    })

    it('should throw INVALID_PROOF for malformed JWT', async () => {
      const provider = setupProvider()
      await assert.rejects(provider.verifyProof('invalid-jwt'), (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_PROOF')
        return true
      })
    })

    it('should throw INVALID_PROOF if kid is missing in header', async () => {
      const provider = setupProvider()
      const proof = await new SignJWT({ aud: credentialIssuer })
        .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt' }) // No kid
        .sign(keys.privateKey)
      await assert.rejects(provider.verifyProof(proof), (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_PROOF')
        assert.equal(err.message, 'Unsupported Proof Header.')
        return true
      })
    })

    it('should throw INVALID_PROOF if typ is not openid4vci-proof+jwt in header', async () => {
      const provider = setupProvider()
      const payload = { aud: credentialIssuer, nonce: 'test-nonce' }
      const proof = await createTestProof(payload, 'ES256', testKid, 'invalid-typ')
      await assert.rejects(provider.verifyProof(proof), (err: VcknotsError) => {
        assert.equal(err.name, 'INVALID_PROOF')
        assert.equal(err.message, 'Invalid Proof Header typ value.')
        return true
      })
    })

    it('should throw INVALID_PROOF for invalid DID format in kid', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { aud: credentialIssuer },
        'ES256',
        'invalid-did',
        'openid4vci-proof+jwt'
      )
      await assert.rejects(provider.verifyProof(proof), {
        name: 'INVALID_PROOF',
        message: 'Invalid DID format: invalid-did',
      })
    })

    it('should throw INVALID_PROOF if no suitable DID provider is found', async () => {
      const provider = credentialProofJWT({ usePreAuth: true, credentialIssuer })
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
        assert.equal(err.name, 'INVALID_PROOF')
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
      await assert.rejects(provider.verifyProof(proof), { name: 'INVALID_PROOF' })
    })

    it('should throw INVALID_PROOF if resolved DID doc is invalid (missing verificationMethod)', async () => {
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
        name: 'INVALID_PROOF',
        message: 'Unsupported did type detected.',
      })
    })

    it('should throw INVALID_PROOF for invalid signature', async () => {
      const provider = setupProvider()
      const otherKeys = await generateKeyPair('ES256')
      const proof = await new SignJWT({ aud: credentialIssuer })
        .setProtectedHeader({ alg: 'ES256', kid: testKid, typ: 'openid4vci-proof+jwt' })
        .setIssuedAt()
        .sign(otherKeys.privateKey) // Signed with a different key
      await assert.rejects(provider.verifyProof(proof), (err: Error & { code?: string }) => {
        // jose throws JWSSignatureVerificationFailed
        assert.equal(err.code, 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED')
        return true
      })
    })

    it('should throw INVALID_PROOF if payload claims are invalid (missing aud)', async () => {
      const provider = setupProvider()
      const proof = await createTestProof(
        { iss: clientId },
        'ES256',
        testKid,
        'openid4vci-proof+jwt'
      ) // Missing aud
      await assert.rejects(provider.verifyProof(proof), {
        name: 'INVALID_PROOF',
        message: 'Unsupported Proof Payload.',
      })
    })

    it('should throw INVALID_PROOF if iss is present in pre-auth flow', async () => {
      const provider = setupProvider({ usePreAuth: true, credentialIssuer })
      const proof = await createTestProof(
        { iss: clientId, aud: credentialIssuer },
        'ES256',
        testKid,
        'openid4vci-proof+jwt'
      )
      await assert.rejects(provider.verifyProof(proof), {
        name: 'INVALID_PROOF',
        message: 'iss claim must omitted using case Pre-Authorized Code Flow.',
      })
    })

    it('should throw INVALID_PROOF if iss does not match client_id in auth-code flow', async () => {
      const provider = setupProvider({ usePreAuth: false, credentialIssuer, clientId })
      const proof = await createTestProof(
        { iss: 'wrong-client', aud: credentialIssuer },
        'ES256',
        testKid,
        'openid4vci-proof+jwt'
      )
      await assert.rejects(provider.verifyProof(proof), {
        name: 'INVALID_PROOF',
        message: 'iss claim must the client_id of the Client making the Credential request.',
      })
    })

    it('should throw INVALID_PROOF if aud does not match credential_issuer', async () => {
      const provider = setupProvider({ usePreAuth: true, credentialIssuer })
      const proof = await createTestProof(
        { aud: 'wrong-issuer' },
        'ES256',
        testKid,
        'openid4vci-proof+jwt'
      )
      await assert.rejects(provider.verifyProof(proof), {
        name: 'INVALID_PROOF',
        message: 'aud claim must be the Credential Issuer Identifier.',
      })
    })
  })
})
