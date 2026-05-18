import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { holderBinding } from '../../src/providers/holder-binding.provider'
import { DidProvider } from '../../src/providers/provider.types'
import { JwtVcJson, VerifiableCredential } from '../../src/credential.types'
import { DidDocument, JsonWebKey } from '../../src/did.types'
import { VcknotsError } from '../../src/errors'
import { ProviderMap, ProviderRegistry } from '../../src/providers/provider.registry'

describe('HolderBindingProvider', () => {
  const publicKeyJwk: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  }

  const otherPublicKeyJwk: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
    y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
  }

  const mockDidProvider: DidProvider = {
    kind: 'did-provider',
    name: 'mock-did-provider',
    single: false,
    canHandle: (method: string) => method === 'mock',
    resolveDid: async (did: string): Promise<DidDocument | null> => {
      if (did === 'did:mock:123') {
        return {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: did,
          verificationMethod: [
            {
              id: `${did}#keys-1`,
              type: 'JsonWebKey2020',
              controller: did,
              publicKeyJwk: publicKeyJwk,
            },
          ],
        }
      }
      return null
    },
  }

  const createMockRegistry = (providers: DidProvider[]): ProviderRegistry => {
    return {
      get: <K extends keyof ProviderMap>(kind: K): ProviderMap[K] => {
        if (kind === 'did-provider') {
          return providers as ProviderMap[K]
        }
        return [] as unknown as ProviderMap[K]
      },
      select: () => {
        throw new Error('select should not be called')
      },
    }
  }

  it('should have correct kind, name, and single properties', () => {
    const provider = holderBinding()
    assert.equal(provider.kind, 'holder-binding-provider')
    assert.equal(provider.name, 'default-holder-binding-provider')
    assert.strictEqual(provider.single, true)
  })

  it('should return true when public key matches the verification method', async () => {
    const provider = holderBinding()
    provider.providers = createMockRegistry([mockDidProvider])
    const credential = {
      id: 'urn:uuid:12345',
      credentialSubject: {
        id: 'did:mock:123',
      },
    } as VerifiableCredential<JwtVcJson>
    const result = await provider.verify([credential], publicKeyJwk)
    assert.strictEqual(result, true)
  })

  it('should throw error when binding verification fails', async () => {
    const provider = holderBinding()
    provider.providers = createMockRegistry([mockDidProvider])
    const credential = {
      id: 'urn:uuid:12345',
      credentialSubject: {
        id: 'did:mock:123',
      },
    } as VerifiableCredential<JwtVcJson>

    await assert.rejects(provider.verify([credential], otherPublicKeyJwk), (err: VcknotsError) => {
      assert.equal(err.name, 'invalid_credential')
      assert.match(err.message, /Binding verification failed for VC/)
      return true
    })
  })

  it('should throw error for invalid credential (missing credentialSubject)', async () => {
    const provider = holderBinding()
    provider.providers = createMockRegistry([mockDidProvider])
    const credential = { id: 'urn:uuid:12345' } as VerifiableCredential<JwtVcJson>
    await assert.rejects(provider.verify([credential], publicKeyJwk), (err: VcknotsError) => {
      assert.equal(err.name, 'invalid_credential')
      assert.match(err.message, /Missing credentialSubject in VC/)
      return true
    })
  })

  it('should throw error for invalid credential (missing credentialSubject.id)', async () => {
    const provider = holderBinding()
    provider.providers = createMockRegistry([mockDidProvider])
    const credential = {
      id: 'urn:uuid:12345',
      credentialSubject: {},
    } as VerifiableCredential<JwtVcJson>
    await assert.rejects(provider.verify([credential], publicKeyJwk), (err: VcknotsError) => {
      assert.equal(err.name, 'invalid_credential')
      assert.match(err.message, /Missing credentialSubject.id in VC/)
      return true
    })
  })

  it('should throw error when did provider is not found', async () => {
    const provider = holderBinding()
    provider.providers = createMockRegistry([])
    const credential = {
      id: 'urn:uuid:12345',
      credentialSubject: {
        id: 'did:mock:123',
      },
    } as VerifiableCredential<JwtVcJson>
    await assert.rejects(provider.verify([credential], publicKeyJwk), (err: VcknotsError) => {
      assert.equal(err.name, 'invalid_proof')
      assert.match(err.message, /No kid or unsupported did type detected/)
      return true
    })
  })

  it('should throw error when DID cannot be resolved', async () => {
    const provider = holderBinding()
    provider.providers = createMockRegistry([mockDidProvider])
    const credential = {
      id: 'urn:uuid:12345',
      credentialSubject: {
        id: 'did:mock:unknown',
      },
    } as VerifiableCredential<JwtVcJson>
    await assert.rejects(provider.verify([credential], publicKeyJwk), (err: VcknotsError) => {
      assert.equal(err.name, 'invalid_credential')
      assert.match(err.message, /Cannot resolve DID/)
      return true
    })
  })

  it('should throw error for invalid DID format', async () => {
    const provider = holderBinding()
    provider.providers = createMockRegistry([mockDidProvider])
    const credential = {
      id: 'urn:uuid:12345',
      credentialSubject: {
        id: 'did:mock',
      },
    } as VerifiableCredential<JwtVcJson>
    await assert.rejects(provider.verify([credential], publicKeyJwk), (err: VcknotsError) => {
      assert.equal(err.name, 'invalid_proof')
      assert.match(err.message, /Invalid DID format/)
      return true
    })
  })
})

