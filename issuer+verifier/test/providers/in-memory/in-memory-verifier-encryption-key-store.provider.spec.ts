import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { ClientId } from '../../../src/client-id.types'
import { inMemoryVerifierEncryptionKeyStore } from '../../../src/providers/in-memory/in-memory-verifier-encryption-key-store.providers'
import { verifierEncryptionKey } from '../../../src/providers/verifier-encryption-key.provider'

describe('inMemoryVerifierEncryptionKeyStore', () => {
  let store: ReturnType<typeof inMemoryVerifierEncryptionKeyStore>
  const verifier = ClientId('https://verifier.example.com')

  beforeEach(() => {
    store = inMemoryVerifierEncryptionKeyStore()
    store.providers = {
      get(kind) {
        if (kind === 'verifier-encryption-key-provider') {
          return [verifierEncryptionKey()]
        }
        throw new Error(`unexpected provider kind: ${kind}`)
      },
      select() {
        throw new Error('select should not be called in this test')
      },
    }
  })

  it('should save and fetch an encryption public jwk for a verifier', async () => {
    await store.save(verifier, 'ECDH-ES')
    const fetched = await store.fetch(verifier, 'ECDH-ES')

    assert.ok(fetched)
    assert.equal(fetched.alg, 'ECDH-ES')
    assert.equal(fetched.use, 'enc')
    assert.ok(fetched.kid)
  })

  it('should replace encryption key with same alg', async () => {
    await store.save(verifier, 'ECDH-ES')
    const first = await store.fetch(verifier, 'ECDH-ES')
    await store.save(verifier, 'ECDH-ES')
    const second = await store.fetch(verifier, 'ECDH-ES')

    assert.ok(first)
    assert.ok(second)
    assert.notEqual(first.kid, second.kid)
  })

  it('should return null if no encryption key pairs are saved', async () => {
    const fetched = await store.fetch(ClientId('https://unknown.example.com'), 'ECDH-ES')
    assert.strictEqual(fetched, null)
  })

  it('should return null if requested algorithm is not found', async () => {
    await store.save(verifier, 'ECDH-ES')
    const fetched = await store.fetch(verifier, 'ES256')
    assert.strictEqual(fetched, null)
  })
})
