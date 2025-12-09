import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { ClientId } from '../../../src/client-id.types'
import { inMemoryVerifierMetadataStore } from '../../../src/providers/in-memory/in-memory-verifier-metadata-store.provider'
import { VerifierMetadata } from '../../../src/verifier-metadata.types'

describe('inMemoryVerifierMetadataStore', () => {
  let store: ReturnType<typeof inMemoryVerifierMetadataStore>
  const verifierId = ClientId('https://verifier.example.com')
  const metadata: VerifierMetadata = {
    client_name: 'Test Verifier',
    jwks: { keys: [] },
    vp_formats: {
      jwt_vc_json: {
        alg_values_supported: ['ES256']
      },
      jwt_vp_json: {
        alg_values_supported: ['ES256']
      },
      'dc+sd-jwt': {
        'sd-jwt_alg_values': ['ES256', 'ES384'],
        'kb-jwt_alg_values': ['ES256', 'ES384']
      }
    },
  }

  beforeEach(() => {
    store = inMemoryVerifierMetadataStore()
  })

  it('should save and fetch metadata for a verifier', async () => {
    await store.save(verifierId, metadata)
    const fetched = await store.fetch(verifierId)
    assert.deepStrictEqual(fetched, metadata)
  })

  it('should return null if no metadata is saved', async () => {
    const fetched = await store.fetch(ClientId('https://unknown.example.com'))
    assert.strictEqual(fetched, null)
  })

  it('should overwrite existing metadata', async () => {
    const newMetadata: VerifierMetadata = {
      ...metadata,
      client_name: 'New Test Verifier',
    }
    await store.save(verifierId, metadata)
    await store.save(verifierId, newMetadata)
    const fetched = await store.fetch(verifierId)
    assert.deepStrictEqual(fetched, newMetadata)
  })
})
