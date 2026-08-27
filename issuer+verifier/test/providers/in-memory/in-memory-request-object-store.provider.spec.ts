import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { inMemoryRequestObjectStore } from '../../../src/providers/in-memory/in-memory-request-object-store.provider'
import { RequestObjectId } from '../../../src/request-object-id.types'
import { RequestObject } from '../../../lib/request-object.types'

describe('InMemoryRequestObjectStoreProvider', () => {
  let provider: ReturnType<typeof inMemoryRequestObjectStore>
  const requestObjectId = RequestObjectId('1234')
  const requestObject: RequestObject = {
    response_type: 'vp_token',
    client_id: 'https://example.com/client123',
    nonce: 'nonce123',
    response_mode: 'direct_post',
    dcql_query: {
      credentials: [
        {
          id: 'test-cred',
          format: 'jwt_vc_json',
          meta: {},
          claims: [{ path: ['$.vc.type'] }],
        },
      ],
    },
  }
  beforeEach(() => {
    provider = inMemoryRequestObjectStore()
  })

  it('should return null when fetching unknown id', async () => {
    const unknownId = requestObjectId
    const fetched = await provider.fetch(unknownId)
    assert.equal(fetched, null)
  })

  it('should save and fetch a request object with DCQL', async () => {
    const id = requestObjectId
    const reqObj = requestObject

    await provider.save(id, reqObj)
    const fetched = await provider.fetch(id)

    assert.notEqual(fetched, null)
    assert.deepEqual(fetched, requestObject)
  })

  it('should overwrite existing request object when saving with the same id', async () => {
    const id = requestObjectId
    const original = requestObject
    const updated = { ...requestObject, client_id: 'https://example.com/updated' }

    await provider.save(id, original)
    await provider.save(id, updated)

    const fetched = await provider.fetch(id)
    assert.notEqual(fetched, null)
    assert.deepEqual(fetched, updated)
    assert.notDeepEqual(fetched, original)
  })

  it('should delete an existing request object', async () => {
    const id = requestObjectId
    const reqObj = requestObject
    await provider.save(id, reqObj)

    await provider.delete(id)
    const fetched = await provider.fetch(id)
    assert.equal(fetched, null)
  })
})
