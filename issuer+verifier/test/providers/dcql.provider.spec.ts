import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { CredentialQueryGenerationOptions } from '../../src/providers'
import { dcql } from '../../src/providers/dcql.provider'

describe('DcqlProvider', () => {
  const provider = dcql()

  it('should have correct properties', () => {
    assert.equal(provider.kind, 'credential-query-provider')
    assert.equal(provider.name, 'default-dcql-provider')
    assert.equal(provider.single, false)
  })

  describe('canHandle', () => {
    it('should return true for "dcql"', () => {
      assert.ok(provider.canHandle('dcql'))
    })

    it('should return false for other queries', () => {
      assert.equal(provider.canHandle('presentation-exchange'), false)
    })
  })

  describe('generate', () => {
    it('should generate a dcql query', async () => {
      const query = {
        credentials: [
          {
            id: 'test-cred',
            format: 'jwt_vc_json',
            meta: {},
            claims: [{ path: ['$.vc.type'] }],
          },
        ],
      }
      const options = {
        kind: 'dcql',
        query: { dcql_query: query },
      } satisfies CredentialQueryGenerationOptions

      const result = await provider.generate(options)

      assert.deepEqual(result, { dcql_query: query })
    })

    it('should throw an error for unsupported kind', async () => {
      const options = {
        kind: 'presentation-exchange',
        query: {},
      } satisfies CredentialQueryGenerationOptions

      await assert.rejects(provider.generate(options), {
        name: 'illegal_argument',
        message: 'presentation-exchange is not supported.',
      })
    })
  })
})

