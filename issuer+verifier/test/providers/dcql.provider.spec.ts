import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { dcql } from '../../src/providers/dcql.provider'

describe('DcqlProvider', () => {
  const provider = dcql()

  it('should have correct properties', () => {
    assert.equal(provider.kind, 'credential-query-provider')
    assert.equal(provider.name, 'default-dcql-provider')
    assert.equal(provider.single, true)
  })

  describe('generate', () => {
    it('should parse and return a valid dcql query', async () => {
      const result = await provider.generate({
        dcql_query: {
          credentials: [
            {
              id: 'test-cred',
              format: 'jwt_vc_json',
              meta: { type_values: [['VerifiableCredential']] },
              claims: [{ path: ['vc', 'credentialSubject', 'name'] }],
            },
          ],
        },
      })

      assert.equal(result.dcql_query.credentials[0].id, 'test-cred')
      assert.equal(result.dcql_query.credentials[0].format, 'jwt_vc_json')
    })

    it('should throw invalid_request for invalid meta key in dc+sd-jwt format', async () => {
      await assert.rejects(
        provider.generate({
          dcql_query: {
            credentials: [
              {
                id: 'test-cred',
                format: 'dc+sd-jwt',
                meta: { doctype_value: 'wrong-key-for-sdjwt' },
                claims: [{ path: ['given_name'] }],
              },
            ],
          },
        }),
        { name: 'invalid_request' }
      )
    })

    it('should throw invalid_request for invalid meta key in mso_mdoc format', async () => {
      await assert.rejects(
        provider.generate({
          dcql_query: {
            credentials: [
              {
                id: 'test-cred',
                format: 'mso_mdoc',
                meta: { vct_values: ['wrong-key-for-mdoc'] },
                claims: [{ path: ['given_name'] }],
              },
            ],
          },
        }),
        { name: 'invalid_request' }
      )
    })

    it('should allow valid meta keys for each format', async () => {
      const cases: Array<{ format: string; meta: Record<string, unknown>; claims: unknown[] }> = [
        {
          format: 'mso_mdoc',
          meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
          claims: [{ path: ['org.iso.18013.5.1', 'given_name'] }],
        },
        {
          format: 'dc+sd-jwt',
          meta: { vct_values: ['https://example.com/vct'] },
          claims: [{ path: ['given_name'] }],
        },
        {
          format: 'ldp_vc',
          meta: { type_values: [['VerifiableCredential']] },
          claims: [{ path: ['name'] }],
        },
        {
          format: 'jwt_vc_json',
          meta: { type_values: [['VerifiableCredential']] },
          claims: [{ path: ['name'] }],
        },
      ]

      for (const { format, meta, claims } of cases) {
        const result = await provider.generate({
          dcql_query: {
            credentials: [
              {
                id: 'test-cred',
                format,
                meta,
                claims,
              },
            ],
          },
        })
        assert.equal(result.dcql_query.credentials[0].format, format)
      }
    })

    it('should throw for structurally invalid DCQL query (missing required id)', async () => {
      await assert.rejects(
        provider.generate({
          dcql_query: {
            credentials: [{ format: 'jwt_vc_json' }],
          },
        })
      )
    })
  })
})

