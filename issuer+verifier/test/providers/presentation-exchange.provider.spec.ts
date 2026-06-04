import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { PresentationDefinition } from '../../src/presentation-definition.types'
import { CredentialQueryGenerationOptions } from '../../src/providers'
import { presentationExchange } from '../../src/providers/presentation-exchange.provider'

describe('PresentationExchangeProvider', () => {
  const provider = presentationExchange()

  it('should have correct properties', () => {
    assert.equal(provider.kind, 'credential-query-provider')
    assert.equal(provider.name, 'default-presentation-exchange-provider')
    assert.equal(provider.single, false)
  })

  describe('canHandle', () => {
    it('should return true for "presentation-exchange"', () => {
      assert.ok(provider.canHandle('presentation-exchange'))
    })

    it('should return false for other queries', () => {
      assert.equal(provider.canHandle('dcql'), false)
    })
  })

  describe('generate', () => {
    it('should generate a presentation exchange query', async () => {
      const definition = PresentationDefinition({
        id: 'test-pd',
        input_descriptors: [{ id: 'test_input', constraints: {} }],
      })
      const options = {
        kind: 'presentation-exchange',
        query: { presentation_definition: definition },
      } satisfies CredentialQueryGenerationOptions

      const result = await provider.generate(options)

      assert.deepEqual(result, { presentation_definition: definition })
    })

    it('should throw an error for unsupported kind', async () => {
      const options = {
        kind: 'dcql',
        query: {},
      } satisfies CredentialQueryGenerationOptions

      await assert.rejects(provider.generate(options), {
        name: 'illegal_argument',
        message: '"dcql" is not supported.',
      })
    })
  })
})

