import { strict as assert } from 'node:assert'
import { describe, it } from 'node:test'
import { Provider } from '../../src/providers/provider.types'
import { CanHandle, selectProvider } from '../../src/providers/provider.utils'

type MockProvider = Provider & CanHandle<string>

describe('selectProvider', () => {
  const one: CanHandle<string> = {
    canHandle: (input: string) => input === 'one',
  }

  const two: CanHandle<string> = {
    canHandle: (input: string) => input === 'two',
  }

  const won: CanHandle<string> = {
    canHandle: (input: string) => input === 'one', // it's another one!
  }

  const candidates = [one, two, won] as MockProvider[]

  it('should return the provider that can handle the specified input', () => {
    const result = selectProvider(candidates, 'two')
    assert.equal(result, two)
  })

  it('should return the first matching provider if multiple can handle the input', () => {
    const result = selectProvider(candidates, 'one')
    assert.equal(result, one)
  })

  it('should throw a VcknotsError when no provider can handle the input', () => {
    assert.throws(() => selectProvider(candidates, 'three'), 'provider_not_found')
  })

  it('should throw an error when the list of candidates is empty', () => {
    assert.throws(() => selectProvider([], 'any'), 'provider_not_found')
  })
})

