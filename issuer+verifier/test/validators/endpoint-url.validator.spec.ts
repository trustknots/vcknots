import assert from 'node:assert/strict'
import { afterEach, beforeEach, describe, it } from 'node:test'

import { endpointUrlSchema } from '../../src/validators/endpoint-url.validator'

describe('endpoint-url.validator', () => {
  const allowInsecureHttpSnapshot = process.env.VCKNOTS_HTTP_ALLOWED
  const debugSnapshot = process.env.VCKNOTS_DEBUG

  beforeEach(() => {
    process.env.VCKNOTS_HTTP_ALLOWED = ''
    process.env.VCKNOTS_DEBUG = ''
  })

  afterEach(() => {
    process.env.VCKNOTS_HTTP_ALLOWED = allowInsecureHttpSnapshot
    process.env.VCKNOTS_DEBUG = debugSnapshot
  })

  it('should accept https URLs', () => {
    const actual = endpointUrlSchema.parse('https://issuer.example.com/credential')

    assert.equal(actual, 'https://issuer.example.com/credential')
  })

  it('should reject http URLs by default', () => {
    assert.throws(() => endpointUrlSchema.parse('http://issuer.example.com/credential'))
  })

  it('should accept http URLs when VCKNOTS_HTTP_ALLOWED is true', () => {
    process.env.VCKNOTS_HTTP_ALLOWED = 'true'

    const actual = endpointUrlSchema.parse('http://issuer.example.com/credential')

    assert.equal(actual, 'http://issuer.example.com/credential')
  })

  it('should accept http URLs when VCKNOTS_DEBUG is true', () => {
    process.env.VCKNOTS_DEBUG = 'true'

    const actual = endpointUrlSchema.parse('http://issuer.example.com/credential')

    assert.equal(actual, 'http://issuer.example.com/credential')
  })

  it('should reject malformed URLs', () => {
    assert.throws(() => endpointUrlSchema.parse(':::invalid:::'))
  })
})
