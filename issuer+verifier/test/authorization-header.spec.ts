import assert from 'node:assert'
import { describe, it } from 'node:test'
import { parseAuthorizationHeader } from '../src/authorization-header'

describe('parseAuthorizationHeader()', () => {
  it('should return missing when Authorization header is not provided', () => {
    assert.deepEqual(parseAuthorizationHeader(), { ok: false, reason: 'missing' })
    assert.deepEqual(parseAuthorizationHeader(null), { ok: false, reason: 'missing' })
    assert.deepEqual(parseAuthorizationHeader('   '), { ok: false, reason: 'missing' })
  })

  it('should parse Bearer and DPoP schemes case-insensitively', () => {
    assert.deepEqual(parseAuthorizationHeader('Bearer access-token'), {
      ok: true,
      value: { scheme: 'bearer', token: 'access-token' },
    })
    assert.deepEqual(parseAuthorizationHeader('dpop access-token'), {
      ok: true,
      value: { scheme: 'dpop', token: 'access-token' },
    })
  })

  it('should trim surrounding whitespace before parsing', () => {
    assert.deepEqual(parseAuthorizationHeader('  bearer access-token  '), {
      ok: true,
      value: { scheme: 'bearer', token: 'access-token' },
    })
  })

  it('should reject malformed Authorization header values', () => {
    assert.deepEqual(parseAuthorizationHeader('Bearer'), {
      ok: false,
      reason: 'malformed',
    })
    assert.deepEqual(parseAuthorizationHeader('Bearer access token'), {
      ok: false,
      reason: 'malformed',
    })
  })

  it('should reject unsupported schemes', () => {
    assert.deepEqual(parseAuthorizationHeader('Basic credentials'), {
      ok: false,
      reason: 'unsupported_scheme',
      scheme: 'Basic',
    })
  })
})
