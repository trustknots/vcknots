import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { parseDpopHeader } from '../src/dpop-proof'

describe('parseDpopHeader()', () => {
  it('should return missing when header is not provided', () => {
    assert.deepEqual(parseDpopHeader(), { ok: false, reason: 'missing' })
    assert.deepEqual(parseDpopHeader(null), { ok: false, reason: 'missing' })
    assert.deepEqual(parseDpopHeader('   '), { ok: false, reason: 'missing' })
  })

  it('should parse a compact JWT DPoP header', () => {
    assert.deepEqual(parseDpopHeader('aaa.bbb.ccc'), {
      ok: true,
      proofJwt: 'aaa.bbb.ccc',
    })
  })

  it('should trim surrounding whitespace before parsing', () => {
    assert.deepEqual(parseDpopHeader('  aaa.bbb.ccc  '), {
      ok: true,
      proofJwt: 'aaa.bbb.ccc',
    })
  })

  it('should reject comma-separated duplicate header values', () => {
    assert.deepEqual(parseDpopHeader('aaa.bbb.ccc, ddd.eee.fff'), {
      ok: false,
      reason: 'duplicate',
    })
  })

  it('should reject malformed compact JWT values', () => {
    assert.deepEqual(parseDpopHeader('aaa.bbb'), { ok: false, reason: 'malformed' })
    assert.deepEqual(parseDpopHeader('aaa.bbb.ccc.ddd'), { ok: false, reason: 'malformed' })
    assert.deepEqual(parseDpopHeader('aaa bbb.ccc.ddd'), { ok: false, reason: 'malformed' })
  })
})
