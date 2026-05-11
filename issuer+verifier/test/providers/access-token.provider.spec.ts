import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { AuthorizationServerIssuer } from '../../src/authorization-server.types'
import { PreAuthorizedCode } from '../../src/pre-authorized-code.types'
import { accessToken } from '../../src/providers/access-token.provider'
import { AccessTokenProvider } from '../../src/providers/provider.types'

describe('AccessTokenProvider', () => {
  const provider: AccessTokenProvider = accessToken()

  it('should be an AccessTokenProvider', () => {
    assert.ok(provider, 'Provider instance should be created')
    assert.equal(
      typeof provider.createTokenPayload,
      'function',
      'Provider should have createTokenPayload function'
    )
  })

  it('should have correct kind, name, and single properties', () => {
    assert.equal(provider.kind, 'access-token-provider', "Kind should be 'access-token-provider'")
    assert.equal(
      provider.name,
      'default-access-token-provider',
      "Name should be 'default-access-token-provider'"
    )
    assert.strictEqual(provider.single, true, 'Single should be true')
  })

  describe('createTokenPayload()', () => {
    const nowSec = Math.floor(Date.now() / 1000)
    const issuer = AuthorizationServerIssuer('https://auth.example.com')
    const code = PreAuthorizedCode('authz-code-123')

    it('should create a payload with default ttl (86400 seconds)', async () => {
      const payload = await provider.createTokenPayload(issuer, code, undefined)

      assert.equal(payload.iss, issuer, 'iss should match issuer')
      assert.equal(payload.sub, code, 'sub should match code')
      assert.ok(payload.iat)
      assert.ok(payload.exp)
      assert.ok(Math.abs(payload.iat - nowSec) <= 1, 'iat should be close to current time')
      assert.ok(payload.exp - payload.iat === 86400, 'exp should be 86400 seconds after iat')
    })

    it('should create a payload with custom ttl from options.ttlSec', async () => {
      const customTtl = 3600
      const payload = await provider.createTokenPayload(issuer, code, { ttlSec: customTtl })

      assert.ok(payload.iat)
      assert.ok(payload.exp)
      assert.equal(payload.exp - payload.iat, customTtl, 'exp should reflect custom ttlSec')
    })
  })
})
