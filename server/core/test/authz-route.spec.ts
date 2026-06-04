import assert from 'node:assert/strict'
import { randomUUID, webcrypto } from 'node:crypto'
import { describe, it } from 'node:test'
import { initializeContext, type DPoPMode } from '@trustknots/vcknots'
import { createAuthzRouter } from '../src/routes/authz.ts'

const baseUrl = 'https://issuer.example.com'

const createAuthzApp = (mode: DPoPMode) =>
  createAuthzRouter(
    initializeContext({
      oauth: {
        senderConstrainedAccessToken: {
          dpop: { mode },
        },
      },
    }),
    baseUrl
  )

const createDpopProof = async (claims?: { nonce?: string }) => {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )
  const { kty, crv, x, y } = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey)
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: { kty, crv, x, y },
  }
  const payload = {
    htm: 'POST',
    htu: `${baseUrl}/token`,
    iat: Math.floor(Date.now() / 1000),
    jti: randomUUID(),
    ...(claims?.nonce ? { nonce: claims.nonce } : {}),
  }
  const signingInput = `${encode(header)}.${encode(payload)}`
  const signature = await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    Buffer.from(signingInput)
  )
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`
}

const postToken = (
  mode: DPoPMode,
  options?: {
    dpop?: string
    body?: string
  }
) =>
  createAuthzApp(mode).request('/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...(options?.dpop ? { DPoP: options.dpop } : {}),
    },
    body:
      options?.body ??
      'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=test-code',
  })

describe('createAuthzRouter()', () => {
  it('DPoP required で DPoP ヘッダがない場合は invalid_request を返す', async () => {
    const response = await postToken('required')
    const body = await response.json()

    assert.equal(response.status, 400)
    assert.deepEqual(body, {
      error: 'invalid_request',
      error_description: 'DPoP proof JWT is required.',
    })
  })

  it('DPoP required で DPoP ヘッダが compact JWT でない場合は invalid_request を返す', async () => {
    const response = await postToken('required', { dpop: 'not-a-compact-jwt' })
    const body = await response.json()

    assert.equal(response.status, 400)
    assert.deepEqual(body, {
      error: 'invalid_request',
      error_description: 'DPoP header must contain a compact JWT.',
    })
  })

  it('DPoP optional でも malformed な DPoP ヘッダは invalid_request を返す', async () => {
    const response = await postToken('optional', { dpop: 'not-a-compact-jwt' })
    const body = await response.json()

    assert.equal(response.status, 400)
    assert.deepEqual(body, {
      error: 'invalid_request',
      error_description: 'DPoP header must contain a compact JWT.',
    })
  })

  it('重複した DPoP ヘッダ相当のカンマ結合値は invalid_request を返す', async () => {
    const response = await postToken('optional', { dpop: 'aaa.bbb.ccc, ddd.eee.fff' })
    const body = await response.json()

    assert.equal(response.status, 400)
    assert.deepEqual(body, {
      error: 'invalid_request',
      error_description: 'DPoP header must appear exactly once.',
    })
  })

  it('DPoP off では malformed な DPoP ヘッダを DPoP エラーとして扱わない', async () => {
    const response = await postToken('off', { dpop: 'not-a-compact-jwt' })
    const body = await response.json()

    assert.equal(response.status, 400)
    assert.deepEqual(body, {
      error: 'PRE_AUTHORIZED_CODE_NOT_FOUND',
      error_description: 'The provided pre-authorized code is invalid.',
    })
  })

  it('DPoP optional で DPoP proof に nonce がない場合は use_dpop_nonce を返す', async () => {
    const response = await postToken('optional', { dpop: await createDpopProof() })
    const body = await response.json()

    assert.equal(response.status, 400)
    assert.equal(response.headers.has('DPoP-Nonce'), true)
    assert.deepEqual(body, {
      error: 'use_dpop_nonce',
      error_description: 'Authorization server requires nonce in DPoP proof.',
    })
  })

  it('DPoP required で DPoP proof に nonce がない場合は use_dpop_nonce を返す', async () => {
    const response = await postToken('required', { dpop: await createDpopProof() })
    const body = await response.json()

    assert.equal(response.status, 400)
    assert.equal(response.headers.has('DPoP-Nonce'), true)
    assert.deepEqual(body, {
      error: 'use_dpop_nonce',
      error_description: 'Authorization server requires nonce in DPoP proof.',
    })
  })
})
