import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { CompactSign, exportJWK, generateKeyPair } from 'jose'
import { decodeSdJwt } from '@sd-jwt/decode'
import { ES256, digest } from '@sd-jwt/crypto-nodejs'
import { buildSdJwtCredential, SD_JWT_VC_TYP } from '../../src/providers/issue-credential-sd-jwt.provider'

const { SDJwtInstance } = require('@sd-jwt/core')

describe('buildSdJwtCredential', () => {
  const issuer = 'https://issuer.example.com'
  const vct = 'IdentityCredential'
  const claims = {
    given_name: 'John',
    family_name: 'Doe',
  }

  // Builds an SD-JWT VC signed by a fresh issuer key, returning everything a test
  // needs to verify the round-trip.
  const issue = async () => {
    const issuerKeys = await generateKeyPair('ES256', { extractable: true })
    const issuerPublicJwk = await exportJWK(issuerKeys.publicKey)
    const holderKeys = await generateKeyPair('ES256', { extractable: true })
    const holderJwk = await exportJWK(holderKeys.publicKey)

    // Mirror IssuerSignatureKeyStoreProvider.sign: sign JSON(payload) under the
    // protected header and return only the signature component.
    const sign = async (payload: Record<string, unknown>, header: Record<string, unknown>) => {
      const jws = await new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
        .setProtectedHeader(header as Parameters<CompactSign['setProtectedHeader']>[0])
        .sign(issuerKeys.privateKey)
      return jws.split('.')[2]
    }

    const sdJwt = await buildSdJwtCredential({
      issuer,
      vct,
      alg: 'ES256',
      kid: 'issuer-key-1',
      holderJwk,
      claims,
      sign,
    })

    return { sdJwt, issuerPublicJwk, holderJwk }
  }

  it('emits combined issuance format terminated with ~', async () => {
    const { sdJwt } = await issue()
    assert.ok(sdJwt.endsWith('~'), 'SD-JWT must end with ~')
    // <jwt>~<disclosure>~<disclosure>~  => 3 parts before trailing empty segment.
    const parts = sdJwt.split('~')
    assert.equal(parts.at(-1), '')
    assert.equal(parts.length, 2 + Object.keys(claims).length)
  })

  it('keeps disclosable claim values out of the signed body', async () => {
    const { sdJwt } = await issue()
    const decoded = await decodeSdJwt(sdJwt, digest)

    assert.equal(decoded.jwt.header.typ, SD_JWT_VC_TYP)
    assert.equal(decoded.jwt.payload.vct, vct)
    assert.equal(decoded.jwt.payload.iss, issuer)
    assert.equal(decoded.jwt.payload._sd_alg, 'sha-256')
    assert.ok(Array.isArray(decoded.jwt.payload._sd))
    // The raw claim values must not appear in the signed JWT body.
    assert.equal(decoded.jwt.payload.given_name, undefined)
    assert.equal(decoded.jwt.payload.family_name, undefined)
  })

  it('binds the holder key via cnf.jwk', async () => {
    const { sdJwt, holderJwk } = await issue()
    const decoded = await decodeSdJwt(sdJwt, digest)
    const cnf = decoded.jwt.payload.cnf as { jwk: { x: string; y: string } }
    assert.ok(cnf?.jwk)
    assert.equal(cnf.jwk.x, holderJwk.x)
    assert.equal(cnf.jwk.y, holderJwk.y)
  })

  it('verifies against the issuer key and recovers disclosed claims', async () => {
    const { sdJwt, issuerPublicJwk } = await issue()

    const verifier = await ES256.getVerifier(issuerPublicJwk)
    const sdjwt = new SDJwtInstance({ verifier, hasher: digest })

    await assert.doesNotReject(() => sdjwt.validate(sdJwt))

    const { payload } = await sdjwt.verify(sdJwt)
    assert.equal(payload.given_name, 'John')
    assert.equal(payload.family_name, 'Doe')
    assert.equal(payload.vct, vct)
  })
})
