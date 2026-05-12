import assert from 'node:assert/strict'
import { describe, it, before } from 'node:test'
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from 'jose'
import { dpopProof } from '../../src/providers/dpop-proof.provider'

const htm = 'POST'
const htu = 'https://issuer.example.com/token'
const DPOP_PROOF_TYP = 'dpop+jwt'

describe('DPoPProofProvider', () => {
  let keys: { publicKey: CryptoKey; privateKey: CryptoKey }
  let publicJwk: JsonWebKey

  before(async () => {
    keys = await generateKeyPair('ES256')
    publicJwk = await exportJWK(keys.publicKey)
  })

  const createProof = async (
    payload?: Partial<JWTPayload>,
    header?: Record<string, unknown>,
    signKey = keys.privateKey
  ) =>
    await new SignJWT({
      htm,
      htu,
      jti: 'test-jti',
      ...payload,
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: DPOP_PROOF_TYP,
        jwk: publicJwk,
        ...header,
      })
      .setIssuedAt()
      .sign(signKey)

  const createUnverifiedProof = (
    header: Record<string, unknown>,
    payload: Record<string, unknown> = {
      htm,
      htu,
      jti: 'test-jti',
      iat: Math.floor(Date.now() / 1000),
    }
  ): string => {
    const encode = (value: Record<string, unknown>) =>
      Buffer.from(JSON.stringify(value)).toString('base64url')
    return `${encode(header)}.${encode(payload)}.signature`
  }

  it('should have correct properties', () => {
    const provider = dpopProof()

    assert.equal(provider.kind, 'dpop-proof-provider')
    assert.equal(provider.name, 'default-dpop-proof-provider')
    assert.equal(provider.single, true)
    assert.equal(provider.proofJtiTtlMs, 6 * 60 * 1000)
  })

  it('should derive proof JTI TTL from factory timing options', () => {
    const provider = dpopProof({
      maxTokenAgeSeconds: 24 * 60 * 60,
      clockToleranceSeconds: 120,
    })

    assert.equal(provider.proofJtiTtlMs, (24 * 60 * 60 + 120) * 1000)
  })

  it('should verify a valid DPoP proof JWT', async () => {
    const provider = dpopProof()
    const proof = await createProof({ jti: 'valid-jti' })

    const result = await provider.verifyProof(proof, { htm, htu })

    assert.equal(result.jti, 'valid-jti')
    assert.equal(typeof result.iat, 'number')
    assert.equal(typeof result.jwkThumbprint, 'string')
    assert.ok(result.jwkThumbprint.length > 0)
  })

  it('should use factory timing options when verifying iat', async () => {
    const provider = dpopProof({
      maxTokenAgeSeconds: 24 * 60 * 60,
      clockToleranceSeconds: 120,
    })
    const proof = await createProof({
      jti: 'custom-timing',
      iat: Math.floor(Date.now() / 1000) - 60 * 60,
    })

    await assert.doesNotReject(provider.verifyProof(proof, { htm, htu }))
  })

  it('should include nonce in verification result when present', async () => {
    const provider = dpopProof()
    const proof = await createProof({ jti: 'nonce-result', nonce: 'expected-nonce' })

    const result = await provider.verifyProof(proof, { htm, htu, nonce: 'expected-nonce' })

    assert.equal(result.nonce, 'expected-nonce')
  })

  it('should ignore query and fragment when comparing htu', async () => {
    const provider = dpopProof()
    const proof = await createProof({
      htu: 'https://issuer.example.com/token?foo=bar#fragment',
      jti: 'htu-query-fragment',
    })

    await assert.doesNotReject(provider.verifyProof(proof, { htm, htu }))
  })

  it('should reject when htu does not match', async () => {
    const provider = dpopProof()
    const proof = await createProof({ htu: 'https://issuer.example.com/other' })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT htu claim does not match the target URI.',
    })
  })

  it('should reject invalid absolute htu values', async () => {
    const provider = dpopProof()
    const proof = await createProof({ htu: 'not-an-absolute-uri' })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT htu claim must be a valid absolute URI.',
    })
  })

  it('should reject when typ is not dpop+jwt', async () => {
    const provider = dpopProof()
    const proof = await createProof({}, { typ: 'JWT' })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: `DPoP proof JWT typ must be "${DPOP_PROOF_TYP}".`,
    })
  })

  it('should reject HMAC alg values', async () => {
    const provider = dpopProof()
    const proof = createUnverifiedProof({
      alg: 'HS256',
      typ: DPOP_PROOF_TYP,
      jwk: publicJwk,
    })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT alg must be an asymmetric signature algorithm.',
    })
  })

  it('should reject jwk containing a private key', async () => {
    const provider = dpopProof()
    const proof = createUnverifiedProof({
      alg: 'ES256',
      typ: DPOP_PROOF_TYP,
      jwk: {
        ...publicJwk,
        d: 'private-key-material',
      },
    })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT header jwk must not contain a private key.',
    })
  })

  it('should reject signatures that do not match the header jwk', async () => {
    const provider = dpopProof()
    const otherKeys = await generateKeyPair('ES256')
    const proof = await createProof({}, undefined, otherKeys.privateKey)

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
    })
  })

  it('should reject empty alg values', async () => {
    const provider = dpopProof()
    const proof = createUnverifiedProof({
      alg: '',
      typ: DPOP_PROOF_TYP,
      jwk: publicJwk,
    })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT alg must be an asymmetric signature algorithm.',
    })
  })

  it('should reject alg none', async () => {
    const provider = dpopProof()
    const proof = createUnverifiedProof({
      alg: 'none',
      typ: DPOP_PROOF_TYP,
      jwk: publicJwk,
    })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT alg must be an asymmetric signature algorithm.',
    })
  })

  it('should reject missing jwk', async () => {
    const provider = dpopProof()
    const proof = createUnverifiedProof({
      alg: 'ES256',
      typ: DPOP_PROOF_TYP,
    })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT header must contain a public JWK.',
    })
  })

  it('should reject jwk values that cannot be imported', async () => {
    const provider = dpopProof()
    const proof = createUnverifiedProof({
      alg: 'ES256',
      typ: DPOP_PROOF_TYP,
      jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'invalid',
        y: 'invalid',
      },
    })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
    })
  })

  it('should reject missing jti', async () => {
    const provider = dpopProof()
    const proof = await createProof({ jti: undefined })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT jti claim is required.',
    })
  })

  it('should reject missing iat', async () => {
    const provider = dpopProof()
    const proof = await new SignJWT({
      htm,
      htu,
      jti: 'missing-iat',
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: DPOP_PROOF_TYP,
        jwk: publicJwk,
      })
      .sign(keys.privateKey)

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT verification failed: missing required "iat" claim',
    })
  })

  it('should reject htm mismatches', async () => {
    const provider = dpopProof()
    const proof = await createProof({ htm: 'GET' })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT htm claim does not match the HTTP method.',
    })
  })

  it('should reject missing htu', async () => {
    const provider = dpopProof()
    const proof = await createProof({ htu: undefined })

    await assert.rejects(provider.verifyProof(proof, { htm, htu }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT htu claim is required.',
    })
  })

  it('should reject nonce mismatches when nonce is expected', async () => {
    const provider = dpopProof()
    const proof = await createProof({ nonce: 'actual-nonce' })

    await assert.rejects(provider.verifyProof(proof, { htm, htu, nonce: 'expected-nonce' }), {
      name: 'INVALID_DPOP_PROOF',
      message: 'DPoP proof JWT nonce claim does not match the expected nonce.',
    })
  })
})
