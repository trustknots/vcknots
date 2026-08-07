// Integration tests for kmsVerifierSignatureKeyStore against a real AWS account. These hit real
// KMS APIs (CreateKey, ImportKeyMaterial, Sign, ...) and are NOT part of the default `test`/`test:ci`
// task — run explicitly via `pnpm test:integration` with credentials for the target account, e.g.:
//
//   cd aws && AWS_PROFILE=vc-knots AWS_REGION=ap-northeast-1 pnpm test:integration
//
// Every key created here is scheduled for deletion (7-day pending window) in the top-level
// `after` hook once the whole file finishes.
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { after, describe, it } from 'node:test'
import { DescribeKeyCommand, KMSClient, ScheduleKeyDeletionCommand } from '@aws-sdk/client-kms'
import { VcknotsError } from '@trustknots/vcknots/errors'
import { VerifierClientId } from '@trustknots/vcknots/verifier'
import { calculateJwkThumbprint, exportJWK, type JWK, jwtVerify } from 'jose'
import { kmsVerifierSignatureKeyStore } from '../src/providers/kms-verifier-signature-key-store.provider'

const RUN_ID = Date.now().toString(36)
const verifierFor = (label: string) =>
  VerifierClientId(`https://integration-test.example.com/${label}-${RUN_ID}`)

const kms = new KMSClient({})
const store = kmsVerifierSignatureKeyStore()

const keyAlias = (verifier: string, alg: string) => {
  const md5 = createHash('md5').update(verifier).digest('base64url')
  return `alias/vcknots/verifiers/${md5}-${alg}`
}

const keyMaterialEquals = (a: JWK, b: JWK, alg: string) =>
  alg.startsWith('ES') ? a.x === b.x && a.y === b.y : a.n === b.n && a.e === b.e

const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')

const createdAliases: string[] = []
const trackCreatedKey = (verifier: string, alg: string) =>
  createdAliases.push(keyAlias(verifier, alg))

after(async () => {
  for (const alias of createdAliases) {
    try {
      const { KeyMetadata } = await kms.send(new DescribeKeyCommand({ KeyId: alias }))
      if (KeyMetadata?.KeyId) {
        await kms.send(
          new ScheduleKeyDeletionCommand({ KeyId: KeyMetadata.KeyId, PendingWindowInDays: 7 })
        )
      }
    } catch {
      // Nothing to clean up if the alias/key is already gone.
    }
  }
})

for (const alg of ['ES256', 'RS256']) {
  describe(`kmsVerifierSignatureKeyStore generate path (${alg})`, () => {
    const verifier = verifierFor(`generate-${alg}`)
    trackCreatedKey(verifier, alg)
    let firstJwk: JWK

    it('save() creates a usable key without throwing', async () => {
      await assert.doesNotReject(store.save(verifier, alg))
    })

    it('fetch() returns a public key with the expected kty', async () => {
      const publicKey = await store.fetch(verifier, alg)
      assert.ok(publicKey, 'fetch() should return a key after save()')
      firstJwk = await exportJWK(publicKey)
      assert.equal(firstJwk.kty, alg.startsWith('ES') ? 'EC' : 'RSA')
    })

    // Mirrors what the verifier flow actually signs: authzRequestJARKid builds the header from
    // the key store's public key thumbprint, then the flow concatenates the encoded header and
    // payload with the signature this store returns.
    it('sign() produces a JAR verifiable with the fetched public key', async () => {
      const publicKey = await store.fetch(verifier, alg)
      assert.ok(publicKey)
      const kid = await calculateJwkThumbprint(await exportJWK(publicKey))
      const jwtHeader = { alg, typ: 'oauth-authz-req+jwt', kid }
      const jwtPayload = {
        client_id: verifier,
        response_type: 'vp_token',
        nonce: `nonce-${RUN_ID}`,
        iat: Math.floor(Date.now() / 1000),
      }
      const signature = await store.sign(verifier, alg, jwtPayload, jwtHeader)
      assert.ok(signature)
      const jar = `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`
      const { payload } = await jwtVerify(jar, publicKey)
      assert.equal(payload.client_id, verifier)
    })

    it('save() is idempotent — a 2nd call reuses the existing key', async () => {
      await store.save(verifier, alg)
      const publicKey = await store.fetch(verifier, alg)
      assert.ok(publicKey)
      const secondJwk = await exportJWK(publicKey)
      assert.ok(
        keyMaterialEquals(firstJwk, secondJwk, alg),
        'public key material should be unchanged'
      )
    })
  })
}

describe('kmsVerifierSignatureKeyStore import path (ES256)', () => {
  const alg = 'ES256'
  const verifier = verifierFor(`import-${alg}`)
  trackCreatedKey(verifier, alg)

  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  let expectedJwk: JWK

  it('save() imports the provided key pair without throwing', async () => {
    expectedJwk = await exportJWK(publicKey)
    await assert.doesNotReject(
      store.save(verifier, alg, { format: 'pem', declaredAlg: alg, privateKey: privateKeyPem })
    )
  })

  it('fetch() returns a key matching the imported pair', async () => {
    const importedPublicKey = await store.fetch(verifier, alg)
    assert.ok(importedPublicKey)
    const importedJwk = await exportJWK(importedPublicKey)
    assert.ok(keyMaterialEquals(expectedJwk, importedJwk, alg))
  })
})

describe('kmsVerifierSignatureKeyStore import path (RS256, unsupported)', () => {
  it('save() rejects an RS256 key pair without creating a key', async () => {
    const alg = 'RS256'
    const verifier = verifierFor(`import-rejected-${alg}`)
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await assert.rejects(
      store.save(verifier, alg, { format: 'pem', declaredAlg: alg, privateKey: privateKeyPem }),
      (error: unknown) => error instanceof VcknotsError
    )
  })
})

describe('kmsVerifierSignatureKeyStore on a never-created verifier', () => {
  const alg = 'ES256'
  const verifier = verifierFor('never-created')

  it('fetch() returns null', async () => {
    const fetched = await store.fetch(verifier, alg)
    assert.equal(fetched, null)
  })

  it('sign() throws authz_verifier_key_not_found', async () => {
    await assert.rejects(
      store.sign(verifier, alg, { client_id: verifier }, { alg, typ: 'oauth-authz-req+jwt' }),
      (error: unknown) =>
        error instanceof VcknotsError && error.name === 'authz_verifier_key_not_found'
    )
  })
})
