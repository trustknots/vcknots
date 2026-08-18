// Integration tests for kmsAuthzSignatureKeyStore against a real AWS account. These hit real
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
import { AuthorizationServerIssuer } from '@trustknots/vcknots/authz'
import { VcknotsError } from '@trustknots/vcknots/errors'
import { calculateJwkThumbprint, exportJWK, type JWK, jwtVerify } from 'jose'
import { isKmsError } from '../src/providers/kms-provider.utils'
import { kmsAuthzSignatureKeyStore } from '../src/providers/kms-authz-signature-key-store.provider'
import { requireAwsSession } from './require-aws-session'

const RUN_ID = Date.now().toString(36)
const authzFor = (label: string) =>
  AuthorizationServerIssuer(`https://integration-test.example.com/${label}-${RUN_ID}`)

const kms = new KMSClient({})
const store = kmsAuthzSignatureKeyStore()

requireAwsSession()

const keyAlias = (authz: string, alg: string) => {
  const md5 = createHash('md5').update(authz).digest('base64url')
  return `alias/vcknots/authz/${md5}-${alg}`
}

const keyMaterialEquals = (a: JWK, b: JWK, alg: string) =>
  alg.startsWith('ES') ? a.x === b.x && a.y === b.y : a.n === b.n && a.e === b.e

const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')

const createdAliases: string[] = []
const trackCreatedKey = (authz: string, alg: string) => createdAliases.push(keyAlias(authz, alg))

after(async () => {
  for (const alias of createdAliases) {
    try {
      const { KeyMetadata } = await kms.send(new DescribeKeyCommand({ KeyId: alias }))
      if (KeyMetadata?.KeyId) {
        await kms.send(
          new ScheduleKeyDeletionCommand({ KeyId: KeyMetadata.KeyId, PendingWindowInDays: 7 })
        )
      }
    } catch (error) {
      // A missing alias/key is fine — it means there is nothing to clean up. Anything else (no
      // permission, throttling) leaves a real key behind in the account, so say so.
      if (!isKmsError(error, 'NotFoundException')) {
        console.warn(`Failed to schedule deletion for ${alias}: ${error}`)
      }
    }
  }
})

for (const alg of ['ES256', 'RS256']) {
  describe(`kmsAuthzSignatureKeyStore generate path (${alg})`, () => {
    const authz = authzFor(`generate-${alg}`)
    trackCreatedKey(authz, alg)
    let firstJwk: JWK

    it('save() creates a usable key without throwing', async () => {
      await assert.doesNotReject(store.save(authz, alg))
    })

    it('fetch() returns a public key with the expected kty', async () => {
      const publicKey = await store.fetch(authz, alg)
      assert.ok(publicKey, 'fetch() should return a key after save()')
      firstJwk = await exportJWK(publicKey)
      assert.equal(firstJwk.kty, alg.startsWith('ES') ? 'EC' : 'RSA')
    })

    // Mirrors what the authz flow actually signs: an access-token / response JWT with iss/sub
    // claims, verified against the public key this store returns.
    it('sign() produces a JWT verifiable with the fetched public key', async () => {
      const publicKey = await store.fetch(authz, alg)
      assert.ok(publicKey)
      const kid = await calculateJwkThumbprint(await exportJWK(publicKey))
      const jwtHeader = { alg, typ: 'at+jwt', kid }
      const jwtPayload = {
        iss: authz,
        sub: `client-${RUN_ID}`,
        iat: Math.floor(Date.now() / 1000),
      }
      const signature = await store.sign(authz, alg, jwtPayload, jwtHeader)
      assert.ok(signature)
      const jwt = `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`
      const { payload } = await jwtVerify(jwt, publicKey)
      assert.equal(payload.iss, authz)
    })

    it('save() is idempotent — a 2nd call reuses the existing key', async () => {
      await store.save(authz, alg)
      const publicKey = await store.fetch(authz, alg)
      assert.ok(publicKey)
      const secondJwk = await exportJWK(publicKey)
      assert.ok(
        keyMaterialEquals(firstJwk, secondJwk, alg),
        'public key material should be unchanged'
      )
    })
  })
}

describe('kmsAuthzSignatureKeyStore import path (ES256)', () => {
  const alg = 'ES256'
  const authz = authzFor(`import-${alg}`)
  trackCreatedKey(authz, alg)

  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  let expectedJwk: JWK

  it('save() imports the provided key pair without throwing', async () => {
    expectedJwk = await exportJWK(publicKey)
    await assert.doesNotReject(
      store.save(authz, alg, { format: 'pem', declaredAlg: alg, privateKey: privateKeyPem })
    )
  })

  it('fetch() returns a key matching the imported pair', async () => {
    const importedPublicKey = await store.fetch(authz, alg)
    assert.ok(importedPublicKey)
    const importedJwk = await exportJWK(importedPublicKey)
    assert.ok(keyMaterialEquals(expectedJwk, importedJwk, alg))
  })
})

describe('kmsAuthzSignatureKeyStore import path (RS256, unsupported)', () => {
  it('save() rejects an RS256 key pair without creating a key', async () => {
    const alg = 'RS256'
    const authz = authzFor(`import-rejected-${alg}`)
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await assert.rejects(
      store.save(authz, alg, { format: 'pem', declaredAlg: alg, privateKey: privateKeyPem }),
      (error: unknown) => error instanceof VcknotsError
    )
  })
})

describe('kmsAuthzSignatureKeyStore on a never-created authz server', () => {
  const alg = 'ES256'
  const authz = authzFor('never-created')

  it('fetch() returns null', async () => {
    const fetched = await store.fetch(authz, alg)
    assert.equal(fetched, null)
  })

  it('sign() throws authz_issuer_key_not_found', async () => {
    await assert.rejects(
      store.sign(authz, alg, { iss: authz }, { alg, typ: 'at+jwt' }),
      (error: unknown) => error instanceof VcknotsError && error.name === 'authz_issuer_key_not_found'
    )
  })
})
