// Integration tests for kmsIssuerSignatureKeyStore against a real AWS account. These hit real
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
import { CredentialIssuer } from '@trustknots/vcknots/issuer'
import { exportJWK, type JWK, jwtVerify } from 'jose'
import { kmsIssuerSignatureKeyStore } from '../src/providers/kms-issuer-signature-key-store.provider'
import { requireAwsSession } from './require-aws-session'

const RUN_ID = Date.now().toString(36)
const issuerFor = (label: string) =>
  CredentialIssuer(`https://integration-test.example.com/${label}-${RUN_ID}`)

const kms = new KMSClient({})
const store = kmsIssuerSignatureKeyStore()

requireAwsSession()

const keyAlias = (issuer: string, alg: string) => {
  const md5 = createHash('md5').update(issuer).digest('base64url')
  return `alias/vcknots/issuers/${md5}-${alg}`
}

const keyMaterialEquals = (a: JWK, b: JWK, alg: string) =>
  alg.startsWith('ES') ? a.x === b.x && a.y === b.y : a.n === b.n && a.e === b.e

const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')

const createdAliases: string[] = []
const trackCreatedKey = (issuer: string, alg: string) => createdAliases.push(keyAlias(issuer, alg))

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
  describe(`kmsIssuerSignatureKeyStore generate path (${alg})`, () => {
    const issuer = issuerFor(`generate-${alg}`)
    trackCreatedKey(issuer, alg)
    let firstJwk: JWK

    it('save() creates a usable key without throwing', async () => {
      await assert.doesNotReject(store.save(issuer, alg))
    })

    it('fetch() returns a public key with the expected kty', async () => {
      const publicKey = await store.fetch(issuer, alg)
      assert.ok(publicKey, 'fetch() should return a key after save()')
      firstJwk = await exportJWK(publicKey)
      assert.equal(firstJwk.kty, alg.startsWith('ES') ? 'EC' : 'RSA')
    })

    it('sign() produces a JWT verifiable with the fetched public key', async () => {
      const publicKey = await store.fetch(issuer, alg)
      assert.ok(publicKey)
      const jwtHeader = { alg, typ: 'JWT' }
      const jwtPayload = {
        iss: issuer,
        sub: 'integration-test',
        iat: Math.floor(Date.now() / 1000),
      }
      const signature = await store.sign(issuer, alg, jwtPayload, jwtHeader)
      assert.ok(signature)
      const jwt = `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`
      const { payload } = await jwtVerify(jwt, publicKey)
      assert.equal(payload.sub, 'integration-test')
    })

    it('save() is idempotent — a 2nd call reuses the existing key', async () => {
      await store.save(issuer, alg)
      const publicKey = await store.fetch(issuer, alg)
      assert.ok(publicKey)
      const secondJwk = await exportJWK(publicKey)
      assert.ok(
        keyMaterialEquals(firstJwk, secondJwk, alg),
        'public key material should be unchanged'
      )
    })
  })
}

describe('kmsIssuerSignatureKeyStore import path (ES256)', () => {
  const alg = 'ES256'
  const issuer = issuerFor(`import-${alg}`)
  trackCreatedKey(issuer, alg)

  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  let expectedJwk: JWK

  it('save() imports the provided key pair without throwing', async () => {
    expectedJwk = await exportJWK(publicKey)
    await assert.doesNotReject(
      store.save(issuer, alg, { format: 'pem', declaredAlg: alg, privateKey: privateKeyPem })
    )
  })

  it('fetch() returns a key matching the imported pair', async () => {
    const importedPublicKey = await store.fetch(issuer, alg)
    assert.ok(importedPublicKey)
    const importedJwk = await exportJWK(importedPublicKey)
    assert.ok(keyMaterialEquals(expectedJwk, importedJwk, alg))
  })
})

describe('kmsIssuerSignatureKeyStore import path (RS256, unsupported)', () => {
  it('save() rejects an RS256 key pair without creating a key', async () => {
    const alg = 'RS256'
    const issuer = issuerFor(`import-rejected-${alg}`)
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await assert.rejects(
      store.save(issuer, alg, { format: 'pem', declaredAlg: alg, privateKey: privateKeyPem }),
      (error: unknown) => error instanceof VcknotsError
    )
  })
})

describe('kmsIssuerSignatureKeyStore on a never-created issuer', () => {
  const alg = 'ES256'
  const issuer = issuerFor('never-created')

  it('fetch() returns null', async () => {
    const fetched = await store.fetch(issuer, alg)
    assert.equal(fetched, null)
  })

  it('sign() throws authz_issuer_key_not_found', async () => {
    await assert.rejects(
      store.sign(issuer, alg, { iss: issuer }, { alg, typ: 'JWT' }),
      (error: unknown) =>
        error instanceof VcknotsError && error.name === 'authz_issuer_key_not_found'
    )
  })
})
