import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { crc32c } from '@node-rs/crc32'
import { calculateJwkThumbprint, exportJWK } from 'jose'
import { VerifierClientId } from '@trustknots/vcknots'
import { raise } from '@trustknots/vcknots/errors'
import { kmsVerifierEncryptionKeyStore } from '../../src/providers/kms-verifier-encryption-key-store.provider'

const projectId = 'test-project'
const locationId = 'global'
const keyRingId = 'verifiers'
const verifier = VerifierClientId('https://example.com/verifier')

const md5 = (value: string) => createHash('md5').update(value).digest('base64url')
const verifierKeyId = (alg: string) => `${md5(verifier)}-enc-${alg}`

type FakePublicKey = {
  name: string
  pem?: string | null
  pemCrc32c?: {
    value?: string | null
  } | null
  algorithm: string
}

const grpcError = (message: string, code: number) => {
  const error = new Error(message) as Error & { code: number }
  error.code = code
  return error
}

class FakeKmsClient {
  keyRings = new Set<string>()
  cryptoKeys = new Set<string>()
  publicKeys = new Map<string, FakePublicKey>()
  versions = new Map<string, { name: string }[]>()
  calls = {
    createKeyRing: [] as Array<Record<string, unknown>>,
    createCryptoKey: [] as Array<Record<string, unknown>>,
  }
  errors = {
    getKeyRing: new Map<string, Error & { code?: number }>(),
    createKeyRing: null as (Error & { code?: number }) | null,
    getCryptoKey: new Map<string, Error & { code?: number }>(),
    createCryptoKey: null as (Error & { code?: number }) | null,
    listCryptoKeyVersions: new Map<string, Error & { code?: number }>(),
  }

  constructor() {
    this.keyRings.add(this.keyRingPath(projectId, locationId, keyRingId))
  }

  keyRingPath(project: string, location: string, keyRing: string) {
    return `projects/${project}/locations/${location}/keyRings/${keyRing}`
  }

  locationPath(project: string, location: string) {
    return `projects/${project}/locations/${location}`
  }

  cryptoKeyPath(project: string, location: string, keyRing: string, key: string) {
    return `${this.keyRingPath(project, location, keyRing)}/cryptoKeys/${key}`
  }

  async getKeyRing({ name }: { name: string }) {
    const error = this.errors.getKeyRing.get(name)
    if (error) {
      throw error
    }
    if (!this.keyRings.has(name)) {
      throw grpcError('not found', 5)
    }
    return [{ name }]
  }

  async createKeyRing(request: Record<string, unknown>) {
    this.calls.createKeyRing.push(request)
    if (this.errors.createKeyRing) {
      throw this.errors.createKeyRing
    }
    const name = this.keyRingPath(projectId, locationId, String(request.keyRingId))
    this.keyRings.add(name)
    return [{ name }]
  }

  async getCryptoKey({ name }: { name: string }) {
    const error = this.errors.getCryptoKey.get(name)
    if (error) {
      throw error
    }
    if (!this.cryptoKeys.has(name)) {
      throw grpcError('not found', 5)
    }
    return [{ name }]
  }

  async createCryptoKey(request: Record<string, unknown>) {
    this.calls.createCryptoKey.push(request)
    if (this.errors.createCryptoKey) {
      throw this.errors.createCryptoKey
    }
    const name = `${String(request.parent)}/cryptoKeys/${String(request.cryptoKeyId)}`
    this.cryptoKeys.add(name)
    return [{ name }]
  }

  async listCryptoKeyVersions({ parent }: { parent: string }) {
    const error = this.errors.listCryptoKeyVersions.get(parent)
    if (error) {
      throw error
    }
    const versions = this.versions.get(parent)
    if (!versions) {
      throw grpcError('not found', 5)
    }
    return [versions]
  }

  async getPublicKey({ name }: { name: string }) {
    const publicKey = this.publicKeys.get(name)
    if (!publicKey) {
      throw raise('INTERNAL_SERVER_ERROR', { message: 'not found' })
    }
    return [publicKey]
  }

  addEnabledVersion(cryptoKeyName: string, versionId: string, publicKey: Omit<FakePublicKey, 'name'>) {
    const versionName = `${cryptoKeyName}/cryptoKeyVersions/${versionId}`
    this.versions.set(cryptoKeyName, [
      ...(this.versions.get(cryptoKeyName) ?? []),
      { name: versionName },
    ])
    this.publicKeys.set(versionName, { ...publicKey, name: versionName })
    return versionName
  }
}

describe('kmsVerifierEncryptionKeyStore', () => {
  const originalConsoleError = console.error

  afterEach(() => {
    console.error = originalConsoleError
  })

  it('should have correct provider metadata', () => {
    const provider = kmsVerifierEncryptionKeyStore({
      client: new FakeKmsClient() as never,
      projectId,
      locationId,
    })

    assert.equal(provider.kind, 'verifier-encryption-key-store-provider')
    assert.equal(provider.name, 'kms-verifier-encryption-key-store-provider')
    assert.equal(provider.single, true)
  })

  it('should create a KMS-managed encryption key', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })

    await provider.save(verifier, 'RSA-OAEP-256')

    assert.equal(kms.calls.createKeyRing.length, 0)
    assert.equal(kms.calls.createCryptoKey.length, 1)
    assert.deepEqual(kms.calls.createCryptoKey[0], {
      parent: kms.keyRingPath(projectId, locationId, keyRingId),
      cryptoKeyId: verifierKeyId('RSA-OAEP-256'),
      skipInitialVersionCreation: false,
      cryptoKey: {
        purpose: 'ASYMMETRIC_DECRYPT',
        importOnly: false,
        versionTemplate: {
          algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256',
        },
        destroyScheduledDuration: { seconds: 60 * 60 * 24 },
      },
    })
  })

  it('should treat ALREADY_EXISTS from createKeyRing as success', async () => {
    const kms = new FakeKmsClient()
    kms.keyRings.clear()
    kms.errors.createKeyRing = grpcError('already exists', 6)
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })

    await provider.save(verifier, 'RSA-OAEP-256')

    assert.equal(kms.calls.createKeyRing.length, 1)
    assert.equal(kms.calls.createCryptoKey.length, 1)
  })

  it('should rethrow non-NOT_FOUND errors from getKeyRing', async () => {
    const kms = new FakeKmsClient()
    const keyRingName = kms.keyRingPath(projectId, locationId, keyRingId)
    kms.errors.getKeyRing.set(keyRingName, grpcError('permission denied', 7))
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })

    await assert.rejects(provider.save(verifier, 'RSA-OAEP-256'), /permission denied/)
  })

  it('should fail save for unsupported algorithms', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })

    await assert.rejects(provider.save(verifier, 'unsupported'), (error: Error) => {
      assert.equal(error.name, 'INTERNAL_SERVER_ERROR')
      assert.match(error.message, /Unsupported verifier encryption key algorithm/)
      return true
    })

    assert.equal(kms.calls.createCryptoKey.length, 0)
  })

  it('should fetch the latest enabled public key when KMS data is valid', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('RSA-OAEP-256')
    )
    kms.addEnabledVersion(cryptoKeyName, '1', {
      pem: publicKeyPem,
      pemCrc32c: { value: String(crc32c(publicKeyPem)) },
      algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256',
    })
    kms.addEnabledVersion(cryptoKeyName, '2', {
      pem: publicKeyPem,
      pemCrc32c: { value: String(crc32c(publicKeyPem)) },
      algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256',
    })

    const key = await provider.fetch(verifier, 'RSA-OAEP-256')
    const expectedJwk = await exportJWK(publicKey)
    const expectedKid = await calculateJwkThumbprint(expectedJwk)

    assert.deepEqual(key, {
      ...expectedJwk,
      alg: 'RSA-OAEP-256',
      kid: expectedKid,
      use: 'enc',
    })
  })

  it('should fetch the numerically latest enabled public key version', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey: oldPublicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const { publicKey: newPublicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const oldPublicKeyPem = oldPublicKey.export({ format: 'pem', type: 'spki' }).toString()
    const newPublicKeyPem = newPublicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('RSA-OAEP-256')
    )
    kms.addEnabledVersion(cryptoKeyName, '2', {
      pem: oldPublicKeyPem,
      pemCrc32c: { value: String(crc32c(oldPublicKeyPem)) },
      algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256',
    })
    kms.addEnabledVersion(cryptoKeyName, '10', {
      pem: newPublicKeyPem,
      pemCrc32c: { value: String(crc32c(newPublicKeyPem)) },
      algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256',
    })

    const key = await provider.fetch(verifier, 'RSA-OAEP-256')
    const expectedJwk = await exportJWK(newPublicKey)
    const expectedKid = await calculateJwkThumbprint(expectedJwk)

    assert.deepEqual(key, {
      ...expectedJwk,
      alg: 'RSA-OAEP-256',
      kid: expectedKid,
      use: 'enc',
    })
  })

  it('should return null when key does not exist', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })

    const key = await provider.fetch(verifier, 'RSA-OAEP-256')

    assert.equal(key, null)
  })

  it('should rethrow non-NOT_FOUND errors from fetch version lookup', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('RSA-OAEP-256')
    )
    kms.errors.listCryptoKeyVersions.set(cryptoKeyName, grpcError('permission denied', 7))

    await assert.rejects(provider.fetch(verifier, 'RSA-OAEP-256'), /permission denied/)
  })

  it('should return null when no enabled version is available', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('RSA-OAEP-256')
    )
    kms.versions.set(cryptoKeyName, [])

    const key = await provider.fetch(verifier, 'RSA-OAEP-256')

    assert.equal(key, null)
  })

  it('should return null when fetched public key data is incomplete', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('RSA-OAEP-256')
    )
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    kms.addEnabledVersion(cryptoKeyName, '1', {
      pem: null,
      pemCrc32c: { value: null },
      algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256',
    })

    const key = await provider.fetch(verifier, 'RSA-OAEP-256')

    assert.equal(key, null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Public key data is incomplete/)
  })

  it('should return null when fetched public key name does not match requested version', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('RSA-OAEP-256')
    )
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    const versionName = kms.addEnabledVersion(cryptoKeyName, '1', {
      pem: publicKeyPem,
      pemCrc32c: { value: String(crc32c(publicKeyPem)) },
      algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256',
    })
    kms.publicKeys.set(versionName, {
      name: `${versionName}-unexpected`,
      pem: publicKeyPem,
      pemCrc32c: { value: String(crc32c(publicKeyPem)) },
      algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256',
    })

    const key = await provider.fetch(verifier, 'RSA-OAEP-256')

    assert.equal(key, null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Public key name mismatch/)
  })

  it('should return null when fetched public key CRC32C does not match', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('RSA-OAEP-256')
    )
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    kms.addEnabledVersion(cryptoKeyName, '1', {
      pem: publicKeyPem,
      pemCrc32c: { value: '0' },
      algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256',
    })

    const key = await provider.fetch(verifier, 'RSA-OAEP-256')

    assert.equal(key, null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Public key integrity check failed/)
  })

  it('should return null when fetched public key algorithm does not match requested algorithm', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierEncryptionKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072 })
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('RSA-OAEP-256')
    )
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    kms.addEnabledVersion(cryptoKeyName, '1', {
      pem: publicKeyPem,
      pemCrc32c: { value: String(crc32c(publicKeyPem)) },
      algorithm: 'EC_SIGN_P256_SHA256',
    })

    const key = await provider.fetch(verifier, 'RSA-OAEP-256')

    assert.equal(key, null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Unsupported KMS key algorithm/)
  })
})
