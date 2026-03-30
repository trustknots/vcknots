import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { crc32c } from '@node-rs/crc32'
import { derToJose } from 'ecdsa-sig-formatter'
import { exportJWK } from 'jose'
import { AuthorizationServerIssuer } from '@trustknots/vcknots/authz'
import { raise } from '@trustknots/vcknots/errors'
import { kmsAuthzSignatureKeyStore } from '../../src/providers/kms-authz-signature-key-store.provider'

const projectId = 'test-project'
const locationId = 'global'
const keyRingId = 'authServers'
const baseImportJobId = 'vcknots-authz-import-job'
const authz = AuthorizationServerIssuer('https://example.com/authz')

const md5 = (value: string) => createHash('md5').update(value).digest('base64url')
const authzKeyId = (alg: string) => `${md5(authz)}-${alg}`

type FakeImportJob = {
  name: string
  state: string
  publicKey?: {
    pem: string
  }
}

type FakePublicKey = {
  name: string
  pem: string
  pemCrc32c: {
    value: string
  }
  algorithm: string
}

const grpcError = (message: string, code: number) => {
  const error = new Error(message) as Error & { code: number }
  error.code = code
  return error
}

const createDeferred = () => {
  let resolve!: () => void
  const promise = new Promise<void>((res) => {
    resolve = res
  })
  return { promise, resolve }
}

class FakeKmsClient {
  keyRings = new Set<string>()
  cryptoKeys = new Set<string>()
  importJobs = new Map<string, FakeImportJob>()
  publicKeys = new Map<string, FakePublicKey>()
  versions = new Map<string, { name: string }[]>()
  asymmetricSignResponse: {
    name: string
    verifiedDigestCrc32c: boolean
    signature: Buffer
    signatureCrc32c: { value: string }
  } | null = null
  calls = {
    createKeyRing: [] as Array<Record<string, unknown>>,
    createImportJob: [] as Array<Record<string, unknown>>,
    createCryptoKey: [] as Array<Record<string, unknown>>,
    importCryptoKeyVersion: [] as Array<Record<string, unknown>>,
    asymmetricSign: [] as Array<Record<string, unknown>>,
  }
  errors = {
    getKeyRing: new Map<string, Error & { code?: number }>(),
    createKeyRing: null as (Error & { code?: number }) | null,
    createImportJob: new Map<string, Error & { code?: number }>(),
    getImportJob: new Map<string, Error & { code?: number }>(),
    getCryptoKey: new Map<string, Error & { code?: number }>(),
    createCryptoKey: null as (Error & { code?: number }) | null,
    listCryptoKeyVersions: new Map<string, Error & { code?: number }>(),
    asymmetricSign: new Map<string, Error & { code?: number }>(),
  }
  getImportJobResponses = new Map<string, FakeImportJob[]>()
  createImportJobBarrier: Promise<void> | null = null

  wrappingKeyPair = generateKeyPairSync('rsa', { modulusLength: 3072 })

  constructor() {
    this.keyRings.add(this.keyRingPath(projectId, locationId, keyRingId))
    const importJobName = this.importJobPath(projectId, locationId, keyRingId, baseImportJobId)
    this.importJobs.set(importJobName, {
      name: importJobName,
      state: 'ACTIVE',
      publicKey: {
        pem: this.wrappingKeyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      },
    })
  }

  keyRingPath(project: string, location: string, keyRing: string) {
    return `projects/${project}/locations/${location}/keyRings/${keyRing}`
  }

  locationPath(project: string, location: string) {
    return `projects/${project}/locations/${location}`
  }

  importJobPath(project: string, location: string, keyRing: string, importJob: string) {
    return `${this.keyRingPath(project, location, keyRing)}/importJobs/${importJob}`
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

  async getImportJob({ name }: { name: string }) {
    const error = this.errors.getImportJob.get(name)
    if (error) {
      throw error
    }
    const responses = this.getImportJobResponses.get(name)
    if (responses && responses.length > 0) {
      const next = responses.shift()
      if (!next) {
        throw new Error(`Missing queued import job response for ${name}`)
      }
      if (responses.length === 0) {
        this.getImportJobResponses.delete(name)
      }
      this.importJobs.set(name, next)
      return [next]
    }
    const job = this.importJobs.get(name)
    if (!job) {
      throw grpcError('not found', 5)
    }
    return [job]
  }

  async createImportJob(request: Record<string, unknown>) {
    this.calls.createImportJob.push(request)
    const importJobId = String(request.importJobId)
    const error = this.errors.createImportJob.get(importJobId)
    if (error) {
      throw error
    }
    if (this.createImportJobBarrier) {
      await this.createImportJobBarrier
    }
    const importJobName = `${String(request.parent)}/importJobs/${String(request.importJobId)}`
    const job = {
      name: importJobName,
      state: 'ACTIVE',
      publicKey: {
        pem: this.wrappingKeyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      },
    }
    this.importJobs.set(importJobName, job)
    return [job]
  }

  async listImportJobs({ parent }: { parent: string }) {
    return [
      [...this.importJobs.values()].filter((job) =>
        String(job.name).startsWith(`${String(parent)}/importJobs/`)
      ),
    ]
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
    if (this.errors.createCryptoKey) {
      throw this.errors.createCryptoKey
    }
    this.calls.createCryptoKey.push(request)
    const name = `${String(request.parent)}/cryptoKeys/${String(request.cryptoKeyId)}`
    this.cryptoKeys.add(name)
    return [{ name }]
  }

  async importCryptoKeyVersion(request: Record<string, unknown>) {
    this.calls.importCryptoKeyVersion.push(request)
    return [{}]
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

  async asymmetricSign(request: Record<string, unknown>) {
    this.calls.asymmetricSign.push(request)
    const error = this.errors.asymmetricSign.get(String(request.name))
    if (error) {
      throw error
    }
    if (!this.asymmetricSignResponse) {
      throw raise('INTERNAL_SERVER_ERROR', { message: 'missing response' })
    }
    return [this.asymmetricSignResponse]
  }

  addEnabledVersion(cryptoKeyName: string, versionId: string, publicKey: FakePublicKey) {
    const versionName = `${cryptoKeyName}/cryptoKeyVersions/${versionId}`
    this.versions.set(cryptoKeyName, [
      ...(this.versions.get(cryptoKeyName) ?? []),
      { name: versionName },
    ])
    this.publicKeys.set(versionName, { ...publicKey, name: versionName })
    return versionName
  }
}

describe('kmsAuthzSignatureKeyStore', () => {
  const originalConsoleError = console.error

  afterEach(() => {
    console.error = originalConsoleError
  })

  it('should have correct provider metadata', () => {
    const provider = kmsAuthzSignatureKeyStore({
      client: new FakeKmsClient() as never,
      projectId,
      locationId,
    })

    assert.equal(provider.kind, 'authz-signature-key-store-provider')
    assert.equal(provider.name, 'kms-authz-signature-key-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save an ES256 authorization server key by importing it into KMS', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await provider.save(authz, 'ES256', {
      format: 'pem',
      declaredAlg: 'ES256',
      privateKey: privateKeyPem,
    })

    assert.equal(kms.calls.createKeyRing.length, 0)
    assert.equal(kms.calls.createCryptoKey.length, 1)
    assert.equal(kms.calls.importCryptoKeyVersion.length, 1)
    assert.deepEqual(kms.calls.createCryptoKey[0], {
      parent: kms.keyRingPath(projectId, locationId, keyRingId),
      cryptoKeyId: authzKeyId('ES256'),
      skipInitialVersionCreation: true,
      cryptoKey: {
        purpose: 'ASYMMETRIC_SIGN',
        importOnly: true,
        versionTemplate: {
          algorithm: 'EC_SIGN_P256_SHA256',
        },
        destroyScheduledDuration: { seconds: 60 * 60 * 24 },
      },
    })

    const importRequest = kms.calls.importCryptoKeyVersion[0]
    assert.equal(
      importRequest.parent,
      kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    )
    assert.equal(importRequest.algorithm, 'EC_SIGN_P256_SHA256')
    assert.equal(
      importRequest.importJob,
      kms.importJobPath(projectId, locationId, keyRingId, baseImportJobId)
    )
    assert.ok(importRequest.wrappedKey instanceof Buffer)
    assert.ok((importRequest.wrappedKey as Buffer).length > 0)
  })

  it('should treat ALREADY_EXISTS from createKeyRing as success', async () => {
    const kms = new FakeKmsClient()
    kms.keyRings.clear()
    kms.errors.createKeyRing = grpcError('already exists', 6)
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await provider.save(authz, 'ES256', {
      format: 'pem',
      declaredAlg: 'ES256',
      privateKey: privateKeyPem,
    })

    assert.equal(kms.calls.createKeyRing.length, 1)
    assert.equal(kms.calls.createCryptoKey.length, 1)
  })

  it('should rethrow non-NOT_FOUND errors from getKeyRing', async () => {
    const kms = new FakeKmsClient()
    const keyRingName = kms.keyRingPath(projectId, locationId, keyRingId)
    kms.errors.getKeyRing.set(keyRingName, grpcError('permission denied', 7))
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await assert.rejects(
      provider.save(authz, 'ES256', {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      }),
      /permission denied/
    )
  })

  it('should reuse the canonical import job across saves', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await provider.save(authz, 'ES256', {
      format: 'pem',
      declaredAlg: 'ES256',
      privateKey: privateKeyPem,
    })
    await provider.save(authz, 'ES256', {
      format: 'pem',
      declaredAlg: 'ES256',
      privateKey: privateKeyPem,
    })

    assert.equal(kms.calls.createImportJob.length, 0)
  })

  it('should create the canonical import job when no related job exists', async () => {
    const kms = new FakeKmsClient()
    kms.importJobs.clear()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await provider.save(authz, 'ES256', {
      format: 'pem',
      declaredAlg: 'ES256',
      privateKey: privateKeyPem,
    })
    await provider.save(authz, 'ES256', {
      format: 'pem',
      declaredAlg: 'ES256',
      privateKey: privateKeyPem,
    })

    assert.equal(kms.calls.createImportJob.length, 1)
    assert.equal(kms.calls.createImportJob[0].importJobId, baseImportJobId)
  })

  it('should reuse an active replacement import job when canonical is expired', async () => {
    const kms = new FakeKmsClient()
    const canonicalImportJobName = kms.importJobPath(
      projectId,
      locationId,
      keyRingId,
      baseImportJobId
    )
    kms.importJobs.set(canonicalImportJobName, {
      name: canonicalImportJobName,
      state: 'EXPIRED',
      publicKey: {
        pem: kms.wrappingKeyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      },
    })
    const replacementImportJobName = kms.importJobPath(
      projectId,
      locationId,
      keyRingId,
      `${baseImportJobId}-12345`
    )
    kms.importJobs.set(replacementImportJobName, {
      name: replacementImportJobName,
      state: 'ACTIVE',
      publicKey: {
        pem: kms.wrappingKeyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      },
    })
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await provider.save(authz, 'ES256', {
      format: 'pem',
      declaredAlg: 'ES256',
      privateKey: privateKeyPem,
    })

    assert.equal(kms.calls.createImportJob.length, 0)
  })

  it('should share in-flight replacement import job creation across concurrent saves', async () => {
    const kms = new FakeKmsClient()
    kms.importJobs.clear()
    kms.errors.createImportJob.set(baseImportJobId, grpcError('already exists', 6))
    const createImportJobDeferred = createDeferred()
    kms.createImportJobBarrier = createImportJobDeferred.promise
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
    const originalDateNow = Date.now
    let now = 1000
    Date.now = () => now++

    try {
      const save1 = provider.save(authz, 'ES256', {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      })
      const save2 = provider.save(authz, 'ES256', {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      })

      while (
        !kms.calls.createImportJob.some((call) =>
          String(call.importJobId).startsWith(`${baseImportJobId}-`)
        )
      ) {
        await new Promise((resolve) => setTimeout(resolve, 0))
      }

      await new Promise((resolve) => setTimeout(resolve, 0))
      createImportJobDeferred.resolve()
      await Promise.all([save1, save2])
    } finally {
      Date.now = originalDateNow
    }

    const replacementCreateCalls = kms.calls.createImportJob.filter((call) =>
      String(call.importJobId).startsWith(`${baseImportJobId}-`)
    )
    assert.equal(replacementCreateCalls.length, 1)
  })

  it('should fail save for unsupported algorithms', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })

    await assert.rejects(
      provider.save(authz, 'unsupported', {
        format: 'jwk',
        declaredAlg: 'unsupported',
        privateKey: { kty: 'EC' },
      }),
      (error: Error) => {
        assert.equal(error.name, 'INTERNAL_SERVER_ERROR')
        assert.match(error.message, /Unsupported authorization server key algorithm/)
        return true
      }
    )

    assert.equal(kms.calls.importCryptoKeyVersion.length, 0)
  })

  it('should reject save when pair algorithm does not match keyAlg', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await assert.rejects(
      provider.save(authz, 'ES384', {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      }),
      (error: Error) => {
        assert.equal(error.name, 'ILLEGAL_ARGUMENT')
        assert.match(error.message, /does not match the requested key algorithm/)
        return true
      }
    )

    assert.equal(kms.calls.createCryptoKey.length, 0)
    assert.equal(kms.calls.importCryptoKeyVersion.length, 0)
  })

  it('should create a KMS-managed key when pair is not provided', async () => {
    const kms = new FakeKmsClient()
    kms.importJobs.clear()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })

    await provider.save(authz, 'ES256')

    assert.equal(kms.calls.createImportJob.length, 0)
    assert.equal(kms.calls.importCryptoKeyVersion.length, 0)
    assert.equal(kms.calls.createCryptoKey.length, 1)
    assert.deepEqual(kms.calls.createCryptoKey[0], {
      parent: kms.keyRingPath(projectId, locationId, keyRingId),
      cryptoKeyId: authzKeyId('ES256'),
      skipInitialVersionCreation: false,
      cryptoKey: {
        purpose: 'ASYMMETRIC_SIGN',
        importOnly: false,
        versionTemplate: {
          algorithm: 'EC_SIGN_P256_SHA256',
        },
        destroyScheduledDuration: { seconds: 60 * 60 * 24 },
      },
    })
  })

  it('should fetch the latest enabled public key when KMS data is valid', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    kms.addEnabledVersion(cryptoKeyName, '1', {
      name: '',
      pem: publicKeyPem,
      pemCrc32c: { value: String(crc32c(publicKeyPem)) },
      algorithm: 'EC_SIGN_P256_SHA256',
    })
    kms.addEnabledVersion(cryptoKeyName, '2', {
      name: '',
      pem: publicKeyPem,
      pemCrc32c: { value: String(crc32c(publicKeyPem)) },
      algorithm: 'EC_SIGN_P256_SHA256',
    })

    const key = await provider.fetch(authz, 'ES256')

    assert.ok(key)
    assert.deepEqual(await exportJWK(key), await exportJWK(publicKey))
  })

  it('should fetch the numerically latest enabled public key version', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey: oldPublicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const { publicKey: newPublicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const oldPublicKeyPem = oldPublicKey.export({ format: 'pem', type: 'spki' }).toString()
    const newPublicKeyPem = newPublicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    kms.addEnabledVersion(cryptoKeyName, '2', {
      name: '',
      pem: oldPublicKeyPem,
      pemCrc32c: { value: String(crc32c(oldPublicKeyPem)) },
      algorithm: 'EC_SIGN_P256_SHA256',
    })
    kms.addEnabledVersion(cryptoKeyName, '10', {
      name: '',
      pem: newPublicKeyPem,
      pemCrc32c: { value: String(crc32c(newPublicKeyPem)) },
      algorithm: 'EC_SIGN_P256_SHA256',
    })

    const key = await provider.fetch(authz, 'ES256')

    assert.ok(key)
    assert.deepEqual(await exportJWK(key), await exportJWK(newPublicKey))
  })

  it('should return null when fetched public key CRC32C does not match', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    kms.addEnabledVersion(cryptoKeyName, '1', {
      name: '',
      pem: publicKeyPem,
      pemCrc32c: { value: '0' },
      algorithm: 'EC_SIGN_P256_SHA256',
    })

    const key = await provider.fetch(authz, 'ES256')

    assert.equal(key, null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Public key integrity check failed/)
  })

  it('should rethrow non-NOT_FOUND errors from fetch version lookup', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    kms.errors.listCryptoKeyVersions.set(cryptoKeyName, grpcError('permission denied', 7))

    await assert.rejects(provider.fetch(authz, 'ES256'), /permission denied/)
  })

  it('should return null when fetched public key name does not match requested version', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    const errors: unknown[][] = []
    console.error = (...args: unknown[]) => {
      errors.push(args)
    }
    const versionName = kms.addEnabledVersion(cryptoKeyName, '1', {
      name: '',
      pem: publicKeyPem,
      pemCrc32c: { value: String(crc32c(publicKeyPem)) },
      algorithm: 'EC_SIGN_P256_SHA256',
    })
    kms.publicKeys.set(versionName, {
      name: `${versionName}-unexpected`,
      pem: publicKeyPem,
      pemCrc32c: { value: String(crc32c(publicKeyPem)) },
      algorithm: 'EC_SIGN_P256_SHA256',
    })

    const key = await provider.fetch(authz, 'ES256')

    assert.equal(key, null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Public key name mismatch/)
  })

  it('should sign with the latest enabled ES256 key version', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    kms.addEnabledVersion(cryptoKeyName, '1', {
      name: '',
      pem: 'unused',
      pemCrc32c: { value: '0' },
      algorithm: 'EC_SIGN_P256_SHA256',
    })
    const latestVersionName = kms.addEnabledVersion(cryptoKeyName, '2', {
      name: '',
      pem: 'unused',
      pemCrc32c: { value: '0' },
      algorithm: 'EC_SIGN_P256_SHA256',
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const derSignature = createHash('sha256').update('fixture').digest()
    const signature = cryptoSign('sha256', derSignature, {
      key: privateKey,
      dsaEncoding: 'der',
    })
    kms.asymmetricSignResponse = {
      name: latestVersionName,
      verifiedDigestCrc32c: true,
      signature,
      signatureCrc32c: { value: String(crc32c(signature)) },
    }
    const jwtHeader = { alg: 'ES256', typ: 'JWT' }
    const jwtPayload = { iss: authz, aud: 'wallet', nonce: 'nonce-123' }

    const result = await provider.sign(authz, 'ES256', jwtPayload, jwtHeader)

    const encodedHeader = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')
    const encodedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url')
    const expectedDigest = createHash('sha256')
      .update(Buffer.from(`${encodedHeader}.${encodedPayload}`))
      .digest()
    assert.equal(result, derToJose(signature.toString('base64'), 'ES256'))
    assert.equal(kms.calls.asymmetricSign.length, 1)
    assert.equal(kms.calls.asymmetricSign[0].name, latestVersionName)
    assert.deepEqual(kms.calls.asymmetricSign[0].digest, { sha256: expectedDigest })
    assert.deepEqual(kms.calls.asymmetricSign[0].digestCrc32c, {
      value: BigInt(crc32c(expectedDigest)).toString(),
    })
  })

  it('should sign with the numerically latest enabled ES256 key version', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    kms.addEnabledVersion(cryptoKeyName, '2', {
      name: '',
      pem: 'unused',
      pemCrc32c: { value: '0' },
      algorithm: 'EC_SIGN_P256_SHA256',
    })
    const latestVersionName = kms.addEnabledVersion(cryptoKeyName, '10', {
      name: '',
      pem: 'unused',
      pemCrc32c: { value: '0' },
      algorithm: 'EC_SIGN_P256_SHA256',
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const derSignature = createHash('sha256').update('fixture').digest()
    const signature = cryptoSign('sha256', derSignature, {
      key: privateKey,
      dsaEncoding: 'der',
    })
    kms.asymmetricSignResponse = {
      name: latestVersionName,
      verifiedDigestCrc32c: true,
      signature,
      signatureCrc32c: { value: String(crc32c(signature)) },
    }

    await provider.sign(authz, 'ES256', { iss: authz }, { alg: 'ES256', typ: 'JWT' })

    assert.equal(kms.calls.asymmetricSign.length, 1)
    assert.equal(kms.calls.asymmetricSign[0].name, latestVersionName)
  })

  it('should fail sign when jwtHeader.alg conflicts with keyAlg', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    kms.addEnabledVersion(cryptoKeyName, '1', {
      name: '',
      pem: 'unused',
      pemCrc32c: { value: '0' },
      algorithm: 'EC_SIGN_P256_SHA256',
    })

    await assert.rejects(
      provider.sign(authz, 'ES256', { iss: authz }, { alg: 'RS256', typ: 'JWT' }),
      (error: Error) => {
        assert.equal(error.name, 'AUTHZ_ISSUER_KEY_NOT_FOUND')
        assert.match(error.message, /algorithm mismatch/)
        return true
      }
    )
  })

  it('should fail sign when jwtHeader.alg is missing', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    kms.addEnabledVersion(cryptoKeyName, '1', {
      name: '',
      pem: 'unused',
      pemCrc32c: { value: '0' },
      algorithm: 'EC_SIGN_P256_SHA256',
    })

    await assert.rejects(
      provider.sign(authz, 'ES256', { iss: authz }, { typ: 'JWT' } as never),
      (error: Error) => {
        assert.equal(error.name, 'AUTHZ_ISSUER_KEY_NOT_FOUND')
        assert.match(error.message, /algorithm mismatch/)
        return true
      }
    )
  })

  it('should wrap sign failures in an INTERNAL_SERVER_ERROR', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    kms.versions.set(cryptoKeyName, [])

    await assert.rejects(
      provider.sign(authz, 'ES256', { iss: authz }, { alg: 'ES256', typ: 'JWT' }),
      (error: Error) => {
        assert.equal(error.name, 'AUTHZ_ISSUER_KEY_NOT_FOUND')
        assert.match(error.message, /Authorization server private key not found/)
        return true
      }
    )
  })

  it('should rethrow non-NOT_FOUND version lookup failures from sign as INTERNAL_SERVER_ERROR', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    kms.errors.listCryptoKeyVersions.set(cryptoKeyName, grpcError('permission denied', 7))

    await assert.rejects(
      provider.sign(authz, 'ES256', { iss: authz }, { alg: 'ES256', typ: 'JWT' }),
      (error: Error) => {
        assert.equal(error.name, 'INTERNAL_SERVER_ERROR')
        assert.match(error.message, /permission denied/)
        return true
      }
    )
  })

  it('should map NOT_FOUND from asymmetricSign to AUTHZ_ISSUER_KEY_NOT_FOUND', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsAuthzSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, authzKeyId('ES256'))
    const latestVersionName = kms.addEnabledVersion(cryptoKeyName, '1', {
      name: '',
      pem: 'unused',
      pemCrc32c: { value: '0' },
      algorithm: 'EC_SIGN_P256_SHA256',
    })
    kms.errors.asymmetricSign.set(latestVersionName, grpcError('not found', 5))

    await assert.rejects(
      provider.sign(authz, 'ES256', { iss: authz }, { alg: 'ES256', typ: 'JWT' }),
      (error: Error) => {
        assert.equal(error.name, 'AUTHZ_ISSUER_KEY_NOT_FOUND')
        assert.match(error.message, /Authorization server private key not found/)
        return true
      }
    )
  })
})
