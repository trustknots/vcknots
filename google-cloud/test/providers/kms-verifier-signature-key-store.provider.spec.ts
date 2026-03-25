import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { crc32c } from '@node-rs/crc32'
import { derToJose } from 'ecdsa-sig-formatter'
import { VerifierClientId } from '@trustknots/vcknots'
import { raise } from '@trustknots/vcknots/errors'
import { kmsVerifierSignatureKeyStore } from '../../src/providers/kms-verifier-signature-key-store.provider'

const projectId = 'test-project'
const locationId = 'global'
const keyRingId = 'verifiers'
const baseImportJobId = 'vcknots-verifier-import-job'
const verifier = VerifierClientId('https://example.com/verifier')

const md5 = (value: string) => createHash('md5').update(value).digest('base64url')
const verifierKeyId = (alg: string) => `${md5(verifier)}-${alg}`

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
    if (!this.keyRings.has(name)) {
      throw raise('INTERNAL_SERVER_ERROR', { message: 'not found' })
    }
    return [{ name }]
  }

  async createKeyRing(request: Record<string, unknown>) {
    this.calls.createKeyRing.push(request)
    const name = this.keyRingPath(projectId, locationId, String(request.keyRingId))
    this.keyRings.add(name)
    return [{ name }]
  }

  async getImportJob({ name }: { name: string }) {
    const job = this.importJobs.get(name)
    if (!job) {
      throw raise('INTERNAL_SERVER_ERROR', { message: 'not found' })
    }
    return [job]
  }

  async createImportJob(request: Record<string, unknown>) {
    this.calls.createImportJob.push(request)
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

  async getCryptoKey({ name }: { name: string }) {
    if (!this.cryptoKeys.has(name)) {
      throw raise('INTERNAL_SERVER_ERROR', { message: 'not found' })
    }
    return [{ name }]
  }

  async createCryptoKey(request: Record<string, unknown>) {
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
    const versions = this.versions.get(parent)
    if (!versions) {
      throw raise('INTERNAL_SERVER_ERROR', { message: 'not found' })
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

describe('kmsVerifierSignatureKeyStore', () => {
  const originalConsoleError = console.error

  afterEach(() => {
    console.error = originalConsoleError
  })

  it('should have correct provider metadata', () => {
    const provider = kmsVerifierSignatureKeyStore({
      client: new FakeKmsClient() as never,
      projectId,
      locationId,
    })

    assert.equal(provider.kind, 'verifier-signature-key-store-provider')
    assert.equal(provider.name, 'kms-verifier-signature-key-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save an ES256 verifier key by importing it into KMS', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const privateKeyPem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()

    await provider.save(verifier, [
      {
        format: 'pem',
        declaredAlg: 'ES256',
        privateKey: privateKeyPem,
      },
    ])

    assert.equal(kms.calls.createKeyRing.length, 0)
    assert.equal(kms.calls.createCryptoKey.length, 1)
    assert.equal(kms.calls.importCryptoKeyVersion.length, 1)
    assert.deepEqual(kms.calls.createCryptoKey[0], {
      parent: kms.keyRingPath(projectId, locationId, keyRingId),
      cryptoKeyId: verifierKeyId('ES256'),
      cryptoKey: {
        purpose: 'ASYMMETRIC_SIGN',
        versionTemplate: {
          algorithm: 'EC_SIGN_P256_SHA256',
        },
        destroyScheduledDuration: { seconds: 60 * 60 * 24 },
      },
    })

    const importRequest = kms.calls.importCryptoKeyVersion[0]
    assert.equal(
      importRequest.parent,
      kms.cryptoKeyPath(projectId, locationId, keyRingId, verifierKeyId('ES256'))
    )
    assert.equal(importRequest.algorithm, 'EC_SIGN_P256_SHA256')
    assert.equal(
      importRequest.importJob,
      kms.importJobPath(projectId, locationId, keyRingId, baseImportJobId)
    )
    assert.ok(importRequest.wrappedKey instanceof Buffer)
    assert.ok((importRequest.wrappedKey as Buffer).length > 0)
  })

  it('should fail save for unsupported algorithms', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })

    await assert.rejects(
      provider.save(verifier, [
        {
          format: 'jwk',
          declaredAlg: 'unsupported',
          privateKey: { kty: 'EC' },
        },
      ]),
      (error: Error) => {
        assert.equal(error.name, 'INTERNAL_SERVER_ERROR')
        assert.match(error.message, /Unsupported verifier key algorithm/)
        return true
      }
    )

    assert.equal(kms.calls.importCryptoKeyVersion.length, 0)
  })

  it('should fetch the latest enabled public key when KMS data is valid', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('ES256')
    )
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

    const key = await provider.fetch(verifier, 'ES256')

    assert.ok(key)
    assert.equal((key as never).export({ format: 'pem', type: 'spki' }).toString(), publicKeyPem)
  })

  it('should fetch the numerically latest enabled public key version', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey: oldPublicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const { publicKey: newPublicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const oldPublicKeyPem = oldPublicKey.export({ format: 'pem', type: 'spki' }).toString()
    const newPublicKeyPem = newPublicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('ES256')
    )
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

    const key = await provider.fetch(verifier, 'ES256')

    assert.ok(key)
    assert.equal((key as never).export({ format: 'pem', type: 'spki' }).toString(), newPublicKeyPem)
  })

  it('should return null when fetched public key CRC32C does not match', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('ES256')
    )
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

    const key = await provider.fetch(verifier, 'ES256')

    assert.equal(key, null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Public key integrity check failed/)
  })

  it('should return null when fetched public key name does not match requested version', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('ES256')
    )
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

    const key = await provider.fetch(verifier, 'ES256')

    assert.equal(key, null)
    assert.equal(errors.length, 1)
    assert.match(String(errors[0][0]), /Public key name mismatch/)
  })

  it('should sign with the latest enabled ES256 key version', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('ES256')
    )
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
    const jwtPayload = { iss: verifier, aud: 'wallet', nonce: 'nonce-123' }

    const result = await provider.sign(verifier, 'ES256', jwtPayload, jwtHeader)

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
    const provider = kmsVerifierSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('ES256')
    )
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

    await provider.sign(verifier, 'ES256', { iss: verifier }, { alg: 'ES256', typ: 'JWT' })

    assert.equal(kms.calls.asymmetricSign.length, 1)
    assert.equal(kms.calls.asymmetricSign[0].name, latestVersionName)
  })

  it('should wrap sign failures in an INTERNAL_SERVER_ERROR', async () => {
    const kms = new FakeKmsClient()
    const provider = kmsVerifierSignatureKeyStore({
      client: kms as never,
      projectId,
      locationId,
    })
    const cryptoKeyName = kms.cryptoKeyPath(
      projectId,
      locationId,
      keyRingId,
      verifierKeyId('ES256')
    )
    kms.versions.set(cryptoKeyName, [])

    await assert.rejects(
      provider.sign(verifier, 'ES256', { iss: verifier }, { alg: 'ES256', typ: 'JWT' }),
      (error: Error) => {
        assert.equal(error.name, 'INTERNAL_SERVER_ERROR')
        assert.match(error.message, /Verifier private key not found/)
        return true
      }
    )
  })
})
