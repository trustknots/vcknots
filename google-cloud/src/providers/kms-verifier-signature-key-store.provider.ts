import {
  constants,
  createHash,
  createPrivateKey,
  createPublicKey,
  publicEncrypt,
} from 'node:crypto'
import { KeyManagementServiceClient } from '@google-cloud/kms'
import { crc32c } from '@node-rs/crc32'
import { VerifierSignatureKeyStoreProvider } from '@trustknots/vcknots/providers'
import { kmsAlgorithmToJoseAlgorithm } from './kms-utils'
import { CloudKmsProviderOptions } from './kms.provider'
import { VerifierClientId } from '@trustknots/vcknots'

export const kmsVerifierSignatureKeyStore = (
  options?: CloudKmsProviderOptions
): VerifierSignatureKeyStoreProvider => {
  const kms = options?.client ?? new KeyManagementServiceClient()
  const projectId = options?.projectId ?? process.env.GOOGLE_CLOUD_PROJECT_ID
  const locationId = options?.locationId ?? process.env.GOOGLE_CLOUD_LOCATION ?? 'global'
  if (!projectId) {
    throw new Error(
      'Missing projectId in CloudKmsProviderOptions or GOOGLE_CLOUD_PROJECT_ID env var'
    )
  }
  const keyRingId = 'verifiers'
  const importJobId = 'vcknots-verifier-import-job'

  const md5 = (verifier: VerifierClientId) => createHash('md5').update(verifier).digest('base64url')

  const verifierKeyId = (verifier: VerifierClientId, alg: string) =>
    `${md5(verifier)}-${alg || 'es256'}`

  const joseAlgorithmToKmsAlgorithm = (alg?: string): string | null => {
    switch (alg) {
      case 'ES256':
        return 'EC_SIGN_P256_SHA256'
      case 'ES384':
        return 'EC_SIGN_P384_SHA384'
      case 'RS256':
        return 'RSA_SIGN_PKCS1_2048_SHA256'
      case 'RS512':
        return 'RSA_SIGN_PKCS1_4096_SHA512'
      case 'PS256':
        return 'RSA_SIGN_PSS_2048_SHA256'
      case 'PS512':
        return 'RSA_SIGN_PSS_4096_SHA512'
      default:
        return null
    }
  }

  const ensureKeyRing = async () => {
    const keyRingName = kms.keyRingPath(projectId, locationId, keyRingId)
    try {
      await kms.getKeyRing({ name: keyRingName })
    } catch {
      const parent = kms.locationPath(projectId, locationId)
      await kms.createKeyRing({
        parent,
        keyRingId,
        keyRing: {},
      })
    }
    return keyRingName
  }

  const ensureImportJob = async (keyRingName: string) => {
    const importJobName = kms.importJobPath(projectId, locationId, keyRingId, importJobId)
    try {
      const [job] = await kms.getImportJob({ name: importJobName })
      if (job.state === 'ACTIVE') {
        return job
      }
    } catch {
      await kms.createImportJob({
        parent: keyRingName,
        importJobId,
        importJob: {
          importMethod: 'RSA_OAEP_3072_SHA256',
          protectionLevel: 'SOFTWARE',
        },
      })
    }

    for (let i = 0; i < 30; i++) {
      const [job] = await kms.getImportJob({ name: importJobName })
      if (job.state === 'ACTIVE') {
        return job
      }
      await new Promise((resolve) => setTimeout(resolve, 1000))
    }
    throw new Error(`Import job did not become ACTIVE: ${importJobName}`)
  }

  const ensureCryptoKey = async (keyRingName: string, keyId: string, kmsAlgorithm: string) => {
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, keyId)
    try {
      await kms.getCryptoKey({ name: cryptoKeyName })
      return cryptoKeyName
    } catch {
      await kms.createCryptoKey({
        parent: keyRingName,
        cryptoKeyId: keyId,
        cryptoKey: {
          purpose: 'ASYMMETRIC_SIGN',
          versionTemplate: {
            algorithm: kmsAlgorithm as never,
          },
          destroyScheduledDuration: { seconds: 60 * 60 * 24 },
        },
      })
      return cryptoKeyName
    }
  }

  const toPkcs8Der = (privateKey: unknown): Buffer => {
    if (typeof privateKey === 'string') {
      const key = createPrivateKey(privateKey)
      return key.export({ format: 'der', type: 'pkcs8' }) as Buffer
    }
    const key = createPrivateKey({
      key: privateKey as unknown as import('node:crypto').JsonWebKey,
      format: 'jwk',
    })
    return key.export({ format: 'der', type: 'pkcs8' }) as Buffer
  }

  const wrapPrivateKeyForImport = (privateKeyDer: Buffer, wrappingPem: string): Buffer => {
    return publicEncrypt(
      {
        key: wrappingPem,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      privateKeyDer
    )
  }

  return {
    kind: 'verifier-signature-key-store-provider',
    name: 'kms-verifier-signature-key-store-provider',
    single: true,

    async save(verifier, pairs) {
      const keyRingName = await ensureKeyRing()
      const importJob = await ensureImportJob(keyRingName)
      const importJobName = importJob.name
      const wrappingPublicKeyPem = importJob.publicKey?.pem
      if (!importJobName || !wrappingPublicKeyPem) {
        throw new Error('Import job is missing name or wrapping public key')
      }

      for (const pair of pairs) {
        const declaredAlg = pair.declaredAlg
        const kmsAlgorithm = joseAlgorithmToKmsAlgorithm(declaredAlg)
        if (!kmsAlgorithm) {
          console.error(`Unsupported verifier key algorithm: ${declaredAlg}`)
          continue
        }
        const keyId = verifierKeyId(verifier, declaredAlg)
        const cryptoKeyName = await ensureCryptoKey(keyRingName, keyId, kmsAlgorithm)

        if (declaredAlg.startsWith('RS') || declaredAlg.startsWith('PS')) {
          throw new Error(
            `Import for ${declaredAlg} requires RSA_AES wrapping (AES-KWP), which is not implemented`
          )
        }

        const privateKeyDer = toPkcs8Der(pair.privateKey)
        const wrappedKey = wrapPrivateKeyForImport(privateKeyDer, wrappingPublicKeyPem)
        await kms.importCryptoKeyVersion({
          parent: cryptoKeyName,
          algorithm: kmsAlgorithm as never,
          importJob: importJobName,
          wrappedKey,
        })
      }
    },

    async fetch(verifier, alg) {
      const keyId = verifierKeyId(verifier, alg)
      const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, keyId)
      let versions: { name?: string | null }[] = []
      try {
        ;[versions] = await kms.listCryptoKeyVersions({
          parent: cryptoKeyName,
          filter: 'state=ENABLED',
        })
      } catch {
        return null
      }
      const latestVersion = versions
        .sort((a, b) => (a.name ?? '').localeCompare(b.name ?? ''))
        .pop()
      if (!latestVersion?.name) {
        return null
      }

      const versionName = latestVersion.name
      const [publicKey] = await kms.getPublicKey({ name: versionName })

      // https://cloud.google.com/kms/docs/data-integrity-guidelines
      if (!publicKey.name || !publicKey.pem || !publicKey.pemCrc32c?.value) {
        console.error(`Public key data is incomplete for verifier ${verifier}`)
        return null
      }
      const publicKeyPem = publicKey.pem
      const publicKeyPemCrc32c = Number(publicKey.pemCrc32c.value)
      if (publicKey.name !== versionName) {
        console.error(
          `Public key name mismatch for verifier ${verifier}: expected ${versionName}, got ${publicKey.name}`
        )
      }
      if (crc32c(publicKeyPem) !== publicKeyPemCrc32c) {
        console.error(
          `Public key integrity check failed for verifier ${verifier}: expected CRC32C ${publicKeyPemCrc32c}, got ${crc32c(publicKeyPem)}`
        )
        return null
      }

      const keyAlg = kmsAlgorithmToJoseAlgorithm(publicKey.algorithm)
      if (!keyAlg || keyAlg !== alg) {
        console.error(
          `Unsupported KMS key algorithm for verifier ${verifier}: ${publicKey.algorithm}`
        )
        return null
      }

      const publicKeyCrypto = createPublicKey(publicKeyPem)
      return publicKeyCrypto as unknown as CryptoKey
    },

    async fetchPrivate(_verifier, _alg) {
      return null
    },
  }
}
