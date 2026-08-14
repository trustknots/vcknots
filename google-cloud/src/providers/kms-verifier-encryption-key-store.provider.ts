import { createHash } from 'node:crypto'
import { KeyManagementServiceClient } from '@google-cloud/kms'
import { crc32c } from '@node-rs/crc32'
import { VerifierClientId } from '@trustknots/vcknots'
import { raise } from '@trustknots/vcknots/errors'
import { VerifierEncryptionKeyStoreProvider } from '@trustknots/vcknots/providers'
import { CloudKmsProviderOptions } from './kms.provider'
import { createKmsProviderHelpers } from './kms-provider.helpers'
import {
  KMS_NOT_FOUND,
  grpcCode,
  joseAlgorithmToKmsAlgorithm,
  kmsAlgorithmToJoseAlgorithm,
  latestEnabledVersion,
} from './kms-provider.utils'

import { calculateJwkThumbprint, exportJWK, importSPKI } from 'jose'

export const kmsVerifierEncryptionKeyStore = (
  options?: CloudKmsProviderOptions
): VerifierEncryptionKeyStoreProvider => {
  const projectId = options?.projectId ?? process.env.GOOGLE_CLOUD_PROJECT_ID
  const locationId = options?.locationId ?? process.env.GOOGLE_CLOUD_LOCATION ?? 'global'
  const kms =
    options?.client ??
    new KeyManagementServiceClient({
      projectId,
      ...(options?.credentials && {
        credentials: {
          private_key: options.credentials.privateKey,
          client_email: options.credentials.clientEmail,
        },
      }),
    })
  if (!projectId) {
    raise('INTERNAL_SERVER_ERROR', {
      message: 'Missing projectId in CloudKmsProviderOptions or GOOGLE_CLOUD_PROJECT_ID env var',
    })
  }
  const keyRingId = 'verifiers'
  const baseImportJobId = 'vcknots-verifier-encryption-import-job'
  const md5 = (verifier: VerifierClientId) => createHash('md5').update(verifier).digest('base64url')
  const verifierKeyId = (verifier: VerifierClientId, alg: string) => `${md5(verifier)}-enc-${alg}`

  const { ensureKeyRing, ensureCryptoKey } = createKmsProviderHelpers({
    kms,
    projectId,
    locationId,
    keyRingId,
    baseImportJobId,
  })

  return {
    kind: 'verifier-encryption-key-store-provider',
    name: 'kms-verifier-encryption-key-store-provider',
    single: true,

    async save(verifier, keyAlg) {
      const kmsAlgorithm = joseAlgorithmToKmsAlgorithm(keyAlg)
      if (!kmsAlgorithm) {
        raise('INTERNAL_SERVER_ERROR', {
          message: `Unsupported verifier encryption key algorithm: ${keyAlg}`,
        })
      }

      const keyRingName = await ensureKeyRing()
      const keyId = verifierKeyId(verifier, keyAlg)

      await ensureCryptoKey(keyRingName, keyId, kmsAlgorithm, {
        importOnly: false,
        purpose: 'ASYMMETRIC_DECRYPT',
      })
    },

    async fetch(verifier, keyAlg) {
      const keyId = verifierKeyId(verifier, keyAlg)
      const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, keyId)
      let versions: { name?: string | null }[] = []
      try {
        const [listedVersions] = await kms.listCryptoKeyVersions({
          parent: cryptoKeyName,
          filter: 'state=ENABLED',
        })
        versions = listedVersions
      } catch (error) {
        if (grpcCode(error) === KMS_NOT_FOUND) {
          return null
        }
        throw error
      }

      const latestVersion = latestEnabledVersion(versions)
      if (!latestVersion?.name) {
        return null
      }

      const versionName = latestVersion.name
      const [publicKey] = await kms.getPublicKey({
        name: versionName,
      })

      // https://cloud.google.com/kms/docs/data-integrity-guidelines
      if (!publicKey.name || !publicKey.pem || publicKey.pemCrc32c?.value == null) {
        console.error(`Public key data is incomplete for verifier ${verifier}`)
        return null
      }
      const publicKeyPem = publicKey.pem
      const publicKeyPemCrc32c = Number(publicKey.pemCrc32c.value)
      if (publicKey.name !== versionName) {
        console.error(
          `Public key name mismatch for verifier ${verifier}: expected ${versionName}, got ${publicKey.name}`
        )
        return null
      }
      if (crc32c(publicKeyPem) !== publicKeyPemCrc32c) {
        console.error(
          `Public key integrity check failed for verifier ${verifier}: expected CRC32C ${publicKeyPemCrc32c}, got ${crc32c(publicKeyPem)}`
        )
        return null
      }

      const alg = kmsAlgorithmToJoseAlgorithm(publicKey.algorithm)
      if (!alg || alg !== keyAlg) {
        console.error(
          `Unsupported KMS key algorithm for verifier ${verifier}: ${publicKey.algorithm}`
        )
        return null
      }

      const cryptoKey = await importSPKI(publicKeyPem, alg)
      const publicJwk = await exportJWK(cryptoKey)
      const kid = await calculateJwkThumbprint(publicJwk)

      return {
        ...publicJwk,
        alg,
        kid,
        use: 'enc',
      }
    },
  }
}
