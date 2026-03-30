import { createHash } from 'node:crypto'
import { KeyManagementServiceClient } from '@google-cloud/kms'
import { crc32c } from '@node-rs/crc32'
import { derToJose } from 'ecdsa-sig-formatter'
import { importSPKI } from 'jose'
import { AuthzSignatureKeyStoreProvider } from '@trustknots/vcknots/providers'
import { AuthorizationServerIssuer } from '@trustknots/vcknots/authz'
import { VcknotsError, raise } from '@trustknots/vcknots/errors'
import { CloudKmsProviderOptions } from './kms.provider'
import { createKmsProviderHelpers } from './kms-provider.helpers'
import {
  KMS_NOT_FOUND,
  digestFieldName,
  grpcCode,
  joseAlgorithmToKmsAlgorithm,
  kmsAlgorithmToJoseAlgorithm,
  latestEnabledVersion,
  toPkcs8Der,
  wrapPrivateKeyForImport,
} from './kms-provider.utils'

export const kmsAuthzSignatureKeyStore = (
  options?: CloudKmsProviderOptions
): AuthzSignatureKeyStoreProvider => {
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
  const keyRingId = 'authServers'
  const baseImportJobId = 'vcknots-authz-import-job'
  const md5 = (authz: AuthorizationServerIssuer) =>
    createHash('md5').update(authz).digest('base64url')
  const authzKeyId = (authz: AuthorizationServerIssuer, alg: string) =>
    `${md5(authz)}-${alg || 'es256'}`

  const { ensureKeyRing, ensureImportJob, ensureCryptoKey } = createKmsProviderHelpers({
    kms,
    projectId,
    locationId,
    keyRingId,
    baseImportJobId,
    importJobPollIntervalMs: 3000,
    importJobMaxRetries: 60,
  })

  return {
    kind: 'authz-signature-key-store-provider',
    name: 'kms-authz-signature-key-store-provider',
    single: true,

    async save(authz, keyAlg, pair) {
      const declaredAlg = pair?.declaredAlg ?? keyAlg
      if (pair && pair.declaredAlg !== keyAlg) {
        raise('ILLEGAL_ARGUMENT', {
          message: `The provided key pair algorithm ${pair.declaredAlg} does not match the requested key algorithm ${keyAlg}.`,
        })
      }

      const kmsAlgorithm = joseAlgorithmToKmsAlgorithm(declaredAlg)
      if (!kmsAlgorithm) {
        raise('INTERNAL_SERVER_ERROR', {
          message: `Unsupported authorization server key algorithm: ${declaredAlg}`,
        })
      }

      if (pair && (declaredAlg.startsWith('RS') || declaredAlg.startsWith('PS'))) {
        raise('INTERNAL_SERVER_ERROR', {
          message: `Import for ${declaredAlg} requires RSA_AES wrapping (AES-KWP), which is not implemented`,
        })
      }

      const keyId = authzKeyId(authz, declaredAlg)
      const keyRingName = await ensureKeyRing()
      if (!pair) {
        await ensureCryptoKey(keyRingName, keyId, kmsAlgorithm, { importOnly: false })
        return
      }

      const importJob = await ensureImportJob(keyRingName)
      const importJobName = importJob.name
      const wrappingPublicKeyPem = importJob.publicKey?.pem
      if (!importJobName || !wrappingPublicKeyPem) {
        raise('INTERNAL_SERVER_ERROR', {
          message: 'Import job is missing name or wrapping public key',
        })
      }

      const privateKeyDer = toPkcs8Der(pair.privateKey)
      const wrappedKey = wrapPrivateKeyForImport(privateKeyDer, wrappingPublicKeyPem)
      const cryptoKeyName = await ensureCryptoKey(keyRingName, keyId, kmsAlgorithm, {
        importOnly: true,
      })
      await kms.importCryptoKeyVersion({
        parent: cryptoKeyName,
        algorithm: kmsAlgorithm as never,
        importJob: importJobName,
        wrappedKey,
      })
    },

    async fetch(authz, keyAlg) {
      const keyId = authzKeyId(authz, keyAlg)
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
      const [publicKey] = await (async () => {
        try {
          return await kms.getPublicKey({ name: versionName })
        } catch (error) {
          if (grpcCode(error) === KMS_NOT_FOUND) {
            return [null]
          }
          throw error
        }
      })()
      if (!publicKey) {
        return null
      }

      if (!publicKey.name || !publicKey.pem || publicKey.pemCrc32c?.value == null) {
        console.error(`Public key data is incomplete for authorization server ${authz}`)
        return null
      }
      const publicKeyPem = publicKey.pem
      const publicKeyPemCrc32c = Number(publicKey.pemCrc32c.value)
      if (publicKey.name !== versionName) {
        console.error(
          `Public key name mismatch for authorization server ${authz}: expected ${versionName}, got ${publicKey.name}`
        )
        return null
      }
      if (crc32c(publicKeyPem) !== publicKeyPemCrc32c) {
        console.error(
          `Public key integrity check failed for authorization server ${authz}: expected CRC32C ${publicKeyPemCrc32c}, got ${crc32c(publicKeyPem)}`
        )
        return null
      }

      const alg = kmsAlgorithmToJoseAlgorithm(publicKey.algorithm)
      if (!alg || alg !== keyAlg) {
        console.error(
          `Unsupported KMS key algorithm for authorization server ${authz}: ${publicKey.algorithm}`
        )
        return null
      }

      return importSPKI(publicKeyPem, alg)
    },

    async sign(authz, keyAlg, jwtPayload, jwtHeader) {
      try {
        const keyId = authzKeyId(authz, keyAlg)
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
          raise('AUTHZ_ISSUER_KEY_NOT_FOUND', {
            message: 'Authorization server private key not found.',
          })
        }

        if (jwtHeader.alg !== keyAlg) {
          raise('AUTHZ_ISSUER_KEY_NOT_FOUND', {
            message: `Authorization server private key algorithm mismatch: header alg ${jwtHeader.alg}, key alg ${keyAlg}.`,
          })
        }

        const encodedHeader = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url')
        const encodedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url')
        const signingInput = `${encodedHeader}.${encodedPayload}`
        const digestField = digestFieldName(keyAlg)
        if (!digestField) {
          raise('INTERNAL_SERVER_ERROR', {
            message: `Unsupported authorization server key algorithm: ${keyAlg}`,
          })
        }
        const digest = createHash(digestField).update(Buffer.from(signingInput)).digest()

        const digestCrc32c = crc32c(digest)
        const versionName = latestVersion.name
        const signed = await (async () => {
          try {
            const [signResponse] = await kms.asymmetricSign({
              name: versionName,
              digest: {
                [digestField]: digest,
              } as never,
              digestCrc32c: {
                value: BigInt(digestCrc32c).toString(),
              },
            })
            return signResponse
          } catch (error) {
            if (grpcCode(error) === KMS_NOT_FOUND) {
              raise('AUTHZ_ISSUER_KEY_NOT_FOUND', {
                message: 'Authorization server private key not found.',
              })
            }
            throw error
          }
        })()

        if (signed.name !== versionName) {
          raise('INTERNAL_SERVER_ERROR', { message: 'KMS key version mismatch' })
        }
        if (!signed.verifiedDigestCrc32c) {
          raise('INTERNAL_SERVER_ERROR', {
            message: 'KMS digest CRC32C verification failed',
          })
        }
        if (!signed.signature || signed.signatureCrc32c?.value == null) {
          raise('INTERNAL_SERVER_ERROR', { message: 'KMS signature is missing' })
        }

        const signature = Buffer.from(signed.signature as Uint8Array)
        if (crc32c(signature) !== Number(signed.signatureCrc32c.value)) {
          raise('INTERNAL_SERVER_ERROR', {
            message: 'KMS signature CRC32C verification failed',
          })
        }
        return keyAlg.startsWith('ES')
          ? derToJose(signature.toString('base64'), keyAlg)
          : signature.toString('base64url')
      } catch (error) {
        if (error instanceof VcknotsError) {
          throw error
        }
        raise('INTERNAL_SERVER_ERROR', { message: `sign error: ${error}` })
      }
    },
  }
}
