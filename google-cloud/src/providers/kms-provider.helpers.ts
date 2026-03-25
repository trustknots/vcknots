import { KeyManagementServiceClient } from '@google-cloud/kms'
import { raise } from '@trustknots/vcknots/errors'
import { grpcCode, KMS_ALREADY_EXISTS, KMS_NOT_FOUND } from './kms-provider.utils'

type CreateKmsProviderHelpersOptions = {
  kms: KeyManagementServiceClient
  projectId: string
  locationId: string
  keyRingId: string
  baseImportJobId: string
  importJobPollIntervalMs?: number
  importJobMaxRetries?: number
}

export const createKmsProviderHelpers = ({
  kms,
  projectId,
  locationId,
  keyRingId,
  baseImportJobId,
  importJobPollIntervalMs = 3000,
  importJobMaxRetries = 60,
}: CreateKmsProviderHelpersOptions) => {
  let cachedImportJobName: string | null = null

  const ensureKeyRing = async () => {
    const keyRingName = kms.keyRingPath(projectId, locationId, keyRingId)
    try {
      await kms.getKeyRing({ name: keyRingName })
    } catch (error) {
      if (grpcCode(error) !== KMS_NOT_FOUND) {
        throw error
      }
      const parent = kms.locationPath(projectId, locationId)
      try {
        await kms.createKeyRing({
          parent,
          keyRingId,
          keyRing: {},
        })
      } catch (createError) {
        if (grpcCode(createError) !== KMS_ALREADY_EXISTS) {
          throw createError
        }
      }
    }
    return keyRingName
  }

  const ensureImportJob = async (keyRingName: string) => {
    const waitForImportJob = async (
      importJobName: string,
      options?: { maxRetries?: number; pollIntervalMs?: number }
    ) => {
      const maxRetries = options?.maxRetries ?? importJobMaxRetries
      const pollIntervalMs = options?.pollIntervalMs ?? importJobPollIntervalMs
      for (let i = 0; i < maxRetries; i++) {
        const [job] = await kms.getImportJob({ name: importJobName })
        if (job.state === 'ACTIVE') {
          return job
        }
        if (job.state === 'EXPIRED') {
          return null
        }
        await new Promise((resolve) => setTimeout(resolve, pollIntervalMs))
      }
      raise('INTERNAL_SERVER_ERROR', {
        message: `Import job did not become ACTIVE: ${importJobName}`,
      })
    }

    const loadImportJob = async (importJobName: string) => {
      try {
        const [job] = await kms.getImportJob({ name: importJobName })
        if (job.state === 'ACTIVE') {
          return job
        }
        if (job.state === 'PENDING_GENERATION') {
          return waitForImportJob(importJobName)
        }
        if (job.state === 'EXPIRED') {
          return null
        }
        return null
      } catch (error) {
        if (grpcCode(error) !== KMS_NOT_FOUND) {
          throw error
        }
        return null
      }
    }

    if (cachedImportJobName) {
      const cachedJob = await loadImportJob(cachedImportJobName)
      if (cachedJob) {
        return cachedJob
      }
      cachedImportJobName = null
    }

    const canonicalImportJobName = kms.importJobPath(
      projectId,
      locationId,
      keyRingId,
      baseImportJobId
    )
    const canonicalJob = await loadImportJob(canonicalImportJobName)
    if (canonicalJob) {
      cachedImportJobName = canonicalImportJobName
      return canonicalJob
    }

    const importJobId = `${baseImportJobId}-${Date.now()}`
    const importJobName = kms.importJobPath(projectId, locationId, keyRingId, importJobId)
    await kms.createImportJob({
      parent: keyRingName,
      importJobId,
      importJob: {
        importMethod: 'RSA_OAEP_3072_SHA256',
        protectionLevel: 'SOFTWARE',
      },
    })
    cachedImportJobName = importJobName
    const createdJob = await waitForImportJob(importJobName)
    if (!createdJob) {
      cachedImportJobName = null
      raise('INTERNAL_SERVER_ERROR', {
        message: `Import job expired before becoming ACTIVE: ${importJobName}`,
      })
    }
    return createdJob
  }

  const ensureCryptoKey = async (keyRingName: string, keyId: string, kmsAlgorithm: string) => {
    const cryptoKeyName = kms.cryptoKeyPath(projectId, locationId, keyRingId, keyId)
    try {
      await kms.getCryptoKey({ name: cryptoKeyName })
      return cryptoKeyName
    } catch (error) {
      if (grpcCode(error) !== KMS_NOT_FOUND) {
        throw error
      }
      try {
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
      } catch (createError) {
        if (grpcCode(createError) !== KMS_ALREADY_EXISTS) {
          throw createError
        }
      }
      return cryptoKeyName
    }
  }

  return {
    ensureKeyRing,
    ensureImportJob,
    ensureCryptoKey,
  }
}
