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
    const createImportJob = async (importJobId: string) => {
      const importJobName = kms.importJobPath(projectId, locationId, keyRingId, importJobId)
      await kms.createImportJob({
        parent: keyRingName,
        importJobId,
        importJob: {
          importMethod: 'RSA_OAEP_3072_SHA256',
          protectionLevel: 'SOFTWARE',
        },
      })
      const createdJob = await waitForImportJob(importJobName)
      if (!createdJob) {
        raise('INTERNAL_SERVER_ERROR', {
          message: `Import job expired before becoming ACTIVE: ${importJobName}`,
        })
      }
      return createdJob
    }

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

    const canonicalImportJobName = kms.importJobPath(
      projectId,
      locationId,
      keyRingId,
      baseImportJobId
    )
    const canonicalJob = await loadImportJob(canonicalImportJobName)
    if (canonicalJob) {
      return canonicalJob
    }

    const [listedImportJobs] = await kms.listImportJobs({ parent: keyRingName })
    const matchingImportJobs = listedImportJobs
      .filter((job) => job.name?.startsWith(`${keyRingName}/importJobs/${baseImportJobId}`))
      .sort((a, b) => (b.name ?? '').localeCompare(a.name ?? ''))

    for (const job of matchingImportJobs) {
      if (!job.name || job.name === canonicalImportJobName) {
        continue
      }
      const reusableJob = await loadImportJob(job.name)
      if (reusableJob) {
        return reusableJob
      }
    }

    try {
      return await createImportJob(baseImportJobId)
    } catch (error) {
      if (grpcCode(error) !== KMS_ALREADY_EXISTS) {
        throw error
      }
    }

    const reloadedCanonicalJob = await loadImportJob(canonicalImportJobName)
    if (reloadedCanonicalJob) {
      return reloadedCanonicalJob
    }

    const replacementImportJobId = `${baseImportJobId}-${Date.now()}`
    return createImportJob(replacementImportJobId)
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
            importOnly: true,
            versionTemplate: {
              algorithm: kmsAlgorithm as never,
            },
            destroyScheduledDuration: { seconds: 60 * 60 * 24 },
          },
          skipInitialVersionCreation: true,
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
