import { createHash } from 'node:crypto'
import { Certificate, ClientId, VerifierClientId, certificateSchema } from '@trustknots/vcknots'
import { raise } from '@trustknots/vcknots/errors'
import { VerifierCertificateStoreProvider } from '@trustknots/vcknots/providers'
import { SecretManagerProviderOptions } from './secret-manager.provider'

const isGoogleApiError = (error: unknown, code: number): boolean => {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === code
  )
}

const getSecretId = (verifier: VerifierClientId, prefix: string): string => {
  const md5 = (verifier: VerifierClientId) => createHash('md5').update(verifier).digest('base64url')
  return `${prefix}-${md5(verifier)}`
}

const decodeSecretData = (value: unknown): string => {
  if (typeof value === 'string') return value
  if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8')
  return ''
}

export const secretManagerVerifierCertificateStoreProvider = (
  options?: SecretManagerProviderOptions
): VerifierCertificateStoreProvider => {
  const client = options?.client
  const projectId = options?.projectId ?? process.env.GOOGLE_CLOUD_PROJECT_ID
  const secretPrefix = options?.secretPrefix ?? 'vcknots-verifier-certificate'

  if (!client) {
    throw new Error('Missing Secret Manager client in SecretManagerProviderOptions')
  }
  if (!projectId) {
    throw new Error(
      'Missing projectId in SecretManagerProviderOptions or GOOGLE_CLOUD_PROJECT_ID env var'
    )
  }

  const loadCertificate = async (verifier: ClientId): Promise<Certificate> => {
    const secretId = getSecretId(verifier, secretPrefix)
    const name = `${client.secretPath(projectId, secretId)}/versions/latest`
    try {
      const [version] = await client.accessSecretVersion({ name })
      const raw = decodeSecretData(version.payload?.data)
      if (!raw) return []
      return certificateSchema.parse(JSON.parse(raw))
    } catch (error) {
      // Secret Manager surfaces gRPC status codes on API errors: 5 = NOT_FOUND.
      if (isGoogleApiError(error, 5)) return []
      raise('INTERNAL_SERVER_ERROR', {
        message: 'Failed to load verifier certificate from Secret Manager.',
        cause: error instanceof Error ? error : undefined,
      })
    }
  }

  return {
    kind: 'verifier-certificate-store-provider',
    name: 'secret-manager-verifier-certificate-store-provider',
    single: true,

    async fetch(verifier) {
      const cert = await loadCertificate(verifier)
      return cert.map((c) =>
        c
          .replace(/-----BEGIN CERTIFICATE-----/g, '')
          .replace(/-----END CERTIFICATE-----/g, '')
          .replace(/\s+/g, '')
          .trim()
      )
    },

    async save(verifier, cert) {
      const validatedCert = certificateSchema.parse(cert)
      const secretId = getSecretId(verifier, secretPrefix)
      const projectName = client.projectPath(projectId)
      const secretName = client.secretPath(projectId, secretId)

      try {
        await client.createSecret({
          parent: projectName,
          secretId,
          secret: { replication: { automatic: {} } },
        })
      } catch (error) {
        // 6 = ALREADY_EXISTS, so a concurrent or repeated save can proceed.
        if (!isGoogleApiError(error, 6)) {
          raise('INTERNAL_SERVER_ERROR', {
            message: 'Failed to create verifier certificate secret in Secret Manager.',
            cause: error instanceof Error ? error : undefined,
          })
        }
      }

      try {
        await client.addSecretVersion({
          parent: secretName,
          payload: {
            data: Buffer.from(JSON.stringify(validatedCert), 'utf8'),
          },
        })
      } catch (error) {
        raise('INTERNAL_SERVER_ERROR', {
          message: 'Failed to store verifier certificate in Secret Manager.',
          cause: error instanceof Error ? error : undefined,
        })
      }
    },
  }
}
