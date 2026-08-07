import { createHash } from 'node:crypto'
import {
  CreateSecretCommand,
  GetSecretValueCommand,
  PutSecretValueCommand,
} from '@aws-sdk/client-secrets-manager'
import { Certificate, certificateSchema } from '@trustknots/vcknots'
import { raise } from '@trustknots/vcknots/errors'
import { VerifierCertificateStoreProvider } from '@trustknots/vcknots/providers'
import { VerifierClientId } from '@trustknots/vcknots/verifier'
import {
  SecretsManagerProviderOptions,
  VERIFIER_CERTIFICATE_SECRET_PREFIX,
  isSecretsManagerError,
  resolveSecretsManagerClient,
} from './secrets-manager'

// The verifier id is a URL (see client-id.types.ts) and ':' is not a legal character in a
// Secrets Manager name, so the id is hashed. Hex rather than base64url because AWS advises
// against names ending in a hyphen plus six characters — that collides with the random suffix
// AWS appends to secret ARNs — and a base64url digest can end that way by chance.
const secretName = (verifier: VerifierClientId, prefix: string): string =>
  `${prefix}/${createHash('md5').update(verifier).digest('hex')}`

export const secretsManagerVerifierCertificateStore = (
  options?: SecretsManagerProviderOptions
): VerifierCertificateStoreProvider => {
  const client = resolveSecretsManagerClient(options)
  const secretPrefix = options?.secretPrefix ?? VERIFIER_CERTIFICATE_SECRET_PREFIX

  const loadCertificate = async (verifier: VerifierClientId): Promise<Certificate> => {
    const name = secretName(verifier, secretPrefix)
    try {
      const { SecretString, SecretBinary } = await client.send(
        new GetSecretValueCommand({ SecretId: name })
      )
      const raw = SecretString ?? (SecretBinary ? Buffer.from(SecretBinary).toString('utf8') : '')
      if (!raw) return []
      return certificateSchema.parse(JSON.parse(raw))
    } catch (error) {
      // An unregistered verifier is a normal state, not a failure.
      if (isSecretsManagerError(error, 'ResourceNotFoundException')) return []
      raise('internal_server_error', {
        message: 'Failed to load verifier certificate from Secrets Manager.',
        cause: error instanceof Error ? error : undefined,
      })
    }
  }

  return {
    kind: 'verifier-certificate-store-provider',
    name: 'secrets-manager-verifier-certificate-store-provider',
    single: true,

    async save(verifier, cert) {
      const validatedCert = certificateSchema.parse(cert)
      const name = secretName(verifier, secretPrefix)
      const secretString = JSON.stringify(validatedCert)

      try {
        await client.send(new CreateSecretCommand({ Name: name, SecretString: secretString }))
        return
      } catch (error) {
        // A secret awaiting deletion blocks both create and update and only an operator can
        // restore it, so say that instead of surfacing the raw SDK message.
        if (isSecretsManagerError(error, 'InvalidRequestException')) {
          raise('internal_server_error', {
            message: `Verifier certificate secret ${name} is scheduled for deletion. Restore or purge it before saving again.`,
            cause: error instanceof Error ? error : undefined,
          })
        }
        if (!isSecretsManagerError(error, 'ResourceExistsException')) {
          raise('internal_server_error', {
            message: 'Failed to create verifier certificate secret in Secrets Manager.',
            cause: error instanceof Error ? error : undefined,
          })
        }
      }

      // The secret already exists, so add a new version holding the updated certificate.
      try {
        await client.send(new PutSecretValueCommand({ SecretId: name, SecretString: secretString }))
      } catch (error) {
        raise('internal_server_error', {
          message: 'Failed to store verifier certificate in Secrets Manager.',
          cause: error instanceof Error ? error : undefined,
        })
      }
    },

    async fetch(verifier) {
      const cert = await loadCertificate(verifier)
      // x5c carries base64-encoded DER without PEM armor (RFC 7515 §4.1.6).
      return cert.map((c) =>
        c
          .replace(/-----BEGIN CERTIFICATE-----/g, '')
          .replace(/-----END CERTIFICATE-----/g, '')
          .replace(/\s+/g, '')
          .trim()
      )
    },
  }
}
