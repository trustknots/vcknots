import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager'

/** Default namespace for secrets this package creates. */
export const VERIFIER_CERTIFICATE_SECRET_PREFIX = 'vcknots/verifier-certificates'

export type SecretsManagerProviderOptions = {
  client?: SecretsManagerClient
  /**
   * Name prefix for the secrets holding verifier certificates. Must stay in sync with the
   * resource ARN pattern the CDK stack grants the Verifier Lambda
   * (server/aws/resources/lib/construct/api/verifier-api.ts).
   */
  secretPrefix?: string
}

export const resolveSecretsManagerClient = (
  options?: SecretsManagerProviderOptions
): SecretsManagerClient => {
  if (options?.client) {
    return options.client
  }
  return new SecretsManagerClient({})
}

export const isSecretsManagerError = (error: unknown, name: string): boolean => {
  return error instanceof Error && error.name === name
}
