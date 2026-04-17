import { Provider } from '@trustknots/vcknots/providers'
import { secretManagerVerifierCertificateStoreProvider } from './secret-manager-verifier-certificate-store.provider'
import { SecretManagerServiceClient } from '@google-cloud/secret-manager'

export type SecretManagerProviderOptions = {
  client?: SecretManagerServiceClient
  projectId?: string
  secretPrefix?: string
  credentials?: {
    privateKey: string
    clientEmail: string
  }
}

const buildSecretManagerClient = (
  options?: SecretManagerProviderOptions
): SecretManagerServiceClient =>
  new SecretManagerServiceClient({
    projectId: options?.projectId,
    ...(options?.credentials && {
      credentials: {
        private_key: options.credentials.privateKey,
        client_email: options.credentials.clientEmail,
      },
    }),
  })

export const secretManager = (options?: SecretManagerProviderOptions): Provider[] => {
  const client = options?.client ?? buildSecretManagerClient(options)
  return [secretManagerVerifierCertificateStoreProvider({ ...options, client })]
}
