import { Provider } from '@trustknots/vcknots/providers'
import { KeyManagementServiceClient } from '@google-cloud/kms'
import { kmsVerifierSignatureKeyStore } from './kms-verifier-signature-key-store.provider'

export type CloudKmsProviderOptions = {
  client?: KeyManagementServiceClient
  projectId?: string
  locationId?: string
  credentials?: {
    privateKey: string
    clientEmail: string
  }
}

const buildKmsClient = (options?: CloudKmsProviderOptions): KeyManagementServiceClient => {
  if (!options) {
    return new KeyManagementServiceClient()
  }

  return new KeyManagementServiceClient({
    projectId: options.projectId,
    ...(options.credentials && {
      credentials: {
        private_key: options.credentials.privateKey,
        client_email: options.credentials.clientEmail,
      },
    }),
  })
}
export const kms = (options?: CloudKmsProviderOptions): Provider[] => {
  const client = options?.client ?? buildKmsClient(options)

  return [kmsVerifierSignatureKeyStore({ ...options, client })]
}
