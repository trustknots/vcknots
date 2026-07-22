import { KMSClient } from '@aws-sdk/client-kms'

export type KmsProviderOptions = {
  client?: KMSClient
}

export const resolveKmsClient = (options?: KmsProviderOptions): KMSClient => {
  if (options?.client) {
    return options.client
  }
  return new KMSClient({})
}
