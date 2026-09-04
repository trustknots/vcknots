import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose'
import { VerifierEncryptionKeyProvider } from './provider.types'

export type VerifierEncryptionKeyProviderOptions = {
  alg?: string
}

export const verifierEncryptionKey = (
  options?: VerifierEncryptionKeyProviderOptions
): VerifierEncryptionKeyProvider => {
  const alg = options?.alg ?? 'RSA-OAEP-256'

  return {
    kind: 'verifier-encryption-key-provider',
    name: 'default-verifier-encryption-key-provider',
    single: false,

    async generate() {
      const { publicKey, privateKey } = await generateKeyPair(alg, {
        extractable: true,
      })
      const publicJwk = await exportJWK(publicKey)
      const privateJwk = await exportJWK(privateKey)
      const kid = await calculateJwkThumbprint(publicJwk)
      return {
        publicKey: { ...publicJwk, alg, kid, use: 'enc' },
        privateKey: { ...privateJwk, alg },
      }
    },

    canHandle(keyAlg: string): boolean {
      return keyAlg === alg
    },
  }
}
