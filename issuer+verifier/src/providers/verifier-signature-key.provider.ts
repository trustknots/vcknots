import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose'
import { VerifierSignatureKeyProvider } from './provider.types'

export type VerifierSignatureKeyProviderOptions = {
  alg?: string
}

export const verifierSignatureKey = (
  options?: VerifierSignatureKeyProviderOptions
): VerifierSignatureKeyProvider => {
  const alg = options?.alg ?? 'ES256'

  return {
    kind: 'verifier-signature-key-provider',
    name: 'default-verifier-signature-key-provider',
    single: false,

    async generate() {
      const { publicKey, privateKey } = await generateKeyPair(alg, {
        extractable: true,
      })
      const publicJwk = await exportJWK(publicKey)
      const privateJwk = await exportJWK(privateKey)
      const kid = await calculateJwkThumbprint(publicJwk)
      return {
        publicKey: { ...publicJwk, alg, kid },
        privateKey: { ...privateJwk, alg },
      }
    },

    canHandle(keyAlg: string): boolean {
      return keyAlg === alg
    },
  }
}
