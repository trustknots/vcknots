import { exportJWK, generateKeyPair } from 'jose'
import { AuthzSignatureKeyProvider } from './provider.types'

export type AuthzSignatureKeyProviderOptions = {
  alg?: string
}

export const authzSignatureKey = (
  options?: AuthzSignatureKeyProviderOptions
): AuthzSignatureKeyProvider => {
  const alg = options?.alg ?? 'ES256'

  return {
    kind: 'authz-signature-key-provider',
    name: 'default-authz-signature-key-provider',
    single: false,

    async generate() {
      const { publicKey, privateKey } = await generateKeyPair(alg, {
        extractable: true,
      })
      const publicJwk = await exportJWK(publicKey)
      const privateJwk = await exportJWK(privateKey)
      return {
        publicKey: { ...publicJwk, alg },
        privateKey: { ...privateJwk, alg },
      }
    },

    canHandle(keyAlg: string): boolean {
      return keyAlg === alg
    },
  }
}
