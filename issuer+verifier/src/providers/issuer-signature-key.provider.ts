import { exportJWK, generateKeyPair } from 'jose'
import { IssuerSignatureKeyProvider } from './provider.types'

export type IssuerSignatureKeyProviderOptions = {
  alg?: string
}

export const issuerSignatureKey = (
  options?: IssuerSignatureKeyProviderOptions
): IssuerSignatureKeyProvider => {
  const alg = options?.alg ?? 'ES256'

  return {
    kind: 'issuer-signature-key-provider',
    name: 'default-issuer-signature-key-provider',
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
