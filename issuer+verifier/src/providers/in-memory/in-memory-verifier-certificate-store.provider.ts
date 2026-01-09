import { Certificate } from '../../signature-key.types'
import { VerifierCertificateStoreProvider } from '../provider.types'

export const inMemoryVerifierCertificateStore = (): VerifierCertificateStoreProvider => {
  const map = new Map<string, Certificate>()

  return {
    kind: 'verifier-certificate-store-provider',
    name: 'in-memory-verifier-certificate-store-provider',
    single: true,

    async save(verifier, cert) {
      map.set(verifier, cert)
    },

    async fetch(verifier) {
      const cert = map.get(verifier) ?? []
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
