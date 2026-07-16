import { CertificateProvider } from './provider.types'
import { X509Certificate } from 'node:crypto'
import { raise } from '../errors'

export const certificate = (): CertificateProvider => {
  return {
    kind: 'certificate-provider',
    name: 'default-certificate-provider',
    single: true,

    async validate(cert: string[]): Promise<boolean> {
      try {
        const certificates = cert
        if (certificates.length === 0) {
          throw raise('invalid_certificate', {
            message: 'Certificate chain is empty.',
          })
        }

        let chainValid = true
        for (let i = 0; i < certificates.length; i++) {
          const x509Cert = new X509Certificate(certificates[i])
          const now = new Date()
          const validFrom = new Date(x509Cert.validFrom)
          const validTo = new Date(x509Cert.validTo)
          const isValid = now >= validFrom && now <= validTo

          if (!isValid) {
            chainValid = false
          }
        }

        if (certificates.length > 1) {
          for (let i = 0; i < certificates.length - 1; i++) {
            const subjectCertPem = certificates[i]
            const issuerCertPem = certificates[i + 1]
            try {
              const subjectCert = new X509Certificate(subjectCertPem)
              const issuerCert = new X509Certificate(issuerCertPem)

              // issuer verification — check whether the issuer of the subject certificate matches the subject of the issuer certificate
              const issuerMatches = subjectCert.issuer === issuerCert.subject
              // console.log(`Issuer-Subject match: ${issuerMatches}`)

              if (!issuerMatches) {
                chainValid = false
                break
              }

              // signature verification — check whether the subject certificate can be verified using the issuer certificate's public key
              const isSignatureValid = subjectCert.verify(issuerCert.publicKey)
              // console.log(`Signature verification: ${isSignatureValid}`)

              if (!isSignatureValid) {
                chainValid = false
                break
              }

              // temporal validation — check whether the issuer certificate was valid at the time the subject certificate was issued.
              const subjectValidFrom = new Date(subjectCert.validFrom)
              const issuerValidFrom = new Date(issuerCert.validFrom)
              const issuerValidTo = new Date(issuerCert.validTo)

              const timeValid =
                subjectValidFrom >= issuerValidFrom && subjectValidFrom <= issuerValidTo
              // console.log(`Temporal validity: ${timeValid}`)

              if (!timeValid) {
                // console.log(`Subject valid from: ${subjectValidFrom.toISOString()}`)
                // console.log(
                //   `Issuer valid period: ${issuerValidFrom.toISOString()} - ${issuerValidTo.toISOString()}`
                // )
                chainValid = false
                break
              }
            } catch (signatureError) {
              // console.log(`Signature verification failed: ${signatureError}`)
              chainValid = false
              break
            }
          }
        }

        // self-signature verification of the root certificate
        if (certificates.length > 0) {
          const rootCertPem = certificates[certificates.length - 1]
          const rootCert = new X509Certificate(rootCertPem)

          const isSelfSigned = rootCert.issuer === rootCert.subject
          // console.log(`Root CA self-signed: ${isSelfSigned}`)

          if (isSelfSigned) {
            try {
              const selfSignatureValid = rootCert.verify(rootCert.publicKey)
              // console.log(`Root self-signature valid: ${selfSignatureValid}`)
              if (!selfSignatureValid) {
                chainValid = false
              }
            } catch (error) {
              // console.log(`Root self-signature verification failed: ${error}`)
              chainValid = false
            }
          }
        }

        return chainValid
      } catch (error) {
        // console.log(`Certificate validation error: ${error}`)
        return false
      }
    },
    getPublicKey(cert: string): string {
      try {
        const x509Cert = new X509Certificate(cert)
        return x509Cert.publicKey.export({ type: 'spki', format: 'pem' }) as string
      } catch (error) {
        // console.log(`Get public key error: ${error}`)
        return ''
      }
    },
  }
}
