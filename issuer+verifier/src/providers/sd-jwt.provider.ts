import { err } from '../errors/vcknots.error'
import { VerifyCredentialProvider } from './provider.types'
const { SDJwtInstance } = require('@sd-jwt/core')
import { ES256, digest } from '@sd-jwt/crypto-nodejs'
import { decodeSdJwt } from '@sd-jwt/decode'
import * as jose from 'jose'

export const verifyCredentialSDJwt = (): VerifyCredentialProvider => {
  return {
    kind: 'verify-credential-provider',
    name: 'sd-jwt-credential-provider',
    single: false,

    async verify(vc, issuer, presentationSubmission): Promise<boolean> {
      // TODO: Change to Option
      const specifiedDiscloseres: string[] = []
      const isKbjwt = false

      try {
        // Sample SD-JWT VC string for testing
        const sdJwtString =
          'eyJhbGciOiJFUzI1NiIsImtpZCI6Ik9GWV9kbVpuQnIxMUYxSkg5dzdNMUVPNEEweGU4VmpQQUl6YS02QzdfVUUiLCJ0eXBlIjoiZGMrc2Qtand0In0.eyJpc3MiOiJodHRwczovL3Zja25vdHMtYXBwLXNkLWp3dC0tdmNrbm90cy5hc2lhLWVhc3QxLmhvc3RlZC5hcHAiLCJpYXQiOjE3NjU1MjI1MDQsInZjdCI6InVybjpldWRpOnBpZDoxIiwiZXhwIjoxODgzMDAwMDAwLCJfc2QiOlsiMVBJdkhhVnM1SmN5V1h0QWNTakNFVUF3T1Radi1WZll3NV9vaUNBTHpkSSIsIkRNa2ZkWVIwOHVrX2kxSkx5Qzd4MmtaM2ZqXzNUdVdNM2huQ0tmQURiT0UiLCJGUlJWU3FnMXlLM1JObjhmS1VjaU1vV3ZQb25TdnhnMGV4MFhRcTRVa1VrIiwiWlhTTS1VRkRRVzZ1T00xalhFdkwyYld4RkxaenJyMlBHdHhkeWg4SVZNcyIsIm1HVWFxdWNaQlB5QzZBV0twS3NreDJTNXNWSzJpSTE5eS1kWHo3ODNnaFUiLCJ3c1JLY2RqanJ3ZnRtenU4R1V6THREdUtkZzNsSElZTmc5SnIwVEdiMENzIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.HkshPJyBeptaVKSyoWl6-n1SeZ2-ZaHn_H4LUbj33pXCY-4aWwv2otXlUfOBp93QH8rXbNW_ZaJ1e1oij1pN1g~WyIzTHJnYjRMWmtzTjlwYVBQNGhfYWJRIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJyQ0NYZjRNSW5rakVTUGhqaEZ0alFRIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyJab1k2ZGdIUXVlRmFheE85REFDenpnIiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJsZjVYaEVObzZHNlZHdkZnSEdLNlJnIiwicGhvbmVfbnVtYmVyIiwiKzEtMjAyLTU1NS0wMTAxIl0~WyJGNjJoVlZnSEFQMXVOZ2pCVlNPd2RnIiwiYWRkcmVzcyIsIntcInN0cmVldF9hZGRyZXNzXCI6IFwiMTIzIE1haW4gU3RcIiwgXCJsb2NhbGl0eVwiOiBcIkFueXRvd25cIiwgXCJyZWdpb25cIjogXCJBbnlzdGF0ZVwiLCBcImNvdW50cnlcIjogXCJVU1wifSJd~WyJTc0VMNC1zTlFDQkprSXI0UXBqaFVRIiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~'

        const decodedSdJwt = await decodeSdJwt(sdJwtString, digest)
        const sdJwtHeader = decodedSdJwt.jwt.header

        let publicJwk: jose.JWK | undefined
        if (decodedSdJwt.jwt.payload.iss && typeof decodedSdJwt.jwt.payload.iss === 'string') {
          const issUri = new URL(decodedSdJwt.jwt.payload.iss)
          if (issUri.protocol !== 'https:') {
            throw err('INVALID_SD_JWT', {
              message: 'Issuer URI must use https scheme',
            })
          }
          let metadataUrl: string
          if (issUri.pathname !== '/') {
            metadataUrl = new URL(
              `.well-known/jwt-vc-issuer/${issUri.pathname.replace(/^\/+/, '')}`,
              issUri
            ).toString()
          } else {
            metadataUrl = new URL('.well-known/jwt-vc-issuer', issUri).toString()
          }
          const metadataResponse = await fetch(metadataUrl)
          if (!metadataResponse.ok) {
            throw err('INVALID_SD_JWT', {
              message: `Failed to fetch issuer metadata: ${metadataResponse.statusText}`,
            })
          }
          const metadata = await metadataResponse.json()
          if (metadata.issuer !== decodedSdJwt.jwt.payload.iss) {
            throw err('INVALID_SD_JWT', {
              message: 'Issuer in metadata does not match SD-JWT issuer',
            })
          }

          let jwks: jose.JSONWebKeySet
          if (metadata.jwks_uri && typeof metadata.jwks_uri === 'string') {
            const jwksResponse = await fetch(metadata.jwks_uri)
            if (!jwksResponse.ok) {
              throw err('INVALID_SD_JWT', {
                message: `Failed to fetch JWKS: ${jwksResponse.statusText}`,
              })
            }
            jwks = await jwksResponse.json()
          } else if (metadata.jwks && typeof metadata.jwks === 'object') {
            jwks = metadata.jwks as jose.JSONWebKeySet
          } else {
            throw err('INVALID_SD_JWT', {
              message: 'No JWKS or JWKS URI found in issuer metadata',
            })
          }
          let jwkFound: jose.JWK | undefined
          if (sdJwtHeader.kid && typeof sdJwtHeader.kid === 'string') {
            jwkFound = jwks.keys.find((key) => key.kid === sdJwtHeader.kid)
            if (!jwkFound) {
              throw err('INVALID_SD_JWT', {
                message: `No matching JWK found for kid: ${sdJwtHeader.kid}`,
              })
            }
            publicJwk = jwkFound
          } else {
            throw err('INVALID_SD_JWT', {
              message: 'SD-JWT header missing kid for JWKs',
            })
          }
        } else if (
          sdJwtHeader.x5c &&
          Array.isArray(sdJwtHeader.x5c) &&
          sdJwtHeader.x5c.length > 0
        ) {
          // TODO: implement x5c to JWK conversion
          throw err('INTERNAL_SERVER_ERROR', {
            message: 'x5c header handling not implemented yet',
          })
        } else {
          throw err('INVALID_SD_JWT', {
            message: 'No method to obtain public JWK for SD-JWT verification',
          })
        }

        if (!publicJwk) {
          throw err('INVALID_SD_JWT', {
            message: 'Unable to obtain public JWK for SD-JWT verification',
          })
        }
        const verifier = await ES256.getVerifier(publicJwk)
        const sdJwtInst = new SDJwtInstance({
          verifier,
          hasher: digest,
        })
        await sdJwtInst.validate(sdJwtString)
        const { payload: claims } = await sdJwtInst.verify(
          sdJwtString,
          specifiedDiscloseres,
          isKbjwt
        )
        console.log('Verified claims:', claims)
      } catch (e) {
        throw err('INVALID_SD_JWT', {
          message: 'Invalid SD-JWT signature detected',
        })
      }
      return true
    },
    canHandle(format: string): boolean {
      return format === 'dc+sd-jwt'
    },
  }
}
