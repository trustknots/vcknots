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

    async verify(vc, issuer, presentationSubmission, options): Promise<boolean> {
      if (options && options.kind !== 'dc+sd-jwt') {
        throw err('ILLEGAL_ARGUMENT', {
          message: `${options.kind} is not supported.`,
        })
      }

      const specifiedDiscloseres = options?.specifiedDiscloseres || []
      const isKbjwt = options?.isKbjwt || false

      try {
        const decodedSdJwt = await decodeSdJwt(vc, digest)
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
        await sdJwtInst.validate(vc)
        const { payload: claims } = await sdJwtInst.verify(vc, specifiedDiscloseres, isKbjwt)
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
