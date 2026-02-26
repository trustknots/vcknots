import { err } from '../errors/vcknots.error'
import { VerifyVerifiablePresentationProvider } from './provider.types'
const { SDJwtInstance } = require('@sd-jwt/core')
import { ES256, digest } from '@sd-jwt/crypto-nodejs'
import { decodeSdJwt, splitSdJwt } from '@sd-jwt/decode'
import * as jose from 'jose'
import { X509Certificate } from 'node:crypto'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'
import { KbJwtJsonPayload } from '../keyBindingJwt.types'
import { Cnonce } from '../cnonce.types'
import { sdJwtPayloadSchema, VpTokenPayload } from '../presentation.types'

export const verifyVerifiablePresentationDcSdJwt = (): VerifyVerifiablePresentationProvider &
  WithProviderRegistry => {
  return {
    kind: 'verify-verifiable-presentation-provider',
    name: 'verify-verifiable-presentation-dc-sd-jwt-provider',
    single: false,

    ...withProviderRegistry,

    async verify(vp, options): Promise<VpTokenPayload> {
      if (options && options.kind !== 'dc+sd-jwt') {
        throw err('ILLEGAL_ARGUMENT', {
          message: `${options.kind} is not supported.`,
        })
      }

      const specifiedDisclosures = options?.specifiedDisclosures || []
      const isKbJwt = options?.isKbJwt || false

      if (isKbJwt && vp.endsWith('~')) {
        throw err('INVALID_SD_JWT', {
          message: 'Expected Key-Binding JWT, but it was not present.',
        })
      }

      const decodedSdJwt = await decodeSdJwt(vp, digest)
      const sdJwtHeader = decodedSdJwt.jwt.header

      let publicJwk: jose.JWK | undefined
      if (
        !sdJwtHeader.x5c &&
        decodedSdJwt.jwt.payload.iss &&
        typeof decodedSdJwt.jwt.payload.iss === 'string'
      ) {
        const issUri = new URL(decodedSdJwt.jwt.payload.iss)
        if (issUri.hostname !== 'localhost' && issUri.protocol !== 'https:') {
          throw err('INVALID_SD_JWT', {
            message: 'Issuer URI must use https scheme',
          })
        }
        let metadataUrl: string
        // Remove any terminating / from pathname as per spec
        const pathname = issUri.pathname.replace(/\/+$/, '')
        if (pathname === '' || pathname === '/') {
          // Use origin to ensure pathname is replaced, not appended
          metadataUrl = new URL('.well-known/jwt-vc-issuer', issUri.origin).toString()
        } else {
          // Remove leading / and insert between host and path component
          const pathWithoutLeadingSlash = pathname.replace(/^\/+/, '')
          // Use origin to ensure pathname is replaced, not appended
          metadataUrl = new URL(
            `.well-known/jwt-vc-issuer/${pathWithoutLeadingSlash}`,
            issUri.origin
          ).toString()
        }
        console.log('jwt-vc-issuer metadataUrl:', metadataUrl)
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
      } else if (sdJwtHeader.x5c && Array.isArray(sdJwtHeader.x5c) && sdJwtHeader.x5c.length > 0) {
        const leafCert = sdJwtHeader.x5c[0]
        try {
          const cert = leafCert.includes('BEGIN CERTIFICATE')
            ? new X509Certificate(leafCert)
            : new X509Certificate(Buffer.from(leafCert, 'base64'))
          publicJwk = await jose.exportJWK(cert.publicKey)
        } catch (error) {
          throw err('INVALID_SD_JWT', {
            message: 'Invalid x5c certificate in SD-JWT header',
          })
        }
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
      // cnf only support jwk
      const cnf = decodedSdJwt.jwt.payload.cnf as { jwk: jose.JWK }
      if (isKbJwt) {
        if (!cnf || !cnf.jwk) {
          throw err('INVALID_SD_JWT', {
            message: 'Key binding JWT verification failed: cnf claim with jwk is missing',
          })
        }
      }
      const kbVerifier = isKbJwt ? await ES256.getVerifier(cnf.jwk) : undefined
      const sdJwtInst = new SDJwtInstance({
        verifier,
        hasher: digest,
        kbVerifier: kbVerifier,
      })
      await sdJwtInst.validate(vp)
      let nonce: string | undefined
      if (isKbJwt) {
        const { kbJwt } = splitSdJwt(vp)
        if (!kbJwt) {
          throw err('INVALID_SD_JWT', {
            message: 'Key binding JWT is missing in SD-JWT VP',
          })
        }
        const kbSdJwtDecoded = KbJwtJsonPayload(await jose.decodeJwt(kbJwt))
        nonce = kbSdJwtDecoded.nonce
      }
      if (nonce) {
        const nonceStore$ = this.providers.get('cnonce-store-provider')
        const nonceValid = await nonceStore$.validate(Cnonce(nonce))
        if (!nonceValid) {
          throw err('INVALID_NONCE', {
            message: 'nonce is not valid.',
          })
        }
        await nonceStore$.revoke(Cnonce(nonce))
      }
      const { payload: claims } = await sdJwtInst.verify(vp, {
        requiredClaimKeys: specifiedDisclosures,
        keyBindingNonce: nonce,
      })
      const parseResult = sdJwtPayloadSchema().safeParse(claims)
      if (!parseResult.success) {
        throw err('INVALID_SD_JWT', {
          message: `SD-JWT payload does not match expected schema: ${parseResult.error.message}`,
        })
      }
      return parseResult.data
    },
    canHandle(format: string): boolean {
      return format === 'dc+sd-jwt'
    },
  }
}
