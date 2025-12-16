import { createPublicKey } from 'node:crypto'
import * as jwt from 'jsonwebtoken'
import { err } from '../errors/vcknots.error'
import { VerifyCredentialProvider } from './provider.types'

export const verifyCredentialJwt = (): VerifyCredentialProvider => {
  return {
    kind: 'verify-credential-provider',
    name: 'default-verifier-jwt-vc-provider',
    single: false,

    async verify(vc, issuer, presentationSubmission): Promise<boolean> {
      const issuerUrl = issuer.endsWith('/') ? issuer : `${issuer}/`
      const res = await fetch(`${issuerUrl}.well-known/jwt-vc-issuer`)

      if (res.status !== 200) {
        throw err('ISSUER_NOT_FOUND', { message: `Cannot fetch jwt-vc-issuer for: ${issuerUrl}` })
      }

      const body = await res.json()

      if (!body.jwks) {
        throw err('JWKS_NOT_FOUND', {
          message: `Missing JWKS section in jwt-vc-issuer for: ${issuerUrl}`,
        })
      }
      if (body.jwks.keys.length === 0) {
        throw err('JWKS_NOT_FOUND', {
          message: `Empty JWKS keys in jwt-vc-issuer for: ${issuerUrl}`,
        })
      }

      const jwks = body.jwks

      const descriptorMap = presentationSubmission.descriptor_map
      for (const map of descriptorMap) {
        if (!map.path_nested) {
          throw err('INVALID_PRESENTATION_SUBMISSION', {
            message: 'Missing path_nested for path: $',
          })
        }

        switch (map.path_nested.format) {
          case 'jwt_vc':
          case 'jwt_vc_json': {
            const key = createPublicKey({ key: jwks.keys[0], format: 'jwk' })
            const e = key.export({ format: 'pem', type: 'spki' })
            const publicKey = e.toString()

            try {
              jwt.verify(vc, publicKey, {
                complete: true,
                ignoreNotBefore: true,
              })
            } catch (e) {
              throw err('INVALID_JWT', {
                message: 'Invalid VC signature detected',
              })
            }

            return true
          }
          default:
            throw err('INVALID_PRESENTATION_SUBMISSION', {
              message: `Unsupported vc format: ${map.path_nested.format}`,
            })
        }
      }

      return true
    },
    canHandle(format: string): boolean {
      return format === 'jwt_vc_json' || format === 'jwt_vc'
    },
  }
}
