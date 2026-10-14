import { createPublicKey } from 'node:crypto'
import type { JsonWebKey as NodeJsonWebKey } from 'node:crypto'
import * as jwt from 'jsonwebtoken'
import { VcknotsError, err } from '../errors/vcknots.error'
import { VerifyCredentialProvider } from './provider.types'
import * as jose from 'jose'
import { parseVerifiableCredentialBase } from '../credential.types'
import base64url from 'base64url'

export const verifyCredentialJwt = (): VerifyCredentialProvider => {
  return {
    kind: 'verify-verifiable-credential-provider',
    name: 'default-verifiable-jwt-vc-provider',
    single: true,

    async verify(vc, options): Promise<boolean> {
      if (typeof vc !== 'string') {
        throw err('illegal_argument', {
          message: 'VC represented as object is not supported.',
        })
      }
      let decodedJwtVc: jwt.Jwt | null
      try {
        decodedJwtVc = jwt.decode(vc, { complete: true }) as jwt.Jwt | null
      } catch (e) {
        throw err('invalid_credential', {
          message: e instanceof Error ? e.message : 'VC JWT is not a valid JWT.',
        })
      }
      if (!decodedJwtVc) {
        throw err('invalid_credential')
      }
      if (options?.allowedAlgs) {
        const vcAlg = decodedJwtVc.header.alg
        if (!vcAlg || !options.allowedAlgs.includes(vcAlg)) {
          throw err('verifier_vp_formats_not_supported', {
            message: `VC algorithm '${vcAlg ?? 'missing'}' is not in jwt_vc_json alg_values. Allowed: ${options.allowedAlgs.join(', ')}`,
          })
        }
      }

      let iss: string | undefined
      const parts = vc.split('.')
      const payload = parts[1]
      let decoded: Record<string, unknown>
      try {
        const raw: unknown = JSON.parse(base64url.decode(payload ?? ''))
        if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
          throw err('invalid_credential', {
            message: 'VC JWT payload is not valid base64url or JSON.',
          })
        }
        decoded = raw as Record<string, unknown>
      } catch (e) {
        if (e instanceof VcknotsError) throw e
        throw err('invalid_credential', {
          message: 'VC JWT payload is not valid base64url or JSON.',
        })
      }
      const credential = decoded.vc ? decoded.vc : decoded
      if (parseVerifiableCredentialBase(credential)) {
        iss = credential.issuer
      }

      let publicJwk: jose.JWK | undefined
      if (iss && typeof iss === 'string') {
        const issUri = new URL(iss)
        if (issUri.hostname !== 'localhost' && issUri.protocol !== 'https:') {
          throw err('invalid_credential', {
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
          throw err('invalid_credential', {
            message: `Failed to fetch issuer metadata: ${metadataResponse.statusText}`,
          })
        }
        const metadata = await metadataResponse.json().catch(() => {
          throw err('invalid_credential', {
            message: `Issuer metadata at ${metadataUrl} is not valid JSON`,
          })
        })
        if (metadata.issuer !== iss) {
          throw err('invalid_credential', {
            message: 'Issuer in metadata does not match VC issuer',
          })
        }
        let jwks: jose.JSONWebKeySet
        if (metadata.jwks_uri && typeof metadata.jwks_uri === 'string') {
          const jwksResponse = await fetch(metadata.jwks_uri)
          if (!jwksResponse.ok) {
            throw err('jwks_not_found', {
              message: `Failed to fetch JWKS: ${jwksResponse.statusText}`,
            })
          }
          jwks = await jwksResponse.json().catch(() => {
            throw err('jwks_not_found', {
              message: `JWKS at ${metadata.jwks_uri} is not valid JSON`,
            })
          })
        } else if (metadata.jwks && typeof metadata.jwks === 'object') {
          jwks = metadata.jwks as jose.JSONWebKeySet
        } else {
          throw err('jwks_not_found', {
            message: 'No JWKS or JWKS URI found in issuer metadata',
          })
        }
        publicJwk = jwks.keys[0]
        if (!publicJwk) {
          throw err('jwks_not_found', {
            message: `Empty JWKS keys in jwt-vc-issuer for: ${issUri}`,
          })
        }
        let decode: jwt.Jwt
        try {
          const publicKey = createPublicKey({
            key: publicJwk as NodeJsonWebKey,
            format: 'jwk',
          })
          decode = jwt.verify(vc, publicKey, {
            complete: true,
            ignoreNotBefore: true,
          })
        } catch (e) {
          if (e instanceof VcknotsError) throw e
          throw err('invalid_credential', {
            message: e instanceof Error ? e.message : 'VC JWT signature verification failed',
          })
        }
        console.log('Verified claims:', decode.payload)
      } else {
        throw err('invalid_credential')
      }
      return true
    },
    canHandle(format: string): boolean {
      return format === 'jwt_vc_json'
    },
  }
}
