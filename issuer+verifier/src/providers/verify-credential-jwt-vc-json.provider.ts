import { createPublicKey } from 'node:crypto'
import type { JsonWebKey as NodeJsonWebKey } from 'node:crypto'
import * as jwt from 'jsonwebtoken'
import { err } from '../errors/vcknots.error'
import { VerifyCredentialProvider } from './provider.types'
import * as jose from 'jose'
import { parseVerifiableCredentialBase } from '../credential.types'
import base64url from 'base64url'

export const verifyCredentialJwt = (): VerifyCredentialProvider => {
  return {
    kind: 'verify-verifiable-credential-provider',
    name: 'default-verifiable-jwt-vc-provider',
    single: true,

    async verify(vc): Promise<boolean> {
      if (typeof vc !== 'string') {
        throw err('ILLEGAL_ARGUMENT', {
          message: 'VC represented as object is not supported.',
        })
      }
      const decodedJwtVc = jwt.decode(vc, { complete: true })
      if (!decodedJwtVc) {
        throw err('INVALID_CREDENTIAL')
      }

      let iss: string | undefined
      const parts = vc.split('.')
      const payload = parts[1]
      const decoded = JSON.parse(base64url.decode(payload))
      const credential = decoded.vc ? decoded.vc : decoded
      if (parseVerifiableCredentialBase(credential)) {
        iss = credential.issuer
      }

      let publicJwk: jose.JWK | undefined
      if (iss && typeof iss === 'string') {
        const issUri = new URL(iss)
        if (issUri.hostname !== 'localhost' && issUri.protocol !== 'https:') {
          throw err('INVALID_CREDENTIAL', {
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
          throw err('INVALID_CREDENTIAL', {
            message: `Failed to fetch issuer metadata: ${metadataResponse.statusText}`,
          })
        }
        const metadata = await metadataResponse.json()
        if (metadata.issuer !== iss) {
          throw err('INVALID_CREDENTIAL', {
            message: 'Issuer in metadata does not match VC issuer',
          })
        }
        let jwks: jose.JSONWebKeySet
        if (metadata.jwks_uri && typeof metadata.jwks_uri === 'string') {
          const jwksResponse = await fetch(metadata.jwks_uri)
          if (!jwksResponse.ok) {
            throw err('JWKS_NOT_FOUND', {
              message: `Failed to fetch JWKS: ${jwksResponse.statusText}`,
            })
          }
          jwks = await jwksResponse.json()
        } else if (metadata.jwks && typeof metadata.jwks === 'object') {
          jwks = metadata.jwks as jose.JSONWebKeySet
        } else {
          throw err('JWKS_NOT_FOUND', {
            message: 'No JWKS or JWKS URI found in issuer metadata',
          })
        }
        publicJwk = jwks.keys[0]
        if (!publicJwk) {
          throw err('JWKS_NOT_FOUND', {
            message: `Empty JWKS keys in jwt-vc-issuer for: ${issUri}`,
          })
        }
        const publicKey = createPublicKey({
          key: publicJwk as NodeJsonWebKey,
          format: 'jwk',
        })

        const decode = jwt.verify(vc, publicKey, {
          complete: true,
          ignoreNotBefore: true,
        })
        console.log('Verified claims:', decode.payload)
      } else {
        throw err('INVALID_CREDENTIAL')
      }
      return true
    },
    canHandle(format: string): boolean {
      return format === 'jwt_vc_json'
    },
  }
}
