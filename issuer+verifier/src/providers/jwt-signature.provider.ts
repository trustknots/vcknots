import { JwtSignatureProvider } from './provider.types'
import { err } from '../errors/vcknots.error'
import { createPublicKey } from 'node:crypto'
import * as jwt from 'jsonwebtoken'
import { Jwk } from '../jwk.type'

export const jwtSignature = (): JwtSignatureProvider => {
  return {
    kind: 'jwt-signature-provider',
    name: 'default-jwt-signature-provider',
    single: true,

    async verify(token, publicKey): Promise<boolean> {
      if (typeof token !== 'string') {
        throw err('invalid_token', {
          message: 'Token is not supported.',
        })
      }

      const key = createPublicKey({ key: publicKey as Jwk, format: 'jwk' })
      const e = key.export({ format: 'pem', type: 'spki' })
      const pemKey = e.toString()

      try {
        jwt.verify(token, pemKey)
      } catch (e: unknown) {
        if (e instanceof jwt.JsonWebTokenError) {
          throw err('invalid_jwt', {
            message: 'Invalid signature detected.',
          })
        }

        throw err('internal_server_error', {
          message: `Unexpected error: ${e}.`,
        })
      }

      return true
    },
  }
}

