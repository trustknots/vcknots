import { AuthzRequestJARProvider } from './provider.types'
import { RequestObject } from '../request-object.types'
import { JwtContent } from '../jwt.types'
import { raise } from '../errors'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'
import { ClientId } from '../client-id.types'
import { calculateJwkThumbprint, exportJWK } from 'jose'

export const authzRequestJARKid = (): AuthzRequestJARProvider & WithProviderRegistry => {
  return {
    kind: 'authz-request-jar-provider',
    name: 'default-authz-request-jar-provider',
    single: false,

    ...withProviderRegistry,

    async generate(
      verifierId: ClientId,
      requestObject: RequestObject,
      alg: string,
      wallet_nonce?: string
    ): Promise<JwtContent> {
      const keyStore$ = this.providers.get('verifier-signature-key-store-provider')
      const verifierPubKey = await keyStore$.fetch(verifierId, alg)
      if (!verifierPubKey) {
        throw raise('authz_verifier_key_not_found', {
          message: 'Verifier key not found.',
        })
      }
      const jwk = await exportJWK(verifierPubKey)
      const publicKeyId = await calculateJwkThumbprint(jwk)

      const jwtHeader = {
        alg,
        typ: 'oauth-authz-req+jwt',
        kid: publicKeyId,
      }
      const jwtPayload = {
        ...requestObject,
        iat: Math.floor(Date.now() / 1000),
      }
      // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10
      if (wallet_nonce) {
        jwtPayload.wallet_nonce = wallet_nonce
      }

      return {
        header: jwtHeader,
        payload: jwtPayload,
      }
    },
    canHandle(clientIdPrefix: string): boolean {
      return clientIdPrefix === 'redirect_uri'
    },
  }
}
