import { AuthzRequestJARProvider } from './provider.types'
import { RequestObject } from '../request-object.types'
import { JwtContent } from '../jwt.types'
import { WithProviderRegistry, withProviderRegistry } from './provider.registry'
import { ClientId } from '../client-id.types'
import { raise } from '../errors'

export const authzRequestJARX5c = (): AuthzRequestJARProvider & WithProviderRegistry => {
  return {
    kind: 'authz-request-jar-provider',
    name: 'authorization-request-jar-x5c.provider',
    single: false,

    ...withProviderRegistry,

    async generate(
      verifierId: ClientId,
      requestObject: RequestObject,
      alg: string,
      wallet_nonce?: string
    ): Promise<JwtContent> {
      const certificateStore$ = this.providers.get('verifier-certificate-store-provider')
      const certificate = await certificateStore$.fetch(verifierId)
      if (certificate.length === 0) {
        throw raise('CERTIFICATE_NOT_FOUND', {
          message: 'Verifier certificate not found.',
        })
      }

      const jwtHeader = {
        alg,
        typ: 'oauth-authz-req+jwt',
        x5c: certificate,
      }
      const jwtPayload = {
        ...requestObject,
        iat: Math.floor(Date.now() / 1000),
      }
      // https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.11
      if (wallet_nonce) {
        jwtPayload.wallet_nonce = wallet_nonce
      }

      return {
        header: jwtHeader,
        payload: jwtPayload,
      }
    },
    canHandle(clientIdScheme: string): boolean {
      const supportClientIdSchemes = ['x509_san_dns', 'x509_san_uri']
      return supportClientIdSchemes.includes(clientIdScheme)
    },
  }
}
