import { AccessTokenProvider } from './provider.types'

export const accessToken = (): AccessTokenProvider => {
  return {
    kind: 'access-token-provider',
    name: 'default-access-token-provider',
    single: true,

    async createTokenPayload(authz, code, options) {
      const timeStamp = Math.floor(Date.now() / 1000)
      const payload = {
        iss: authz,
        sub: code,
        exp: timeStamp + (options?.ttlSec ?? 86400),
        iat: timeStamp,
      }
      return payload
    },
  }
}
