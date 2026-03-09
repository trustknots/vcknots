import base64url from 'base64url'
import { importJWK, jwtVerify } from 'jose'
import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from './authorization-server.types'
import { err } from './errors/vcknots.error'
import { selectProvider } from './providers/provider.utils'
import { GrantType, TokenRequest } from './token-request.types'
import { VcknotsContext } from './vcknots.context'
type TokenRequestOptions = {
  // biome-ignore lint/complexity/noBannedTypes: <explanation>
  [GrantType.AuthorizationCode]: {
    //TODO: Implement options for authorization code flow
  }
  [GrantType.PreAuthorizedCode]: {
    ttlSec?: number
    c_nonce_expire_in?: number
  }
}

export type AuthzFlow = {
  findAuthzServerMetadata(
    issuer: AuthorizationServerIssuer
  ): Promise<AuthorizationServerMetadata | null>
  createAuthzServerMetadata(
    metadata: AuthorizationServerMetadata,
    options?: { alg?: 'ES256' }
  ): Promise<void>
  createAccessToken<T extends GrantType>(
    authz: AuthorizationServerIssuer,
    tokenRequest: TokenRequest,
    options?: TokenRequestOptions[T]
    // biome-ignore lint/complexity/noBannedTypes: <explanation>
  ): Promise<Object>
  verifyAccessToken(authz: AuthorizationServerIssuer, accessToken: string): Promise<boolean>
}

export const initializeAuthzFlow = (context: VcknotsContext): AuthzFlow => {
  const authz$ = context.providers.get('authz-server-metadata-store-provider')
  const codeStore$ = context.providers.get('pre-authorized-code-store-provider')
  const cnonce$ = context.providers.get('nonce-provider')
  const cnonceStore$ = context.providers.get('nonce-store-provider')
  const accessToken$ = context.providers.get('access-token-provider')
  const authzKey$ = context.providers.get('authz-signature-key-store-provider')
  const authzSignatureKey$ = context.providers.get('authz-signature-key-provider')

  return {
    async findAuthzServerMetadata(issuer) {
      return await authz$.fetch(issuer)
    },
    async createAuthzServerMetadata(metadata, options) {
      const privateKeyAlg = options?.alg ?? 'ES256'
      const provider = selectProvider(authzSignatureKey$, privateKeyAlg)
      const key = await provider.generate()
      const current = await authz$.fetch(metadata.issuer)
      if (current) {
        throw err('DUPLICATE_AUTHZ_SERVER', {
          message: `issuer ${metadata.issuer} is already registered.`,
        })
      }
      await authzKey$.save(metadata.issuer, key)
      await authz$.save(metadata)
    },
    async createAccessToken(authz, tokenRequest, options) {
      switch (tokenRequest.grant_type) {
        case 'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          const option = options as TokenRequestOptions[GrantType.PreAuthorizedCode]
          // Check pre-code validity
          const isValid = await codeStore$.validate(tokenRequest['pre-authorized_code'])
          if (!isValid) {
            throw err('PRE_AUTHORIZED_CODE_NOT_FOUND', {
              message: 'The provided pre-authorized code is invalid.',
            })
          }
          // delete code from store
          await codeStore$.delete(tokenRequest['pre-authorized_code'])

          // TODO: if ix_code is provided, it should be validated

          // Fetch private key
          const keyPaire = await authzKey$.fetch(authz)
          if (!keyPaire) {
            throw err('INVALID_REQUEST', {
              message: `Authorization server key for ${authz} not found.`,
            })
          }
          const privateKey = keyPaire.privateKey
          if (!privateKey) {
            throw err('INVALID_REQUEST', {
              message: 'Authorization server private key not found.',
            })
          }
          const privateKeyAlg = privateKey.alg ?? null
          if (!privateKeyAlg || typeof privateKeyAlg !== 'string') {
            throw err('INVALID_REQUEST', {
              message: 'Authorization server private key algorithm is not specified.',
            })
          }
          // Authz access token (data)
          // for JWK privateKey
          const jwtHeader = {
            alg: privateKeyAlg,
            typ: 'JWT',
          }
          const jwtPayload = await accessToken$.createTokenPayload(
            authz,
            tokenRequest['pre-authorized_code']
          )
          // sign with issuer private key
          const provider = selectProvider(authzSignatureKey$, privateKeyAlg)
          const signature = await provider.sign(privateKey, privateKeyAlg, jwtPayload, jwtHeader)
          if (!signature) {
            throw err('INTERNAL_SERVER_ERROR', {
              message: 'Cannot sign access token.',
            })
          }
          // format JWT components
          const encode = (x: unknown) => base64url.encode(JSON.stringify(x))

          // Create cnonce
          const cnonce = await cnonce$.generate()
          await cnonceStore$.save(cnonce)
          // Create Token Response
          return {
            access_token: `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`, // TODO: Implement access token generation
            token_type: 'bearer',
            expires_in: option?.ttlSec ?? 86400,
            c_nonce: cnonce,
            c_nonce_expires_in: option?.c_nonce_expire_in ?? 60 * 5 * 1000, // 5 minutes
          }
        }
        case 'authorization_code': {
          // TODO: Implement authorization code flow
          throw err('FEATURE_NOT_IMPLEMENTED_YET', {
            message: 'Authorization code flow is not supported.',
          })
        }
        default: {
          throw err('INVALID_REQUEST', {
            message: `Unsupported grant type: ${tokenRequest.grant_type}`,
          })
        }
      }
    },
    async verifyAccessToken(authz, accessToken: string): Promise<boolean> {
      // TODO:  AccessToken Support (self-contained, Token Introspection) — prioritize self-contained.
      // self-contained check
      const [jwtHeader, jwtPayload, jwtSignature] = accessToken.split('.')
      if (!jwtHeader || !jwtPayload || !jwtSignature) {
        throw err('INVALID_ACCESS_TOKEN', {
          message: 'Access token is not a valid JWT.',
        })
      }
      const decodedHeader = JSON.parse(base64url.decode(jwtHeader))
      const decodedPayload = JSON.parse(base64url.decode(jwtPayload))

      // TODO: Need to consider whether to use Provider
      const authzIssuer = AuthorizationServerIssuer(decodedPayload.iss)
      if (authzIssuer !== authz) {
        throw err('INVALID_ACCESS_TOKEN', {
          message: `Access token issuer ${authzIssuer} does not match the expected issuer ${authz}.`,
        })
      }
      const keyPair = await authzKey$.fetch(authzIssuer)
      if (!keyPair) {
        throw err('AUTHZ_ISSUER_KEY_NOT_FOUND', {
          message: `Authorization server key for ${authzIssuer} not found.`,
        })
      }

      const [canHandle] = authzSignatureKey$.filter((it) => it.canHandle(decodedHeader.alg))
      if (!canHandle) {
        throw err('PROVIDER_NOT_FOUND', {
          message: `Signature algorithm ${decodedHeader.alg} is not supported.`,
        })
      }

      if (!keyPair.publicKey) {
        throw err('AUTHZ_ISSUER_KEY_NOT_FOUND', {
          message: `Authorization server public key for ${authzIssuer} not found.`,
        })
      }
      const authzJWKS = await importJWK(keyPair.publicKey)
      // Reference: library-dependent implementation
      // const authzJWKS = createRemoteJWKSet(
      //   new URL(`${authz}/.well-known/jwks.json`)
      // )
      try {
        await jwtVerify(accessToken, authzJWKS, decodedPayload)
      } catch (error) {
        throw err('INVALID_ACCESS_TOKEN', {
          message: 'Access token verification failed.',
        })
      }
      return true
    },
  }
}

export {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from './authorization-server.types'
export { TokenRequest as AuthzTokenRequest } from './token-request.types'
