import base64url from 'base64url'
import { jwtVerify } from 'jose'
import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from './authorization-server.types'
import { AuthzOAuthPolicy } from './authz-oauth-policy.types'
import type { DPoPProofVerifyContext } from './dpop-proof.types'
import { err } from './errors/vcknots.error'
import { GrantType, TokenRequest } from './token-request.types'
import { VcknotsContext } from './vcknots.context'
import { JwtPayload } from './jwt.types'
import { Nonce } from './nonce.types'

type AuthzKeyAlg = string

export { AuthzOAuthPolicy } from './authz-oauth-policy.types'
export type { DPoPMode } from './authz-oauth-policy.types'

type DPoPProofContext = {
  proofJwt: string
  htm: string
  htu: string
  // Defaults to false. Set true when the endpoint requires a DPoP nonce challenge.
  nonceRequired?: boolean
}

type TokenRequestOptions = {
  [GrantType.AuthorizationCode]: {
    //TODO: Implement options for authorization code flow
    alg?: AuthzKeyAlg
    dpopProof?: DPoPProofContext
  }
  [GrantType.PreAuthorizedCode]: {
    ttlSec?: number
    alg?: AuthzKeyAlg
    dpopProof?: DPoPProofContext
  }
}

type AnyTokenRequestOptions =
  | TokenRequestOptions[GrantType.AuthorizationCode]
  | TokenRequestOptions[GrantType.PreAuthorizedCode]

type AccessTokenVerifyOptions = { alg?: AuthzKeyAlg }

type DPoPBoundAccessTokenVerifyOptions = AccessTokenVerifyOptions & {
  dpopProof: DPoPProofContext
}

export type AuthzFlow = {
  findAuthzServerMetadata(
    issuer: AuthorizationServerIssuer
  ): Promise<AuthorizationServerMetadata | null>
  createAuthzServerMetadata(
    metadata: AuthorizationServerMetadata,
    options?: { alg?: AuthzKeyAlg }
  ): Promise<void>
  findAuthzOAuthPolicy(issuer: AuthorizationServerIssuer): Promise<AuthzOAuthPolicy | null>
  createAuthzOAuthPolicy(
    issuer: AuthorizationServerIssuer,
    policy: AuthzOAuthPolicy
  ): Promise<void>
  createDpopNonceChallenge(ttlMs?: number): Promise<string>
  createAccessToken(
    authz: AuthorizationServerIssuer,
    tokenRequest: TokenRequest,
    options?: AnyTokenRequestOptions
    // biome-ignore lint/complexity/noBannedTypes: <explanation>
  ): Promise<Object>
  verifyAccessToken(
    authz: AuthorizationServerIssuer,
    accessToken: string,
    options?: AccessTokenVerifyOptions
  ): Promise<boolean>
  // Bearer access token verification. Returns the verified JWT payload for callers that need claims.
  verifyAccessTokenPayload(
    authz: AuthorizationServerIssuer,
    accessToken: string,
    options?: AccessTokenVerifyOptions
  ): Promise<JwtPayload>
  // DPoP-bound access token verification. Also verifies the DPoP proof and cnf.jkt binding.
  verifyDpopBoundAccessToken(
    authz: AuthorizationServerIssuer,
    accessToken: string,
    options: DPoPBoundAccessTokenVerifyOptions
  ): Promise<JwtPayload>
}

export const initializeAuthzFlow = (context: VcknotsContext): AuthzFlow => {
  const authz$ = context.providers.get('authz-server-metadata-store-provider')
  const authzOAuthPolicy$ = context.providers.get('authz-oauth-policy-store-provider')
  const codeStore$ = context.providers.get('pre-authorized-code-store-provider')
  const accessToken$ = context.providers.get('access-token-provider')
  const authzKey$ = context.providers.get('authz-signature-key-store-provider')
  const dpopProof$ = context.providers.get('dpop-proof-provider')
  const dpopProofJtiStore$ = context.providers.get('dpop-proof-jti-store-provider')

  const verifyAccessTokenPayload = async (
    authz: AuthorizationServerIssuer,
    accessToken: string,
    options?: AccessTokenVerifyOptions
  ): Promise<JwtPayload> => {
    const [jwtHeader, jwtPayload, jwtSignature] = accessToken.split('.')
    if (!jwtHeader || !jwtPayload || !jwtSignature) {
      throw err('INVALID_ACCESS_TOKEN', {
        message: 'Access token is not a valid JWT.',
      })
    }

    let decodedHeader: { alg?: AuthzKeyAlg }
    let decodedPayload: JwtPayload
    try {
      decodedHeader = JSON.parse(base64url.decode(jwtHeader))
      decodedPayload = JSON.parse(base64url.decode(jwtPayload))
    } catch (error) {
      throw err('INVALID_ACCESS_TOKEN', {
        message:
          error instanceof Error
            ? `Access token is not a valid JWT. ${error.message}`
            : 'Access token is not a valid JWT.',
      })
    }

    const authzIssuer = AuthorizationServerIssuer(decodedPayload.iss)
    if (authzIssuer !== authz) {
      throw err('INVALID_ACCESS_TOKEN', {
        message: `Access token issuer ${authzIssuer} does not match the expected issuer ${authz}.`,
      })
    }
    const keyAlg = decodedHeader.alg ?? options?.alg ?? 'ES256'
    const publicKey = await authzKey$.fetch(authzIssuer, keyAlg)
    if (!publicKey) {
      throw err('AUTHZ_ISSUER_KEY_NOT_FOUND', {
        message: `Authorization server key for ${authzIssuer} not found.`,
      })
    }

    try {
      await jwtVerify(accessToken, publicKey, {
        issuer: decodedPayload.iss,
      })
    } catch {
      throw err('INVALID_ACCESS_TOKEN', {
        message: 'Access token verification failed.',
      })
    }
    return decodedPayload
  }

  const getCnfJkt = (payload: JwtPayload): string | undefined => {
    const cnf = payload.cnf
    if (cnf === null || typeof cnf !== 'object' || Array.isArray(cnf)) {
      return undefined
    }
    const jkt = (cnf as { jkt?: unknown }).jkt
    return typeof jkt === 'string' && jkt.trim().length > 0 ? jkt : undefined
  }

  const verifyDpopBoundAccessToken = async (
    authz: AuthorizationServerIssuer,
    accessToken: string,
    options: DPoPBoundAccessTokenVerifyOptions
  ): Promise<JwtPayload> => {
    const nonceRequired = options.dpopProof.nonceRequired ?? false

    // Validate in dependency order: access token, DPoP proof, optional nonce,
    // cnf.jkt binding, then jti replay. This avoids consuming nonce/jti before
    // the presented token and proof are structurally valid.
    const payload = await verifyAccessTokenPayload(authz, accessToken, options)
    const accessTokenJkt = getCnfJkt(payload)
    if (!accessTokenJkt) {
      throw err('INVALID_ACCESS_TOKEN', {
        message: 'DPoP-bound access token must contain cnf.jkt.',
      })
    }

    const verifiedDpopProof = await dpopProof$.verifyProof(options.dpopProof.proofJwt, {
      htm: options.dpopProof.htm,
      htu: options.dpopProof.htu,
      // Credential endpoint DPoP proofs must bind to the presented access token via `ath`.
      accessToken,
    } satisfies DPoPProofVerifyContext)

    if (nonceRequired) {
      const nonceStore$ = context.providers.get('nonce-store-provider')
      if (!verifiedDpopProof.nonce) {
        throw err('USE_DPOP_NONCE', {
          message: 'Credential issuer requires nonce in DPoP proof.',
        })
      }
      const consumed = await nonceStore$.consume(Nonce({ nonce: verifiedDpopProof.nonce }))
      if (!consumed) {
        throw err('USE_DPOP_NONCE', {
          message: 'Credential issuer requires nonce in DPoP proof.',
        })
      }
    }

    // Bind the access token to the DPoP proof key via cnf.jkt.
    if (verifiedDpopProof.jwkThumbprint !== accessTokenJkt) {
      throw err('INVALID_DPOP_PROOF', {
        message: 'DPoP proof public key does not match access token cnf.jkt.',
      })
    }

    // Reject replayed DPoP proofs by storing jti per proof public key thumbprint.
    // The cache TTL follows the proof validity window, so a jti is retained
    // while the corresponding proof could still pass iat/maxTokenAge validation.
    const isNewJti = await dpopProofJtiStore$.saveIfAbsent(
      verifiedDpopProof.jwkThumbprint,
      verifiedDpopProof.jti,
      { ttlMs: dpopProof$.proofJtiTtlMs }
    )
    if (!isNewJti) {
      throw err('INVALID_DPOP_PROOF', {
        message: 'DPoP proof JWT jti has already been used.',
      })
    }

    return payload
  }

  return {
    async findAuthzServerMetadata(issuer) {
      return await authz$.fetch(issuer)
    },
    async createAuthzServerMetadata(metadata, options) {
      const privateKeyAlg = options?.alg ?? 'ES256'
      const current = await authz$.fetch(metadata.issuer)
      if (current) {
        throw err('DUPLICATE_AUTHZ_SERVER', {
          message: `issuer ${metadata.issuer} is already registered.`,
        })
      }
      await authzKey$.save(metadata.issuer, privateKeyAlg)
      await authz$.save(metadata)
    },
    async findAuthzOAuthPolicy(issuer) {
      return await authzOAuthPolicy$.fetch(issuer)
    },
    async createAuthzOAuthPolicy(issuer, policy) {
      await authzOAuthPolicy$.save(issuer, policy)
    },
    async createDpopNonceChallenge(ttlMs) {
      const nonce$ = context.providers.get('nonce-provider')
      const nonceStore$ = context.providers.get('nonce-store-provider')
      const dpopNonce = await nonce$.generate({ nonce_expires_in: ttlMs })
      await nonceStore$.save(dpopNonce)
      return dpopNonce.nonce
    },
    async createAccessToken(authz, tokenRequest, options) {
      switch (tokenRequest.grant_type) {
        case 'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          const option = options as TokenRequestOptions[GrantType.PreAuthorizedCode]

          const verifiedDpopProof = option?.dpopProof
            ? await dpopProof$.verifyProof(option.dpopProof.proofJwt, {
                htm: option.dpopProof.htm,
                htu: option.dpopProof.htu,
              } satisfies DPoPProofVerifyContext)
            : undefined
          if (verifiedDpopProof) {
            if (option?.dpopProof?.nonceRequired) {
              const nonceStore$ = context.providers.get('nonce-store-provider')
              if (!verifiedDpopProof.nonce) {
                throw err('USE_DPOP_NONCE', {
                  message: 'Authorization server requires nonce in DPoP proof.',
                })
              }
              const nonce = Nonce({ nonce: verifiedDpopProof.nonce })
              const consumed = await nonceStore$.consume(nonce)
              if (!consumed) {
                throw err('USE_DPOP_NONCE', {
                  message: 'Authorization server requires nonce in DPoP proof.',
                })
              }
            }
            const isNewJti = await dpopProofJtiStore$.saveIfAbsent(
              verifiedDpopProof.jwkThumbprint,
              verifiedDpopProof.jti,
              { ttlMs: dpopProof$.proofJtiTtlMs }
            )
            if (!isNewJti) {
              throw err('INVALID_DPOP_PROOF', {
                message: 'DPoP proof JWT jti has already been used.',
              })
            }
          }
          // Check pre-code validity
          const isValid = await codeStore$.validate(
            tokenRequest['pre-authorized_code'],
            tokenRequest.tx_code
          )
          if (!isValid) {
            throw err('PRE_AUTHORIZED_CODE_NOT_FOUND', {
              message: 'The provided pre-authorized code is invalid.',
            })
          }
          // delete code from store
          await codeStore$.delete(tokenRequest['pre-authorized_code'])

          const keyAlg = options?.alg ?? 'ES256'
          // Authz access token (data)
          // for JWK privateKey
          const jwtHeader = {
            alg: keyAlg,
            typ: 'JWT',
          }
          const jwtPayload = await accessToken$.createTokenPayload(
            authz,
            tokenRequest['pre-authorized_code'],
            {
              ttlSec: option?.ttlSec,
              ...(verifiedDpopProof ? { cnf: { jkt: verifiedDpopProof.jwkThumbprint } } : {}),
            }
          )
          // sign with issuer private key
          const signature = await authzKey$.sign(authz, keyAlg, jwtPayload, jwtHeader)
          if (!signature) {
            throw err('INTERNAL_SERVER_ERROR', {
              message: 'Cannot sign access token.',
            })
          }
          // format JWT components
          const encode = (x: unknown) => base64url.encode(JSON.stringify(x))

          // Create Token Response
          return {
            access_token: `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`, // TODO: Implement access token generation
            token_type: verifiedDpopProof ? 'DPoP' : 'bearer',
            expires_in: option?.ttlSec ?? 86400,
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
    // Backward-compatible boolean API. Use verifyAccessTokenPayload when callers need claims.
    async verifyAccessToken(authz, accessToken: string, options): Promise<boolean> {
      await verifyAccessTokenPayload(authz, accessToken, options)
      return true
    },
    // Bearer access token verification. Use this when the caller needs JWT claims.
    verifyAccessTokenPayload: verifyAccessTokenPayload,
    // DPoP access token verification. Use this when Authorization scheme is DPoP.
    verifyDpopBoundAccessToken: verifyDpopBoundAccessToken,
  }
}

export {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from './authorization-server.types'
export { TokenRequest as AuthzTokenRequest } from './token-request.types'
