import {
  parseAuthorizationHeader,
  parseDpopHeader,
  VcknotsContext,
} from '@trustknots/vcknots'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialRequest,
  initializeIssuerFlow,
} from '@trustknots/vcknots/issuer'
import { AuthorizationServerIssuer, initializeAuthzFlow } from '@trustknots/vcknots/authz'
import { VcknotsError } from '@trustknots/vcknots/errors'
import {
  buildBearerAuthenticateHeader,
  buildDpopAuthenticateHeader,
} from '@trustknots/server-core/utils/www-authenticate.js'
import { Context, Hono } from 'hono'
import { handleError } from '../utils/error-handler.js'

const DPOP_NONCE_TTL_MS = 5 * 60 * 1000

export const createIssueRouter = (context: VcknotsContext, baseUrl: string) => {
  const issueApp = new Hono()

  const issuerFlow = initializeIssuerFlow(context)
  const authzFlow = initializeAuthzFlow(context)

  const hasCnfJkt = (payload: unknown) => {
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
      return false
    }
    const cnf = (payload as { cnf?: unknown }).cnf
    if (cnf === null || typeof cnf !== 'object' || Array.isArray(cnf)) {
      return false
    }
    return typeof (cnf as { jkt?: unknown }).jkt === 'string'
  }

  const unauthorized = (
    c: Context,
    realm: string,
    body: { error: string; error_description: string },
    challenge: { error?: 'invalid_request' | 'invalid_token' | 'insufficient_scope' } = {}
  ) => {
    c.header(
      'WWW-Authenticate',
      buildBearerAuthenticateHeader({
        realm,
        error: challenge.error,
        errorDescription: challenge.error ? body.error_description : undefined,
      })
    )
    return c.json(body, 401)
  }

  const dpopNonceResponse = async (c: Context, realm: string) => {
    const dpopNonce = await authzFlow.createDpopNonceChallenge(DPOP_NONCE_TTL_MS)
    const errorDescription = 'Credential issuer requires nonce in DPoP proof.'
    c.header('DPoP-Nonce', dpopNonce)
    c.header(
      'WWW-Authenticate',
      buildDpopAuthenticateHeader({
        realm,
        error: 'use_dpop_nonce',
        errorDescription,
      })
    )
    return c.json(
      {
        error: 'use_dpop_nonce',
        error_description: errorDescription,
      },
      401
    )
  }

  const invalidDpopProof = (c: Context, realm: string, errorDescription: string) => {
    c.header(
      'WWW-Authenticate',
      buildDpopAuthenticateHeader({
        realm,
        error: 'invalid_dpop_proof',
        errorDescription,
      })
    )
    return c.json(
      {
        error: 'invalid_dpop_proof',
        error_description: errorDescription,
      },
      401
    )
  }

  issueApp.post('/:issuer/configurations/:configuration/offer', async (c) => {
    try {
      const issuer = CredentialIssuer(c.req.param('issuer'))
      const configurations = [CredentialConfigurationId(c.req.param('configuration'))]

      // It only accepts a domain as an argument
      const offer = await issuerFlow.offerCredential(issuer, configurations, {
        usePreAuth: true,
      })
      return c.text(
        `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`
      )
    } catch (err) {
      const errorResponse = handleError(err)
      return c.json(errorResponse, 400)
    }
  })

  issueApp.post('/:issuer/credentials', async (c) => {
    const issueClaimsSample = {
      given_name: 'test',
      family_name: 'taro',
      degree: '5',
      gpa: 'test',
    }

    try {
      const issuer = CredentialIssuer(c.req.param('issuer'))
      const authz = AuthorizationServerIssuer(c.req.param('issuer'))
      const realm = c.req.param('issuer')
      const dpopMode = await authzFlow.resolveAuthzPolicyDpopMode(authz, 'default_client')

      // Verify AccessToken
      const authorization = parseAuthorizationHeader(c.req.header('Authorization'))
      if (!authorization.ok) {
        return unauthorized(c, realm, {
          error: 'invalid_token',
          error_description:
            authorization.reason === 'missing'
              ? 'Access token is required.'
              : 'Authorization header must use Bearer or DPoP scheme.',
        })
      }
      if (dpopMode === 'off' && (authorization.value.scheme === 'dpop' || c.req.header('DPoP'))) {
        return unauthorized(c, realm, {
          error: 'invalid_token',
          error_description: 'DPoP access tokens are not supported by this credential endpoint.',
        })
      }

      try {
        if (authorization.value.scheme === 'dpop') {
          const dpopProof = parseDpopHeader(c.req.header('DPoP'))
          if (!dpopProof.ok) {
            return invalidDpopProof(
              c,
              realm,
              dpopProof.reason === 'missing'
                ? 'DPoP proof JWT is required.'
                : dpopProof.reason === 'duplicate'
                  ? 'DPoP header must appear exactly once.'
                  : 'DPoP header must contain a compact JWT.'
            )
          }
          await authzFlow.verifyDpopBoundAccessToken(authz, authorization.value.token, {
            dpopProof: {
              proofJwt: dpopProof.proofJwt,
              htm: c.req.method,
              htu: `${issuer}/credentials`,
              nonceRequired: true,
            },
          })
        } else {
          if (dpopMode === 'required') {
            return unauthorized(
              c,
              realm,
              {
                error: 'invalid_token',
                error_description: 'DPoP access token is required.',
              },
              { error: 'invalid_token' }
            )
          }
          const accessTokenPayload = await authzFlow.verifyAccessTokenPayload(
            authz,
            authorization.value.token
          )
          if (hasCnfJkt(accessTokenPayload)) {
            return unauthorized(
              c,
              realm,
              {
                error: 'invalid_token',
                error_description:
                  'DPoP-bound access token must be presented with DPoP scheme.',
              },
              { error: 'invalid_token' }
            )
          }
        }
      } catch (err) {
        if (err instanceof VcknotsError && err.name === 'INVALID_ACCESS_TOKEN') {
          return unauthorized(
            c,
            realm,
            {
              error: 'invalid_token',
              error_description: err.message,
            },
            { error: 'invalid_token' }
          )
        }
        if (err instanceof VcknotsError && err.name === 'INVALID_DPOP_PROOF') {
          return invalidDpopProof(c, realm, err.message)
        }
        if (err instanceof VcknotsError && err.name === 'USE_DPOP_NONCE') {
          return dpopNonceResponse(c, realm)
        }
        throw err
      }
      const request = await c.req.json()
      const parse = CredentialRequest(request)
      // Issue Credential
      const credential = await issuerFlow.issueCredential(issuer, parse, {
        alg: 'ES256',
        cnonce: {
          c_nonce_expires_in: 60 * 5 * 1000,
        },
        claims: issueClaimsSample,
        proofJwt: { usePreAuth: true },
      })
      return c.json(credential)
    } catch (err) {
      const errorResponse = handleError(err)
      return c.json(errorResponse, 400)
    }
  })

  issueApp.get('/:issuer/.well-known/openid-credential-issuer', async (c) => {
    try {
      const issuer = CredentialIssuer(c.req.param('issuer'))
      const metadata = await issuerFlow.findIssuerMetadata(issuer)
      if (!metadata) {
        return c.json(
          {
            error: 'not_found',
            error_description: 'Credential issuer metadata not found.',
          },
          404
        )
      }
      return c.json(metadata)
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })

  issueApp.get('/:issuer/.well-known/jwt-vc-issuer', async (c) => {
    try {
      const issuer = CredentialIssuer(c.req.param('issuer'))
      const metadata = await issuerFlow.findJwtVcIssuerMetadata(issuer)
      if (!metadata) {
        return c.json(
          {
            error: 'not_found',
            error_description: 'Credential issuer metadata not found.',
          },
          404
        )
      }
      return c.json(metadata)
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })

  return issueApp
}
