import {
  parseAuthorizationHeader,
  parseDpopHeader,
  resolveDpopMode,
  VcknotsContext,
  parseCredentialConfigurationId,
} from '@trustknots/vcknots'
import {
  CredentialRequest,
  CredentialIssuer,
  initializeIssuerFlow,
} from '@trustknots/vcknots/issuer'
import { AuthorizationServerIssuer, initializeAuthzFlow } from '@trustknots/vcknots/authz'
import { VcknotsError } from '@trustknots/vcknots/errors'
import { Context, Hono } from 'hono'
import { handleError } from '../utils/error-handler.js'
import {
  buildBearerAuthenticateHeader,
  buildDpopAuthenticateHeader,
} from '../utils/www-authenticate.js'

const C_NONCE_TTL_MS = 2 * 60 * 1000
const DPOP_NONCE_TTL_MS = 5 * 60 * 1000

export const createIssueRouter = (context: VcknotsContext, baseUrl: string) => {
  const issueApp = new Hono()

  const issuerFlow = initializeIssuerFlow(context)
  const authzFlow = initializeAuthzFlow(context)
  const realm = baseUrl

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

  const dpopNonceResponse = async (c: Context) => {
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
    console.log('[credentials-route] DPoP nonce response', {
      headers: {
        'DPoP-Nonce': dpopNonce,
        'WWW-Authenticate': buildDpopAuthenticateHeader({
          realm,
          error: 'use_dpop_nonce',
          errorDescription,
        }),
      },
      payload: {
        error: 'use_dpop_nonce',
        error_description: errorDescription,
      },
    })
    return c.json(
      {
        error: 'use_dpop_nonce',
        error_description: errorDescription,
      },
      401
    )
  }

  const invalidDpopProof = (c: Context, errorDescription: string) => {
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

  issueApp.post('/configurations/:configuration/offer', async (c) => {
    try {
      const issuer = CredentialIssuer(baseUrl)
      const configurations = [parseCredentialConfigurationId(c.req.param('configuration'))]

      // It only accepts a domain as an argument
      const offer = await issuerFlow.offerCredential(issuer, configurations, {
        usePreAuth: true,
      })
      return c.text(
        `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`
      )
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  issueApp.post('/credentials', async (c) => {
    const issueClaimsSample = {
      given_name: 'test',
      family_name: 'taro',
      degree: '5',
      gpa: 'test',
      address: {
        country: 'fuga',
        region: 'xyz',
      },
    }

    try {
      const issuer = CredentialIssuer(baseUrl)
      const authz = AuthorizationServerIssuer(baseUrl)
      const dpopMode = resolveDpopMode(context.options)

      // Verify AccessToken
      const authorization = parseAuthorizationHeader(c.req.header('Authorization'))
      if (!authorization.ok) {
        return unauthorized(c, {
          error: 'invalid_token',
          error_description:
            authorization.reason === 'missing'
              ? 'Access token is required.'
              : 'Authorization header must use Bearer or DPoP scheme.',
        })
      }
      if (dpopMode === 'off' && (authorization.value.scheme === 'dpop' || c.req.header('DPoP'))) {
        return unauthorized(c, {
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
              dpopProof.reason === 'missing'
                ? 'DPoP proof JWT is required.'
                : dpopProof.reason === 'duplicate'
                  ? 'DPoP header must appear exactly once.'
                  : 'DPoP header must contain a compact JWT.'
            )
          }
          console.log('[credentials-route] verify DPoP-bound access token params', {
            authz,
            accessTokenLength: authorization.value.token.length,
            accessToken: authorization.value.token,
            dpopProof: {
              proofJwtLength: dpopProof.proofJwt.length,
              proofJwt: dpopProof.proofJwt,
              htm: c.req.method,
              htu: `${baseUrl}/credentials`,
              nonceRequired: true,
            },
          })
          await authzFlow.verifyDpopBoundAccessToken(authz, authorization.value.token, {
            dpopProof: {
              proofJwt: dpopProof.proofJwt,
              htm: c.req.method,
              htu: `${baseUrl}/credentials`,
              nonceRequired: true,
            },
          })
        } else {
          if (dpopMode === 'required') {
            return unauthorized(
              c,
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
              {
                error: 'invalid_token',
                error_description: 'DPoP-bound access token must be presented with DPoP scheme.',
              },
              { error: 'invalid_token' }
            )
          }
        }
      } catch (err) {
        if (err instanceof VcknotsError && err.name === 'invalid_access_token') {
          return unauthorized(
            c,
            {
              error: 'invalid_token',
              error_description: err.message,
            },
            { error: 'invalid_token' }
          )
        }
        if (err instanceof VcknotsError && err.name === 'invalid_dpop_proof') {
          return invalidDpopProof(c, err.message)
        }
        if (err instanceof VcknotsError && err.name === 'use_dpop_nonce') {
          return dpopNonceResponse(c)
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
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  issueApp.get('/.well-known/openid-credential-issuer', async (c) => {
    try {
      const issuer = CredentialIssuer(baseUrl)
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
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  issueApp.get('/.well-known/jwt-vc-issuer', async (c) => {
    try {
      const issuer = CredentialIssuer(baseUrl)
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
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })
  issueApp.post('/nonce', async (c) => {
    try {
      const cnonce = await issuerFlow.createNonce(C_NONCE_TTL_MS)
      const dpopMode = resolveDpopMode(context.options)
      const headers: Record<string, string> = {
        'Cache-Control': 'no-store',
      }
      const payload = {
        c_nonce: cnonce,
      }

      c.header('Cache-Control', 'no-store')
      if (dpopMode !== 'off') {
        const dpopNonce = await issuerFlow.createNonce(DPOP_NONCE_TTL_MS)
        headers['DPoP-Nonce'] = dpopNonce
        c.header('DPoP-Nonce', dpopNonce)
      }
      console.log('[nonce-route] response', {
        headers,
        payload,
      })
      return c.json(payload, 200)
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  issueApp.get('/nonce/:nonce', async (c) => {
    try {
      const nonce = c.req.param('nonce')
      const valid = await issuerFlow.validateNonce(nonce)
      return c.json({ valid })
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  issueApp.delete('/nonce/:nonce', async (c) => {
    try {
      const nonce = c.req.param('nonce')
      const deleted = await issuerFlow.revokeNonce(nonce)
      if (!deleted) {
        return c.json({ error: 'not_found', error_description: 'Nonce not found.' }, 404)
      }
      return c.json({ deleted: true }, 200)
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  return issueApp
}
