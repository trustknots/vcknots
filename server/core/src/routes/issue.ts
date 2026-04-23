import { VcknotsContext } from '@trustknots/vcknots'
import {
  CredentialConfigurationId,
  CredentialRequest,
  CredentialIssuer,
  initializeIssuerFlow,
} from '@trustknots/vcknots/issuer'
import { AuthorizationServerIssuer, initializeAuthzFlow } from '@trustknots/vcknots/authz'
import { VcknotsError } from '@trustknots/vcknots/errors'
import { Context, Hono } from 'hono'
import { parseAuthorizationHeader } from '../utils/authorization-header.js'
import { handleError } from '../utils/error-handler.js'
import { buildBearerAuthenticateHeader } from '../utils/www-authenticate.js'

export const createIssueRouter = (context: VcknotsContext, baseUrl: string) => {
  const issueApp = new Hono()

  const issuerFlow = initializeIssuerFlow(context)
  const authzFlow = initializeAuthzFlow(context)
  const realm = baseUrl

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

  issueApp.post('/configurations/:configuration/offer', async (c) => {
    try {
      const issuer = CredentialIssuer(baseUrl)
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
      if (authorization.value.scheme === 'dpop') {
        return unauthorized(c, {
          error: 'invalid_token',
          error_description: 'DPoP access tokens are not supported by this credential endpoint.',
        })
      }

      let isValid: boolean
      try {
        isValid = await authzFlow.verifyAccessToken(authz, authorization.value.token)
      } catch (err) {
        if (err instanceof VcknotsError && err.name === 'INVALID_ACCESS_TOKEN') {
          return unauthorized(
            c,
            {
              error: 'invalid_token',
              error_description: err.message,
            },
            { error: 'invalid_token' }
          )
        }
        throw err
      }
      if (!isValid) {
        return unauthorized(
          c,
          {
            error: 'invalid_token',
            error_description: 'Access token is invalid.',
          },
          { error: 'invalid_token' }
        )
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
      const NONCE_TTL_MS = 2 * 60 * 1000 // 2 minutes
      const cnonce = await issuerFlow.createNonce(NONCE_TTL_MS)
      c.header('Cache-Control', 'no-store')
      return c.json(
        {
          c_nonce: cnonce,
        },
        200
      )
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
