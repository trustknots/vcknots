import { VcknotsContext } from '@trustknots/vcknots'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialRequest,
  initializeIssuerFlow,
} from '@trustknots/vcknots/issuer'
import { AuthorizationServerIssuer, initializeAuthzFlow } from '@trustknots/vcknots/authz'
import { VcknotsError } from '@trustknots/vcknots/errors'
import { parseAuthorizationHeader } from '@trustknots/server-core/utils/authorization-header.js'
import { buildBearerAuthenticateHeader } from '@trustknots/server-core/utils/www-authenticate.js'
import { Context, Hono } from 'hono'
import { handleError } from '../utils/error-handler.js'
import { JwtPayload } from '@trustknots/vcknots'

export const createIssueRouter = (context: VcknotsContext, baseUrl: string) => {
  const issueApp = new Hono()

  const issuerFlow = initializeIssuerFlow(context)
  const authzFlow = initializeAuthzFlow(context)

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
      if (authorization.value.scheme === 'dpop') {
        return unauthorized(c, realm, {
          error: 'invalid_token',
          error_description: 'DPoP access tokens are not supported by this credential endpoint.',
        })
      }

      let accessTokenPayload: JwtPayload
      try {
        accessTokenPayload = await authzFlow.verifyAccessToken(authz, authorization.value.token)
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
        throw err
      }
      const request = await c.req.json()
      const parse = CredentialRequest(request)

      const allowedConfigurationIds = Array.isArray(accessTokenPayload.credential_configuration_ids)
        ? accessTokenPayload.credential_configuration_ids
        : []

      // Issue Credential
      const credential = await issuerFlow.issueCredential(issuer, parse, {
        alg: 'ES256',
        cnonce: {
          c_nonce_expires_in: 60 * 5 * 1000,
        },
        claims: issueClaimsSample,
        proofJwt: { usePreAuth: true },
        credentialConfigurationId: allowedConfigurationIds,
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
