import { VcknotsContext } from '@trustknots/vcknots'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialRequest,
  initializeIssuerFlow,
} from '@trustknots/vcknots/issuer'
import { AuthorizationServerIssuer, initializeAuthzFlow } from '@trustknots/vcknots/authz'
import { parseAuthorizationHeader } from '@trustknots/server-core/utils/authorization-header.js'
import { Hono } from 'hono'
import { handleError } from '../utils/error-handler.js'

export const createIssueRouter = (context: VcknotsContext, baseUrl: string) => {
  const issueApp = new Hono()

  const issuerFlow = initializeIssuerFlow(context)
  const authzFlow = initializeAuthzFlow(context)

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

      const request = await c.req.json()
      const parse = CredentialRequest(request)
      // Verify AccessToken
      const authorization = parseAuthorizationHeader(c.req.header('Authorization'))
      if (!authorization.ok) {
        return c.json(
          {
            error: 'invalid_token',
            error_description:
              authorization.reason === 'missing'
                ? 'Access token is required.'
                : 'Authorization header must use Bearer or DPoP scheme.',
          },
          401
        )
      }
      if (authorization.value.scheme === 'dpop') {
        return c.json(
          {
            error: 'invalid_token',
            error_description: 'DPoP access tokens are not supported by this credential endpoint.',
          },
          401
        )
      }

      const isValid = await authzFlow.verifyAccessToken(authz, authorization.value.token)
      console.log('isValid:', isValid)
      if (!isValid) {
        return c.json(
          {
            error: 'invalid_token',
            error_description: 'Access token is invalid.',
          },
          401
        )
      }
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
