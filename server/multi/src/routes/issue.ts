import { VcknotsContext } from '@trustknots/vcknots'
import {
  CredentialConfigurationId,
  CredentialIssuer,
  CredentialRequest,
  initializeIssuerFlow,
} from '@trustknots/vcknots/issuer'
import {
  AuthorizationServerIssuer,
  initializeAuthzFlow,
  type CredentialEndpointAuthorizationContext,
} from '@trustknots/vcknots/authz'
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

      let authorizationContext: CredentialEndpointAuthorizationContext
      try {
        authorizationContext = await authzFlow.authorizeCredentialEndpointAccess(authz, {
          authorizationHeader: c.req.header('Authorization'),
          dpopHeader: c.req.header('DPoP'),
          htm: c.req.method,
          htu: `${issuer}/credentials`,
          nonceRequired: true,
        })
      } catch (err) {
        if (err instanceof VcknotsError && err.name === 'invalid_access_token') {
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
        if (err instanceof VcknotsError && err.name === 'invalid_dpop_proof') {
          return invalidDpopProof(c, realm, err.message)
        }
        if (err instanceof VcknotsError && err.name === 'use_dpop_nonce') {
          return dpopNonceResponse(c, realm)
        }
        throw err
      }
      const request = await c.req.json()
      const parse = CredentialRequest(request)
      // Issue Credential
      const credential = await issuerFlow.issueCredential(issuer, parse, authorizationContext, {
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
