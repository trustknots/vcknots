import { parseDpopHeader, resolveDpopMode, VcknotsContext } from '@trustknots/vcknots'
import { VcknotsError } from '@trustknots/vcknots/errors'
import {
  AuthorizationServerIssuer,
  AuthzTokenRequest,
  initializeAuthzFlow,
} from '@trustknots/vcknots/authz'
import { Hono } from 'hono'
import { handleError } from '../utils/error-handler.js'

export const createAuthzRouter = (context: VcknotsContext, baseUrl: string) => {
  const authzApp = new Hono()

  const authzFlow = initializeAuthzFlow(context)

  authzApp.post('/token', async (c) => {
    try {
      const dpopMode = resolveDpopMode(context.options)
      const dpopProof = parseDpopHeader(c.req.header('DPoP'))
      if (
        (dpopMode === 'required' && !dpopProof.ok) ||
        (dpopMode !== 'off' && !dpopProof.ok && dpopProof.reason !== 'missing')
      ) {
        return c.json(
          {
            error: 'invalid_request',
            error_description:
              dpopProof.reason === 'missing'
                ? 'DPoP proof JWT is required.'
                : dpopProof.reason === 'duplicate'
                  ? 'DPoP header must appear exactly once.'
                  : 'DPoP header must contain a compact JWT.',
          },
          400
        )
      }

      const request = await c.req.formData()
      const tokenRequest = AuthzTokenRequest(Object.fromEntries(request.entries()))
      const issuer = AuthorizationServerIssuer(baseUrl)
      const accessToken = await authzFlow.createAccessToken(issuer, tokenRequest, {
        ...(dpopMode !== 'off' && dpopProof.ok
          ? {
              dpopProof: {
                proofJwt: dpopProof.proofJwt,
                htm: c.req.method,
                htu: `${baseUrl}/token`,
              },
            }
          : {}),
      })
      return c.json(accessToken)
    } catch (err) {
      if (err instanceof VcknotsError && err.name === 'INVALID_DPOP_PROOF') {
        return c.json(
          {
            error: 'invalid_dpop_proof',
            error_description: err.message,
          },
          400
        )
      }
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  authzApp.get('/.well-known/oauth-authorization-server', async (c) => {
    try {
      const authz = AuthorizationServerIssuer(baseUrl)
      const metadata = await authzFlow.findAuthzServerMetadata(authz)
      if (!metadata) {
        return c.json(
          {
            error: 'not_found',
            error_description: 'Authorization server metadata not found.',
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

  return authzApp
}
