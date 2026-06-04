import { parseDpopHeader, resolveDpopMode, VcknotsContext } from '@trustknots/vcknots'
import { VcknotsError } from '@trustknots/vcknots/errors'
import {
  AuthorizationServerIssuer,
  AuthzTokenRequest,
  initializeAuthzFlow,
} from '@trustknots/vcknots/authz'
import { Context, Hono } from 'hono'
import { handleError } from '../utils/error-handler.js'

const DPOP_NONCE_TTL_MS = 5 * 60 * 1000

export const createAuthzRouter = (context: VcknotsContext, baseUrl: string) => {
  const authzApp = new Hono()

  const authzFlow = initializeAuthzFlow(context)

  const dpopNonceResponse = async (c: Context) => {
    const dpopNonce = await authzFlow.createDpopNonceChallenge(DPOP_NONCE_TTL_MS)
    c.header('DPoP-Nonce', dpopNonce)
    return c.json(
      {
        error: 'use_dpop_nonce',
        error_description: 'Authorization server requires nonce in DPoP proof.',
      },
      400
    )
  }

  authzApp.post('/:issuer/token', async (c) => {
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

      const issuer = c.req.param('issuer')
      const authz = AuthorizationServerIssuer(issuer)
      const request = await c.req.formData()
      const tokenRequest = AuthzTokenRequest(Object.fromEntries(request.entries()))
      const accessToken = await authzFlow.createAccessToken(authz, tokenRequest, {
        ...(dpopMode !== 'off' && dpopProof.ok
          ? {
              dpopProof: {
                proofJwt: dpopProof.proofJwt,
                htm: c.req.method,
                htu: `${baseUrl}/authorizations/${encodeURIComponent(issuer)}/token`,
                nonceRequired: true,
              },
            }
          : {}),
      })
      return c.json(accessToken)
    } catch (err) {
      if (err instanceof VcknotsError && err.name === 'invalid_dpop_proof') {
        return c.json(
          {
            error: 'invalid_dpop_proof',
            error_description: err.message,
          },
          400
        )
      }
      if (err instanceof VcknotsError && err.name === 'use_dpop_nonce') {
        return dpopNonceResponse(c)
      }
      const errorResponse = handleError(err)
      return c.json(errorResponse, 400)
    }
  })

  authzApp.get('/:issuer/.well-known/oauth-authorization-server', async (c) => {
    try {
      const authz = AuthorizationServerIssuer(c.req.param('issuer'))
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
      return c.json(handleError(err), 400)
    }
  })

  return authzApp
}
