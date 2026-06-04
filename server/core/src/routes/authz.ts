import { parseDpopHeader, VcknotsContext } from '@trustknots/vcknots'
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

  authzApp.post('/token', async (c) => {
    try {
      const request = await c.req.formData()
      const requestData: Record<string, string | File | number> = Object.fromEntries(
        request.entries()
      )
      const issuer = AuthorizationServerIssuer(baseUrl)
      const clientResolution = await authzFlow.resolveTokenRequestClientPolicy(
        issuer,
        requestData
      )
      if (!clientResolution.ok) {
        console.warn('[token-route] client authentication rejected', {
          error: clientResolution.error,
          error_description: clientResolution.error_description,
          ...clientResolution.log,
        })
        return c.json(
          {
            error: clientResolution.error,
            error_description: clientResolution.error_description,
          },
          400
        )
      }
      const dpopMode = clientResolution.dpopMode
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

      const tokenRequest = AuthzTokenRequest(requestData)
      const accessToken = await authzFlow.createAccessToken(issuer, tokenRequest, {
        clientId: clientResolution.clientId,
        ...(dpopMode !== 'off' && dpopProof.ok
          ? {
              dpopProof: {
                proofJwt: dpopProof.proofJwt,
                htm: c.req.method,
                htu: `${baseUrl}/token`,
                nonceRequired: true,
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
      if (err instanceof VcknotsError && err.name === 'USE_DPOP_NONCE') {
        return dpopNonceResponse(c)
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
