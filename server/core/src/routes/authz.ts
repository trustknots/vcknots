import { VcknotsContext } from '@trustknots/vcknots'
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
      const request = await c.req.formData()
      const tokenRequest = AuthzTokenRequest(Object.fromEntries(request.entries()))
      const issuer = AuthorizationServerIssuer(baseUrl)
      const accessToken = await authzFlow.createAccessToken(issuer, tokenRequest)
      return c.json(accessToken)
    } catch (err) {
      const errorResponse = handleError(err)
      return c.json(errorResponse, 400)
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
      return c.json(handleError(err), 400)
    }
  })

  return authzApp
}
