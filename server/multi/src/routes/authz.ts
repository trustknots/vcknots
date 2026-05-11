import { parseAuthorizationServerIssuer, VcknotsContext } from '@trustknots/vcknots'
import { AuthzTokenRequest, initializeAuthzFlow } from '@trustknots/vcknots/authz'
import { Hono } from 'hono'
import { handleError } from '../utils/error-handler.js'

export const createAuthzRouter = (context: VcknotsContext, baseUrl: string) => {
  const authzApp = new Hono()

  const authzFlow = initializeAuthzFlow(context)

  authzApp.post('/:issuer/token', async (c) => {
    try {
      const authz = parseAuthorizationServerIssuer(c.req.param('issuer'))
      const request = await c.req.formData()
      const tokenRequest = AuthzTokenRequest(Object.fromEntries(request.entries()))
      const accessToken = await authzFlow.createAccessToken(authz, tokenRequest)
      return c.json(accessToken)
    } catch (err) {
      const errorResponse = handleError(err)
      return c.json(errorResponse, 400)
    }
  })

  authzApp.get('/:issuer/.well-known/oauth-authorization-server', async (c) => {
    try {
      const authz = parseAuthorizationServerIssuer(c.req.param('issuer'))
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
