import { VcknotsContext } from '@trustknots/vcknots'
import {
  AuthorizationServerIssuer,
  AuthzTokenRequest,
  initializeAuthzFlow,
} from '@trustknots/vcknots/authz'
import { Hono } from 'hono'
import { handleError } from '../utils/error-handler.js'
import { RouteTypesOptions } from './routes.options.types.js'

export const createAuthzRouter = (
  context: VcknotsContext,
  baseUrl: string,
  options?: RouteTypesOptions
) => {
  const authzApp = new Hono()

  const authzFlow = initializeAuthzFlow(context)

  authzApp.post('/token', async (c) => {
    try {
      const request = await c.req.formData()
      let requestData: Record<string, string | File | number> = Object.fromEntries(
        request.entries()
      )

      if (options?.tx_code?.input_mode !== 'text' && requestData.tx_code) {
        const numericTxCode = parseInt(requestData.tx_code as string, 10)
        if (!isNaN(numericTxCode)) {
          requestData.tx_code = numericTxCode
        }
      }

      const tokenRequest = AuthzTokenRequest(requestData)
      const issuer = AuthorizationServerIssuer(baseUrl)
      const accessToken = await authzFlow.createAccessToken(issuer, tokenRequest)
      return c.json(accessToken)
    } catch (err) {
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
