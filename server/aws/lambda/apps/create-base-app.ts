import type { VcknotsContext, VcknotsOptions } from '@trustknots/vcknots'
import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { createVcknotsContext, getBaseUrl } from '../context/vcknots-context.js'
import { sanitizeError } from '../utils/error-logger.js'

type RouteFactory = (context: VcknotsContext, baseUrl: string) => Hono

export function createBaseApp(createRouter: RouteFactory, options?: VcknotsOptions) {
  const context = createVcknotsContext(options)
  const baseUrl = getBaseUrl()

  const app = new Hono()
  app.route('/', createRouter(context, baseUrl))
  app.notFound((c) => c.json({ error: 'Not Found' }, 404))
  app.onError((err, c) => {
    if (err instanceof HTTPException) return err.getResponse()
    console.error('Error occurred:', sanitizeError(err))
    return c.json({ error: 'internal_server_error' }, 500)
  })

  return { app, context, baseUrl }
}
