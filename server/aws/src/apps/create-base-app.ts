import type { VcknotsContext, VcknotsOptions } from '@trustknots/vcknots'
import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { createVcknotsContext, getBaseUrl } from '../context/vcknots-context.js'
import { sanitizeError } from '../utils/error-logger.js'

type RouteFactory = (context: VcknotsContext, baseUrl: string) => Hono

export function createBaseApp(
  createRouter: RouteFactory,
  { port, baseUrl }: { port?: number; baseUrl?: string } = {},
  vcknots?: VcknotsOptions,
) {
  const context = createVcknotsContext(vcknots)
  const resolvedBaseUrl = getBaseUrl({ port, baseUrl })

  const app = new Hono()
  app.route('/', createRouter(context, resolvedBaseUrl))
  app.notFound((c) => c.json({ error: 'Not Found' }, 404))
  app.onError((err, c) => {
    if (err instanceof HTTPException) return err.getResponse()
    console.error('Error occurred:', sanitizeError(err))
    return c.json({ error: 'internal_server_error' }, 500)
  })

  return { app }
}
