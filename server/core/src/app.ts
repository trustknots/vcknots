import { VcknotsContext } from '@trustknots/vcknots'
import { showRoutes } from 'hono/dev'
import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { createAuthzRouter } from './routes/authz.js'
import { createIssueRouter } from './routes/issue.js'
import { createVerifierRouter } from './routes/verify.js'

export const createApp = (context: VcknotsContext, baseUrl: string) => {
  const app = new Hono()

  const options = {
    tx_code: {
      input_mode: 'numeric' as const,
      length: 6,
      description: 'Your transaction code for credential issuance',
    },
  }

  app.route('/', createIssueRouter(context, baseUrl, options))
  app.route('/', createAuthzRouter(context, baseUrl, options))
  app.route('/', createVerifierRouter(context, baseUrl))

  app.notFound((c) => c.json({ error: 'Not Found' }, 404))
  app.onError((err, c) => {
    if (err instanceof HTTPException) return err.getResponse()
    console.error(err)
    return c.json({ error: 'internal_server_error' }, 500)
  })

  showRoutes(app, { verbose: true })

  return app
}
