import { createAuthzRouter } from '@trustknots/server-core/routes/authz'
import { createBaseApp } from './create-base-app.js'

export function createAuthzApp() {
  const port = Number.parseInt(process.env.AUTHZ_PORT ?? '8082', 10)
  if (Number.isNaN(port)) throw new Error('AUTHZ_PORT must be a valid integer')
  return createBaseApp(
    createAuthzRouter,
    { port, baseUrl: process.env.AUTHZ_BASE_URL },
  )
}
