import { createAuthzRouter } from '@trustknots/server-core/routes/authz'
import { createBaseApp } from './create-base-app.js'

export function createAuthzApp() {
  const rawPort = process.env.AUTHZ_PORT ?? '8082'
  const port = Number.parseInt(rawPort, 10)
  if (!Number.isFinite(port)) throw new Error(`Invalid AUTHZ_PORT: "${rawPort}"`)
  return createBaseApp(
    createAuthzRouter,
    { port, baseUrl: process.env.AUTHZ_BASE_URL },
  )
}
