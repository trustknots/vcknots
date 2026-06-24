import { createAuthzRouter } from '@trustknots/server-core/routes/authz'
import { createBaseApp } from './create-base-app.js'

export function createAuthzApp() {
  return createBaseApp(
    createAuthzRouter,
    { port: Number.parseInt(process.env.AUTHZ_PORT ?? '8082', 10), baseUrl: process.env.AUTHZ_BASE_URL },
  )
}
