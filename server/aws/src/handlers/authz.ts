import 'dotenv/config'
import { serve } from '@hono/node-server'
import { handle } from 'hono/aws-lambda'
import { createAuthzApp } from '../apps/create-authz-app.js'

const { app } = createAuthzApp()

export { app }
export const handler = handle(app)

if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  const rawPort = process.env.AUTHZ_PORT ?? '8082'
  const port = Number.parseInt(rawPort, 10)
  if (!Number.isFinite(port)) throw new Error(`Invalid AUTHZ_PORT: "${rawPort}"`)
  const baseUrl = process.env.AUTHZ_BASE_URL ?? `http://localhost:${port}`
  serve({ fetch: app.fetch, port }, () => {
    console.log(`Authz is running on ${baseUrl}`)
  })
}
