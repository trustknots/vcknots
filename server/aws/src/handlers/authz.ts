import 'dotenv/config'
import { serve } from '@hono/node-server'
import { handle } from 'hono/aws-lambda'
import { createAuthzApp } from '../apps/create-authz-app.js'

const { app } = createAuthzApp()

export { app }
export const handler = handle(app)

if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  const port = Number.parseInt(process.env.AUTHZ_PORT ?? '8082', 10)
  if (Number.isNaN(port)) throw new Error('AUTHZ_PORT must be a valid integer')
  const baseUrl = process.env.AUTHZ_BASE_URL ?? `http://localhost:${port}`
  serve({ fetch: app.fetch, port }, () => {
    console.log(`Authz is running on ${baseUrl}`)
  })
}
