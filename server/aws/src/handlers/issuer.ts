import { serve } from '@hono/node-server'
import { handle } from 'hono/aws-lambda'
import { createIssuerApp } from '../apps/create-issuer-app.js'

if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  await import('dotenv/config')
}

const { app, initialize } = createIssuerApp()

export { app }
export const handler = handle(app)

if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  const rawPort = process.env.ISSUER_PORT ?? '8081'
  const port = Number.parseInt(rawPort, 10)
  if (!Number.isFinite(port)) throw new Error(`Invalid ISSUER_PORT: "${rawPort}"`)
  const baseUrl = process.env.ISSUER_BASE_URL ?? `http://localhost:${port}`
  await initialize(baseUrl)
  serve({ fetch: app.fetch, port }, () => {
    console.log(`Issuer is running on ${baseUrl}`)
  })
}
