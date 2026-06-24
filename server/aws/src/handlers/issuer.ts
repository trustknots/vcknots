import 'dotenv/config'
import { serve } from '@hono/node-server'
import { handle } from 'hono/aws-lambda'
import { createIssuerApp } from '../apps/create-issuer-app.js'

const { app, initialize } = createIssuerApp()

export { app }
export const handler = handle(app)

if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  const port = Number.parseInt(process.env.ISSUER_PORT ?? '8081', 10)
  if (Number.isNaN(port)) throw new Error('ISSUER_PORT must be a valid integer')
  const baseUrl = process.env.ISSUER_BASE_URL ?? `http://localhost:${port}`
  await initialize(baseUrl)
  serve({ fetch: app.fetch, port }, () => {
    console.log(`Issuer is running on ${baseUrl}`)
  })
}
