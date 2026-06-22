import 'dotenv/config'
import { serve } from '@hono/node-server'
import { handle } from 'hono/aws-lambda'
import { createIssuerApp } from '../apps/create-issuer-app.js'

const { app } = createIssuerApp()

export { app }
export const handler = handle(app)

if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  const port = Number.parseInt(process.env.PORT ?? '8081', 10)
  const baseUrl = process.env.BASE_URL ?? `http://localhost:${port}`
  serve({ fetch: app.fetch, port }, () => {
    console.log(`Issuer is running on ${baseUrl}`)
  })
}
