import 'dotenv/config'
import { serve } from '@hono/node-server'
import { handle } from 'hono/aws-lambda'
import { createVerifierApp } from '../apps/create-verifier-app.js'

const { app, initialize } = createVerifierApp()

export { app }
export const handler = handle(app)

if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  const rawPort = process.env.VERIFIER_PORT ?? '8083'
  const port = Number.parseInt(rawPort, 10)
  if (!Number.isFinite(port)) throw new Error(`Invalid VERIFIER_PORT: "${rawPort}"`)
  const baseUrl = process.env.VERIFIER_BASE_URL ?? `http://localhost:${port}`
  await initialize(baseUrl)
  serve({ fetch: app.fetch, port }, () => {
    console.log(`Verifier is running on ${baseUrl}`)
  })
}
