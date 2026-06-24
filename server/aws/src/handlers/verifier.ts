import 'dotenv/config'
import { serve } from '@hono/node-server'
import { handle } from 'hono/aws-lambda'
import { createVerifierApp } from '../apps/create-verifier-app.js'

const { app } = createVerifierApp()

export { app }
export const handler = handle(app)

if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  const port = Number.parseInt(process.env.VERIFIER_PORT ?? '8083', 10)
  if (Number.isNaN(port)) throw new Error('VERIFIER_PORT must be a valid integer')
  const baseUrl = process.env.VERIFIER_BASE_URL ?? `http://localhost:${port}`
  serve({ fetch: app.fetch, port }, () => {
    console.log(`Verifier is running on ${baseUrl}`)
  })
}
