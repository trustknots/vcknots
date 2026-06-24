import { createVerifierRouter } from '@trustknots/server-core/routes/verify'
import { createBaseApp } from './create-base-app.js'

export function createVerifierApp() {
  const port = Number.parseInt(process.env.VERIFIER_PORT ?? '8083', 10)
  if (Number.isNaN(port)) throw new Error('VERIFIER_PORT must be a valid integer')
  return createBaseApp(
    createVerifierRouter,
    { port, baseUrl: process.env.VERIFIER_BASE_URL },
  )
}
