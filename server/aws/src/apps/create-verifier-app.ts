import { createVerifierRouter } from '@trustknots/server-core/routes/verify'
import { createBaseApp } from './create-base-app.js'

export function createVerifierApp() {
  const rawPort = process.env.VERIFIER_PORT ?? '8083'
  const port = Number.parseInt(rawPort, 10)
  if (!Number.isFinite(port)) throw new Error(`Invalid VERIFIER_PORT: "${rawPort}"`)
  return createBaseApp(
    createVerifierRouter,
    { port, baseUrl: process.env.VERIFIER_BASE_URL },
  )
}
