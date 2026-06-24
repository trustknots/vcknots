import { createVerifierRouter } from '@trustknots/server-core/routes/verify'
import { createBaseApp } from './create-base-app.js'

export function createVerifierApp() {
  return createBaseApp(
    createVerifierRouter,
    { port: Number.parseInt(process.env.VERIFIER_PORT ?? '8083', 10), baseUrl: process.env.VERIFIER_BASE_URL },
  )
}
