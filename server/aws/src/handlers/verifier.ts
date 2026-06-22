import { handle } from 'hono/aws-lambda'
import { createVerifierApp } from '../apps/create-verifier-app.js'

const { app } = createVerifierApp()

export { app }
export const handler = handle(app)
