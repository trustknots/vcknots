import { handle } from 'hono/aws-lambda'
import { createIssuerApp } from '../apps/create-issuer-app.js'

const { app } = createIssuerApp()

export { app }
export const handler = handle(app)
