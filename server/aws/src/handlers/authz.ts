import { handle } from 'hono/aws-lambda'
import { createAuthzApp } from '../apps/create-authz-app.js'

const { app } = createAuthzApp()

export { app }
export const handler = handle(app)
