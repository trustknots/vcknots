import { createVerifierRouter } from '@trustknots/server-core/routes/verify'
import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { handle } from 'hono/aws-lambda'
import { createVcknotsContext, getBaseUrl } from '../context/vcknots-context.js'

const options = {
  // TODO: @trustknots/aws provider（DynamoDB/KMS/Secrets Manager など）が揃ったらここに差し替える
}

const context = createVcknotsContext(options)
const baseUrl = getBaseUrl()

const app = new Hono()
app.route('/', createVerifierRouter(context, baseUrl))
app.notFound((c) => c.json({ error: 'Not Found' }, 404))
app.onError((err, c) => {
  if (err instanceof HTTPException) return err.getResponse()
  console.error(err)
  return c.json({ error: 'internal_server_error' }, 500)
})

export const handler = handle(app)
