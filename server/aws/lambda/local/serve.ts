import { serve } from '@hono/node-server'
import type { Hono } from 'hono'

export function serveApp(app: Hono, label: string, defaultPort: number) {
  const port = Number.parseInt(process.env.PORT ?? String(defaultPort), 10)
  const baseUrl = process.env.BASE_URL ?? `http://localhost:${port}`

  serve({ fetch: app.fetch, port }, () => {
    console.log(`${label} is running on ${baseUrl}`)
  })
}
