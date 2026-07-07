import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dynamodbAuthzServerMetadataStore } from '@trustknots/aws'
import { createAuthzRouter } from '@trustknots/server-core/routes/authz'
import { AuthorizationServerIssuer, AuthorizationServerMetadata, initializeAuthzFlow } from '@trustknots/vcknots/authz'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createBaseApp } from './create-base-app.js'

export function createAuthzApp(options?: VcknotsOptions) {
  const tableName = process.env.AUTH_SERVERS_TABLE_NAME
  if (!tableName) {
    throw new Error('AUTH_SERVERS_TABLE_NAME is required')
  }

  const rawPort = process.env.AUTHZ_PORT ?? '8082'
  const port = Number.parseInt(rawPort, 10)
  if (!Number.isFinite(port)) throw new Error(`Invalid AUTHZ_PORT: "${rawPort}"`)

  const store = dynamodbAuthzServerMetadataStore({ tableName })
  const { app, context } = createBaseApp(
    createAuthzRouter,
    { port, baseUrl: process.env.AUTHZ_BASE_URL },
    { ...options, providers: [store, ...(options?.providers ?? [])] },
  )

  async function initialize(baseUrl: string) {
    const authzFlow = initializeAuthzFlow(context)

    const existing = await authzFlow.findAuthzServerMetadata(AuthorizationServerIssuer(baseUrl))
    if (existing) {
      console.log('Authz server metadata already exists, skipping initialization')
      return
    }

    const samplesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../samples')
    const sampleAuthzMetadata = JSON.parse(readFileSync(join(samplesDir, 'authorization_metadata.json'), 'utf-8'))
    const metadata = AuthorizationServerMetadata({
      ...sampleAuthzMetadata,
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
    })
    await authzFlow.createAuthzServerMetadata(metadata)
    console.log('Authz server metadata initialized')
  }

  return { app, initialize }
}
