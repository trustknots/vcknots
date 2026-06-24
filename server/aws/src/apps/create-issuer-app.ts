import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dynamodbIssuerMetadataStore } from '@trustknots/aws'
import { createIssueRouter } from '@trustknots/server-core/routes/issue'
import { CredentialIssuer, CredentialIssuerMetadata, initializeIssuerFlow } from '@trustknots/vcknots/issuer'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createBaseApp } from './create-base-app.js'
import { createVcknotsContext } from '../context/vcknots-context.js'

export function createIssuerApp(options?: VcknotsOptions) {
  const tableName = process.env.ISSUERS_TABLE_NAME
  if (!tableName) {
    throw new Error('ISSUERS_TABLE_NAME is required')
  }

  const port = Number.parseInt(process.env.ISSUER_PORT ?? '8081', 10)
  if (Number.isNaN(port)) throw new Error('ISSUER_PORT must be a valid integer')

  const store = dynamodbIssuerMetadataStore({ tableName })
  const { app } = createBaseApp(
    createIssueRouter,
    { port, baseUrl: process.env.ISSUER_BASE_URL },
    { ...options, providers: [store, ...(options?.providers ?? [])] },
  )

  async function initialize(baseUrl: string) {
    const existing = await store.fetch(CredentialIssuer(baseUrl))
    if (existing) {
      console.log('Issuer metadata already exists, skipping initialization')
      return
    }

    const samplesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../samples')
    const sampleIssuerMetadata = JSON.parse(readFileSync(join(samplesDir, 'issuer_metadata.json'), 'utf-8'))

    const context = createVcknotsContext({ ...options, providers: [store, ...(options?.providers ?? [])] })
    const issuerFlow = initializeIssuerFlow(context)
    const metadata = CredentialIssuerMetadata({
      ...sampleIssuerMetadata,
      credential_issuer: baseUrl,
      authorization_servers: [baseUrl],
      credential_endpoint: `${baseUrl}/credentials`,
      deferred_credential_endpoint: `${baseUrl}/deferred_credential`,
      nonce_endpoint: `${baseUrl}/nonce`,
    })
    await issuerFlow.createIssuerMetadata(metadata)
    console.log('Issuer metadata initialized')
  }

  return { app, initialize }
}
