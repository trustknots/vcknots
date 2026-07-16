import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  dynamodbIssuerMetadataStore,
  dynamodbNonceStore,
  dynamodbPreAuthorizedCodeStore,
} from '@trustknots/aws'
import { createIssueRouter } from '@trustknots/server-core/routes/issue'
import { CredentialIssuer, CredentialIssuerMetadata, initializeIssuerFlow } from '@trustknots/vcknots/issuer'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createBaseApp } from './create-base-app.js'

export function createIssuerApp(options?: VcknotsOptions) {
  const issuersTableName = process.env.ISSUERS_TABLE_NAME
  if (!issuersTableName) {
    throw new Error('ISSUERS_TABLE_NAME is required')
  }

  const noncesTableName = process.env.NONCES_TABLE_NAME
  if (!noncesTableName) {
    throw new Error('NONCES_TABLE_NAME is required')
  }

  const preCodesTableName = process.env.PRE_CODES_TABLE_NAME
  if (!preCodesTableName) {
    throw new Error('PRE_CODES_TABLE_NAME is required')
  }

  const rawPort = process.env.ISSUER_PORT ?? '8081'
  const port = Number.parseInt(rawPort, 10)
  if (!Number.isFinite(port)) throw new Error(`Invalid ISSUER_PORT: "${rawPort}"`)

  const issuerMetadataStore = dynamodbIssuerMetadataStore({ tableName: issuersTableName })
  const nonceStore = dynamodbNonceStore({ tableName: noncesTableName })
  const preAuthorizedCodeStore = dynamodbPreAuthorizedCodeStore({ tableName: preCodesTableName })
  const { app, context } = createBaseApp(
    createIssueRouter,
    { port, baseUrl: process.env.ISSUER_BASE_URL },
    {
      ...options,
      providers: [
        issuerMetadataStore,
        nonceStore,
        preAuthorizedCodeStore,
        ...(options?.providers ?? []),
      ],
    },
  )

  async function initialize(baseUrl: string) {
    const issuerFlow = initializeIssuerFlow(context)

    const existing = await issuerFlow.findIssuerMetadata(CredentialIssuer(baseUrl))
    if (existing) {
      console.log('Issuer metadata already exists, skipping initialization')
      return
    }

    const samplesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../samples')
    const sampleIssuerMetadata = JSON.parse(readFileSync(join(samplesDir, 'issuer_metadata.json'), 'utf-8'))
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
