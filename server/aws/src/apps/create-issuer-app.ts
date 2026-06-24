import { dynamodbIssuerMetadataStore } from '@trustknots/aws'
import { createIssueRouter } from '@trustknots/server-core/routes/issue'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createBaseApp } from './create-base-app.js'

export function createIssuerApp(options?: VcknotsOptions) {
  const tableName = process.env.ISSUERS_TABLE_NAME
  if (!tableName) {
    throw new Error('ISSUERS_TABLE_NAME is required')
  }

  return createBaseApp(
    createIssueRouter,
    { port: Number.parseInt(process.env.ISSUER_PORT ?? '8081', 10), baseUrl: process.env.ISSUER_BASE_URL },
    { ...options, providers: [dynamodbIssuerMetadataStore({ tableName }), ...(options?.providers ?? [])] },
  )
}
