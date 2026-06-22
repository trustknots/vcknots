import { dynamodbIssuerMetadataStore } from '@trustknots/aws'
import { createIssueRouter } from '@trustknots/server-core/routes/issue'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createRoleApp } from './create-role-app.js'

export function createIssuerApp(options?: VcknotsOptions) {
  const tableName = process.env.ISSUERS_TABLE_NAME
  if (!tableName) {
    throw new Error('ISSUERS_TABLE_NAME is required')
  }

  return createRoleApp(createIssueRouter, {
    ...options,
    providers: [dynamodbIssuerMetadataStore({ tableName }), ...(options?.providers ?? [])],
  })
}
