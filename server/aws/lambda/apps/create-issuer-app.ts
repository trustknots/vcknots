import { createIssueRouter } from '@trustknots/server-core/routes/issue'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createRoleApp } from './create-role-app.js'

export function createIssuerApp(options?: VcknotsOptions) {
  return createRoleApp(createIssueRouter, options)
}
