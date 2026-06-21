import { createAuthzRouter } from '@trustknots/server-core/routes/authz'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createRoleApp } from './create-role-app.js'

export function createAuthzApp(options?: VcknotsOptions) {
  return createRoleApp(createAuthzRouter, options)
}
