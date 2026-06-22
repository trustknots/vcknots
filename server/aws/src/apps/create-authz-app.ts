import { createAuthzRouter } from '@trustknots/server-core/routes/authz'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createBaseApp } from './create-base-app.js'

export function createAuthzApp(options?: VcknotsOptions) {
  return createBaseApp(createAuthzRouter, options)
}
