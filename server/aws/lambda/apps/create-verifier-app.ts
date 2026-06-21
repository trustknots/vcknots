import { createVerifierRouter } from '@trustknots/server-core/routes/verify'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createRoleApp } from './create-role-app.js'

export function createVerifierApp(options?: VcknotsOptions) {
  return createRoleApp(createVerifierRouter, options)
}
