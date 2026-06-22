import { createVerifierRouter } from '@trustknots/server-core/routes/verify'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createBaseApp } from './create-base-app.js'

export function createVerifierApp(options?: VcknotsOptions) {
  return createBaseApp(createVerifierRouter, options)
}
