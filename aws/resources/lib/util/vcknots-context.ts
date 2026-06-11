import { initializeContext } from '@trustknots/vcknots'
import type { VcknotsOptions } from '@trustknots/vcknots'

export function createVcknotsContext(options?: VcknotsOptions) {
  return initializeContext({
    ...options,
    debug: process.env.NODE_ENV !== 'production',
  })
}

export function getBaseUrl() {
  return process.env.BASE_URL ?? 'http://localhost:8080'
}
