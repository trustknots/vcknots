import { initializeContext } from '@trustknots/vcknots'
import type { VcknotsOptions } from '@trustknots/vcknots'

export function createVcknotsContext(options?: VcknotsOptions) {
  return initializeContext({
    ...options,
    debug: process.env.NODE_ENV !== 'production',
  })
}

export function getBaseUrl({ port = 8080, baseUrl = `http://localhost:${port}` }: { port?: number; baseUrl?: string } = {}) {
  const apiId = process.env.API_GATEWAY_ID
  const region = process.env.AWS_REGION
  const stage = process.env.API_STAGE ?? 'test'

  if (apiId && region) {
    return `https://${apiId}.execute-api.${region}.amazonaws.com/${stage}`
  }

  return baseUrl
}
