import { z } from 'zod'

/**
 * OID4VCI metadata endpoints must use https scheme.
 */
export const endpointUrlSchema = z.string().refine(
  (value) => {
    try {
      const url = new URL(value)

      if (url.protocol === 'https:') {
        return true
      }

      if (
        url.protocol === 'http:' &&
        (process.env.VCKNOTS_HTTP_ALLOWED === 'true' || process.env.VCKNOTS_DEBUG === 'true')
      ) {
        return true
      }

      return false
    } catch {
      return false
    }
  },
  { message: 'Must be a valid https URL' }
)
