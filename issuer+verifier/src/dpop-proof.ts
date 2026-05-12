import type { ParsedDpopHeader } from './dpop-proof.types'

const compactJwtPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/

export const parseDpopHeader = (headerValue?: string | null): ParsedDpopHeader => {
  const trimmed = headerValue?.trim()
  if (!trimmed) {
    return { ok: false, reason: 'missing' }
  }

  // Duplicate DPoP header fields are combined into a comma-separated value by HTTP recipients.
  if (trimmed.includes(',')) {
    return { ok: false, reason: 'duplicate' }
  }

  if (!compactJwtPattern.test(trimmed)) {
    return { ok: false, reason: 'malformed' }
  }

  return { ok: true, proofJwt: trimmed }
}
