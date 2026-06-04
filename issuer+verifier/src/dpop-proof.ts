import type { ParsedDpopHeader } from './dpop-proof.types'

const compactJwtPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/

/**
 * Parses the HTTP `DPoP` header value before cryptographic proof verification.
 *
 * This covers the RFC 9449 structural checks handled at the HTTP header layer:
 * - The DPoP header value must be present when required by the caller.
 * - Multiple DPoP header fields must not be accepted. HTTP recipients commonly
 *   combine duplicate header fields into a comma-separated value, so comma is
 *   treated as a duplicate-header signal here.
 * - The header value must be a single compact JWT string (`header.payload.signature`).
 */
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
