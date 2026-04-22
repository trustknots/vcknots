const supportedAuthorizationSchemes = ['bearer', 'dpop'] as const
type AuthorizationScheme = (typeof supportedAuthorizationSchemes)[number]

export type ParsedAuthorizationHeader = {
  scheme: AuthorizationScheme
  token: string
}

export type AuthorizationHeaderParseResult =
  | {
      ok: true
      value: ParsedAuthorizationHeader
    }
  | {
      ok: false
      reason: 'missing' | 'malformed' | 'unsupported_scheme'
      scheme?: string
    }

const authorizationHeaderPattern = /^(\S+)\s+(.+)$/
const isAuthorizationScheme = (value: string): value is AuthorizationScheme =>
  supportedAuthorizationSchemes.some((scheme) => scheme === value)

export const parseAuthorizationHeader = (
  headerValue?: string | null
): AuthorizationHeaderParseResult => {
  const trimmed = headerValue?.trim()
  if (!trimmed) {
    return { ok: false, reason: 'missing' }
  }

  const match = authorizationHeaderPattern.exec(trimmed)
  if (!match) {
    return { ok: false, reason: 'malformed' }
  }

  const [, scheme, token] = match
  const normalizedToken = token.trim()
  if (!normalizedToken) {
    return { ok: false, reason: 'malformed' }
  }

  const normalizedScheme = scheme.toLowerCase()
  if (!isAuthorizationScheme(normalizedScheme)) {
    return {
      ok: false,
      reason: 'unsupported_scheme',
      scheme,
    }
  }

  return {
    ok: true,
    value: {
      scheme: normalizedScheme,
      token: normalizedToken,
    },
  }
}
