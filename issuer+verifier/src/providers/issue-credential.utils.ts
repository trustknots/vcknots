import { raise } from '../errors/vcknots.error'

const forbiddenPathSegments = new Set(['__proto__', 'constructor', 'prototype'])

export const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

export const assertSafePath = (path: string[]): void => {
  if (path.length === 0) {
    throw raise('invalid_claims', {
      message: 'Claim path must not be empty.',
    })
  }

  for (const segment of path) {
    if (forbiddenPathSegments.has(segment)) {
      throw raise('invalid_claims', {
        message: `Unsupported claim path segment: ${segment}`,
      })
    }
  }
}

export const getClaimValue = (claims: Record<string, unknown>, path: string[]): unknown => {
  assertSafePath(path)
  let current: unknown = claims
  for (const segment of path) {
    if (!isPlainObject(current) || !Object.prototype.hasOwnProperty.call(current, segment)) {
      return undefined
    }
    current = current[segment]
  }
  return current
}

export const setClaimValue = (
  target: Record<string, unknown>,
  path: string[],
  value: unknown
): void => {
  assertSafePath(path)
  let current = target
  for (const segment of path.slice(0, -1)) {
    const next = Object.prototype.hasOwnProperty.call(current, segment)
      ? current[segment]
      : undefined
    if (!isPlainObject(next)) {
      current[segment] = {}
    }
    current = current[segment] as Record<string, unknown>
  }
  current[path[path.length - 1]] = value
}
