import { OAuthClientAssertionJtiStoreProvider } from '../provider.types'

const DEFAULT_OAUTH_CLIENT_ASSERTION_JTI_TTL_MS = 5 * 60 * 1000

export const inMemoryOAuthClientAssertionJtiStore =
  (): OAuthClientAssertionJtiStoreProvider => {
    const usedJtis = new Map<string, number>()

    const toKey = (clientId: string, jti: string) => JSON.stringify([clientId, jti])
    const cleanupExpired = (now: number) => {
      for (const [key, expiresAt] of usedJtis) {
        if (now > expiresAt) {
          usedJtis.delete(key)
        }
      }
    }

    return {
      kind: 'oauth-client-assertion-jti-store-provider',
      name: 'in-memory-oauth-client-assertion-jti-store-provider',
      single: true,

      async saveIfAbsent(clientId, jti, options): Promise<boolean> {
        const key = toKey(clientId, jti)
        const now = Date.now()
        cleanupExpired(now)

        if (usedJtis.has(key)) {
          return false
        }

        usedJtis.set(key, now + (options?.ttlMs ?? DEFAULT_OAUTH_CLIENT_ASSERTION_JTI_TTL_MS))
        return true
      },
    }
  }
