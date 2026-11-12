import { VerifierStateStoreProvider } from '../provider.types'

const DEFAULT_VERIFIER_STATE_TTL_MS = 5 * 60 * 1000

type StateEntry = {
  /** Undefined while `state` is only reserved. */
  transactionId?: string
  expiresAt: number
}

export const inMemoryVerifierStateStore = (): VerifierStateStoreProvider => {
  const states = new Map<string, StateEntry>()

  const cleanupExpired = (now: number) => {
    for (const [state, entry] of states) {
      if (now > entry.expiresAt) {
        states.delete(state)
      }
    }
  }

  return {
    kind: 'verifier-state-store-provider',
    name: 'in-memory-verifier-state-store-provider',
    single: true,

    async reserve(state, options): Promise<boolean> {
      const now = Date.now()
      cleanupExpired(now)

      if (states.has(state)) {
        return false
      }
      states.set(state, { expiresAt: now + (options?.ttlMs ?? DEFAULT_VERIFIER_STATE_TTL_MS) })
      return true
    },

    async register(state, transactionId, options): Promise<boolean> {
      const now = Date.now()
      cleanupExpired(now)

      if (states.get(state)?.transactionId !== undefined) {
        return false
      }
      states.set(state, {
        transactionId,
        expiresAt: now + (options?.ttlMs ?? DEFAULT_VERIFIER_STATE_TTL_MS),
      })
      return true
    },

    async take(state): Promise<string | null> {
      const entry = states.get(state)
      if (entry?.transactionId === undefined || Date.now() > entry.expiresAt) {
        return null
      }
      states.delete(state)
      return entry.transactionId
    },

    async consume(state): Promise<void> {
      states.delete(state)
    },
  }
}
