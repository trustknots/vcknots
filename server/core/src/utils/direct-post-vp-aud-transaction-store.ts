/** Default TTL for in-memory `direct_post` state-to-transaction binding (10 minutes). */
export const DEFAULT_DIRECT_POST_STATE_TTL_MS = 5 * 60 * 1000

type StateTransaction = {
  transactionId: string
  expiresAt: number
}

export type DirectPostVpAudTransactionStore = {
  reserve: (
    state: string
  ) => { ok: true } | { ok: false; error: { error: string; error_description: string } }
  register: (
    state: string,
    transactionId: string
  ) => { ok: true } | { ok: false; error: { error: string; error_description: string } }
  resolve: (
    state: string | undefined
  ) =>
    | { ok: true; transactionId: string }
    | { ok: false; error: { error: string; error_description: string } }
  consume: (state: string) => void
}

/**
 * OpenID4VP `direct_post` state binding: maps the OAuth `state` parameter
 * (echoed by the wallet) back to the verifier transaction ID for VP validation.
 * `state` → `transactionId` lookup only; `clientId` and credential query are held by the library.
 */
export function createDirectPostVpAudTransactionStore(options?: {
  ttlMs?: number
}): DirectPostVpAudTransactionStore {
  const ttlMs = options?.ttlMs ?? DEFAULT_DIRECT_POST_STATE_TTL_MS
  const byState = new Map<string, StateTransaction>()

  const consume = (state: string): void => {
    byState.delete(state)
  }

  const sweepExpired = (): void => {
    const now = Date.now()
    for (const [key, val] of byState) {
      if (now > val.expiresAt) byState.delete(key)
    }
  }

  const reserve = (
    state: string
  ): { ok: true } | { ok: false; error: { error: string; error_description: string } } => {
    sweepExpired()
    const existing = byState.get(state)
    if (existing !== undefined) {
      if (Date.now() <= existing.expiresAt) {
        return {
          ok: false,
          error: {
            error: 'invalid_request',
            error_description: 'state is already in use for an active presentation transaction',
          },
        }
      }
      byState.delete(state)
    }
    byState.set(state, { transactionId: '', expiresAt: Date.now() + ttlMs })
    return { ok: true }
  }

  const register = (
    state: string,
    transactionId: string
  ): { ok: true } | { ok: false; error: { error: string; error_description: string } } => {
    const existing = byState.get(state)
    if (existing !== undefined) {
      const isReservation = existing.transactionId === ''
      if (!isReservation && Date.now() <= existing.expiresAt) {
        return {
          ok: false,
          error: {
            error: 'invalid_request',
            error_description: 'state is already in use for an active presentation transaction',
          },
        }
      }
      byState.delete(state)
    }
    byState.set(state, { transactionId, expiresAt: Date.now() + ttlMs })
    return { ok: true }
  }

  const resolve = (
    state: string | undefined
  ):
    | { ok: true; transactionId: string }
    | { ok: false; error: { error: string; error_description: string } } => {
    if (state == null || state.trim() === '') {
      return {
        ok: false,
        error: {
          error: 'invalid_request',
          error_description: 'state is required for VP audience validation',
        },
      }
    }
    const rec = byState.get(state)
    if (rec === undefined) {
      return {
        ok: false,
        error: { error: 'invalid_request', error_description: 'unknown or expired state' },
      }
    }
    if (Date.now() > rec.expiresAt) {
      consume(state)
      return {
        ok: false,
        error: { error: 'invalid_request', error_description: 'unknown or expired state' },
      }
    }
    if (rec.transactionId === '') {
      return {
        ok: false,
        error: { error: 'invalid_request', error_description: 'unknown or expired state' },
      }
    }
    return { ok: true, transactionId: rec.transactionId }
  }

  return { reserve, register, resolve, consume }
}
