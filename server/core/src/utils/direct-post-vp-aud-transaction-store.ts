import { randomUUID } from 'node:crypto'

/** Default TTL for in-memory `direct_post` state-to-transaction binding (5 minutes). */
export const DEFAULT_DIRECT_POST_STATE_TTL_MS = 5 * 60 * 1000

type StateTransaction = {
  transactionId: string
  reservationToken: string
  expiresAt: number
}

type OkWithToken = { ok: true; reservationToken: string }
type OkResult = { ok: true }
type ErrorResult = { ok: false; error: { error: string; error_description: string } }

export type DirectPostVpAudTransactionStore = {
  reserve: (state: string) => Promise<OkWithToken | ErrorResult>
  register: (
    state: string,
    transactionId: string,
    reservationToken: string
  ) => Promise<OkResult | ErrorResult>
  resolve: (state: string | undefined) => Promise<{ ok: true; transactionId: string } | ErrorResult>
  consume: (state: string, transactionId: string) => Promise<void>
  release: (state: string, reservationToken: string) => Promise<void>
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

  const sweepExpired = (): void => {
    const now = Date.now()
    for (const [key, val] of byState) {
      if (now > val.expiresAt) byState.delete(key)
    }
  }

  const reserve = async (state: string) => {
    sweepExpired()
    const existing = byState.get(state)
    if (existing !== undefined && Date.now() <= existing.expiresAt) {
      return {
        ok: false as const,
        error: {
          error: 'invalid_request',
          error_description: 'state is already in use for an active presentation transaction',
        },
      }
    }
    byState.delete(state)
    const reservationToken = randomUUID()
    byState.set(state, { transactionId: '', reservationToken, expiresAt: Date.now() + ttlMs })
    return { ok: true as const, reservationToken }
  }

  const register = async (state: string, transactionId: string, reservationToken: string) => {
    const existing = byState.get(state)
    if (
      existing === undefined ||
      Date.now() > existing.expiresAt ||
      existing.transactionId !== '' ||
      existing.reservationToken !== reservationToken
    ) {
      return {
        ok: false as const,
        error: {
          error: 'invalid_request',
          error_description: 'state is already in use for an active presentation transaction',
        },
      }
    }
    byState.set(state, { transactionId, reservationToken, expiresAt: Date.now() + ttlMs })
    return { ok: true as const }
  }

  const resolve = async (state: string | undefined) => {
    if (state == null || state.trim() === '') {
      return {
        ok: false as const,
        error: {
          error: 'invalid_request',
          error_description: 'state is required for VP audience validation',
        },
      }
    }
    const rec = byState.get(state)
    if (rec === undefined) {
      return {
        ok: false as const,
        error: { error: 'invalid_request', error_description: 'unknown or expired state' },
      }
    }
    if (Date.now() > rec.expiresAt) {
      byState.delete(state)
      return {
        ok: false as const,
        error: { error: 'invalid_request', error_description: 'unknown or expired state' },
      }
    }
    if (rec.transactionId === '') {
      return {
        ok: false as const,
        error: { error: 'invalid_request', error_description: 'unknown or expired state' },
      }
    }
    return { ok: true as const, transactionId: rec.transactionId }
  }

  const consume = async (state: string, transactionId: string): Promise<void> => {
    const existing = byState.get(state)
    if (existing?.transactionId === transactionId) {
      byState.delete(state)
    }
  }

  const release = async (state: string, reservationToken: string): Promise<void> => {
    const existing = byState.get(state)
    if (existing?.transactionId === '' && existing.reservationToken === reservationToken) {
      byState.delete(state)
    }
  }

  return { reserve, register, resolve, consume, release }
}
