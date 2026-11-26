import { createHash, randomUUID } from 'node:crypto'
import { DirectPostVpAudTransactionStore } from '@trustknots/server-core'
import { FirestoreProviderOptions } from '@trustknots/google-cloud'
import { getFirestore, Timestamp, Transaction } from 'firebase-admin/firestore'

const DEFAULT_TTL_MS = 5 * 60 * 1000

type StoredState = {
  state: string
  transactionId: string
  reservationToken: string
  expires_at: Timestamp
  status: 'reserved' | 'registered' | 'processing'
}

const stateToDocId = (state: string) => createHash('sha256').update(state).digest('hex')

const errorResult = (error_description: string) => ({
  ok: false as const,
  error: { error: 'invalid_request', error_description },
})

export const createFirestoreStateStore = (
  options?: FirestoreProviderOptions & { ttlMs?: number; verifierUrl?: string }
): DirectPostVpAudTransactionStore => {
  const db = options?.app
    ? options.databaseId
      ? getFirestore(options.app, options.databaseId)
      : getFirestore(options.app)
    : options?.databaseId
      ? getFirestore(options.databaseId)
      : getFirestore()

  try {
    db.settings({ ignoreUndefinedProperties: true })
  } catch (cause) {
    if (!(cause instanceof Error) || !cause.message.includes('already been initialized')) {
      throw cause
    }
  }

  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots-server'
  const ttlMs = options?.ttlMs ?? DEFAULT_TTL_MS
  const verifierPrefix = options?.verifierUrl
    ? `verifiers/${createHash('md5').update(options.verifierUrl).digest('base64url')}/`
    : ''

  const docRef = (state: string) =>
    db.doc(`${ns}/v1/${verifierPrefix}states/${stateToDocId(state)}`)

  const reserve = async (state: string) => {
    const ref = docRef(state)
    const reservationToken = randomUUID()

    try {
      await db.runTransaction(async (tx: Transaction) => {
        const doc = await tx.get(ref)
        const now = Date.now()
        if (doc.exists) {
          const data = doc.data() as StoredState
          if (now <= data.expires_at.toMillis()) {
            throw new Error('state_conflict')
          }
        }
        tx.set(ref, {
          state,
          transactionId: '',
          reservationToken,
          expires_at: Timestamp.fromMillis(now + ttlMs),
          status: 'reserved',
        })
      })
      return { ok: true as const, reservationToken }
    } catch (err) {
      if (err instanceof Error && err.message === 'state_conflict') {
        return errorResult('state is already in use for an active presentation transaction')
      }
      throw err
    }
  }

  const register = async (state: string, transactionId: string, reservationToken: string) => {
    const ref = docRef(state)

    try {
      await db.runTransaction(async (tx: Transaction) => {
        const doc = await tx.get(ref)
        const now = Date.now()
        if (!doc.exists) {
          throw new Error('register_failed')
        }
        const data = doc.data() as StoredState
        if (
          now > data.expires_at.toMillis() ||
          data.status !== 'reserved' ||
          data.reservationToken !== reservationToken
        ) {
          throw new Error('register_failed')
        }
        tx.set(ref, {
          state,
          transactionId,
          reservationToken,
          expires_at: Timestamp.fromMillis(now + ttlMs),
          status: 'registered',
        })
      })
      return { ok: true as const }
    } catch (err) {
      if (err instanceof Error && err.message === 'register_failed') {
        return errorResult('state is already in use for an active presentation transaction')
      }
      throw err
    }
  }

  const acquire = async (state: string | undefined) => {
    if (state == null || state.trim() === '') {
      return errorResult('state is required for VP audience validation')
    }

    const ref = docRef(state)

    type TxOutcome = { kind: 'acquired'; transactionId: string } | { kind: 'expired' }

    let outcome: TxOutcome
    try {
      outcome = await db.runTransaction(async (tx: Transaction): Promise<TxOutcome> => {
        const doc = await tx.get(ref)
        const now = Date.now()
        if (!doc.exists) throw new Error('acquire_failed')
        const data = doc.data() as StoredState
        if (now > data.expires_at.toMillis()) {
          tx.delete(ref)
          return { kind: 'expired' }
        }
        if (data.status !== 'registered') throw new Error('acquire_failed')
        tx.set(ref, { ...data, status: 'processing' })
        return { kind: 'acquired', transactionId: data.transactionId }
      })
    } catch (err) {
      if (err instanceof Error && err.message === 'acquire_failed') {
        return errorResult('unknown or expired state')
      }
      throw err
    }

    if (outcome.kind === 'expired') return errorResult('unknown or expired state')
    return { ok: true as const, transactionId: outcome.transactionId }
  }

  // verify transactionId before deleting to prevent wrong-generation delete
  const consume = async (state: string, transactionId: string) => {
    const ref = docRef(state)
    await db.runTransaction(async (tx: Transaction) => {
      const doc = await tx.get(ref)
      if (doc.exists) {
        const data = doc.data() as StoredState
        if (data.transactionId === transactionId) {
          tx.delete(ref)
        }
      }
    })
  }

  const release = async (state: string, reservationToken: string) => {
    const ref = docRef(state)
    await db.runTransaction(async (tx: Transaction) => {
      const doc = await tx.get(ref)
      if (doc.exists) {
        const data = doc.data() as StoredState
        if (data.status === 'reserved' && data.reservationToken === reservationToken) {
          tx.delete(ref)
        }
      }
    })
  }

  return { reserve, register, acquire, consume, release }
}
