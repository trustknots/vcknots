import { createHash, randomUUID } from 'node:crypto'
import { DirectPostVpAudTransactionStore } from '@trustknots/server-core'
import { FirestoreProviderOptions } from '@trustknots/google-cloud'
import { getFirestore, Timestamp, Transaction } from 'firebase-admin/firestore'

const DEFAULT_TTL_MS = 5 * 60 * 1000

type StoredState = {
  transactionId: string
  reservationToken: string
  expiresAt: Timestamp
}

const stateToDocId = (state: string) => createHash('sha256').update(state).digest('hex')

const errorResult = (error_description: string) => ({
  ok: false as const,
  error: { error: 'invalid_request', error_description },
})

export const createFirestoreDirectPostStateStore = (
  options?: FirestoreProviderOptions & { ttlMs?: number }
): DirectPostVpAudTransactionStore => {
  // Fix #5: handle databaseId without app
  const db = options?.app
    ? options.databaseId
      ? getFirestore(options.app, options.databaseId)
      : getFirestore(options.app)
    : options?.databaseId
      ? getFirestore(options.databaseId)
      : getFirestore()

  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots-server'
  const ttlMs = options?.ttlMs ?? DEFAULT_TTL_MS

  // Fix #4: use SHA-256 of state as document ID to avoid path issues
  const docRef = (state: string) => db.doc(`${ns}/v1/directPostStates/${stateToDocId(state)}`)

  const reserve = async (state: string) => {
    const ref = docRef(state)
    const reservationToken = randomUUID()

    try {
      await db.runTransaction(async (tx: Transaction) => {
        const doc = await tx.get(ref)
        const now = Date.now()
        if (doc.exists) {
          const data = doc.data() as StoredState
          if (now <= data.expiresAt.toMillis()) {
            throw new Error('state_conflict')
          }
        }
        tx.set(ref, {
          transactionId: '',
          reservationToken,
          expiresAt: Timestamp.fromMillis(now + ttlMs),
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
          now > data.expiresAt.toMillis() ||
          data.transactionId !== '' ||
          data.reservationToken !== reservationToken
        ) {
          throw new Error('register_failed')
        }
        tx.set(ref, {
          transactionId,
          reservationToken,
          expiresAt: Timestamp.fromMillis(now + ttlMs),
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

  const resolve = async (state: string | undefined) => {
    if (state == null || state.trim() === '') {
      return errorResult('state is required for VP audience validation')
    }

    const ref = docRef(state)
    const doc = await ref.get()
    if (!doc.exists) {
      return errorResult('unknown or expired state')
    }

    const data = doc.data() as StoredState
    if (Date.now() > data.expiresAt.toMillis()) {
      // Fix #2: conditional delete — only remove if still expired at delete time
      await db.runTransaction(async (tx: Transaction) => {
        const current = await tx.get(ref)
        if (current.exists) {
          const d = current.data() as StoredState
          if (Date.now() > d.expiresAt.toMillis()) {
            tx.delete(ref)
          }
        }
      })
      return errorResult('unknown or expired state')
    }

    if (data.transactionId === '') {
      return errorResult('unknown or expired state')
    }

    return { ok: true as const, transactionId: data.transactionId }
  }

  // Fix #2 (consume): verify transactionId before deleting to prevent wrong-generation delete
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
        if (data.transactionId === '' && data.reservationToken === reservationToken) {
          tx.delete(ref)
        }
      }
    })
  }

  return { reserve, register, resolve, consume, release }
}
