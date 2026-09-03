import { App } from 'firebase-admin/app'
import { Firestore } from 'firebase-admin/firestore'

/** Minimal doc ref shape passed into Firestore `Transaction.get` / `set` / `delete`. */
type MockTxnDocRef = {
  path: string
}

/** Transaction mock aligned with firebase-admin: chained `set`/`delete`, snapshots include `ref`. */
export type MockFirestoreTransaction = {
  get: <R extends MockTxnDocRef>(
    docRef: R
  ) => Promise<{
    exists: boolean
    data: () => Record<string, unknown> | undefined
    ref: R
  }>
  set: <R extends MockTxnDocRef>(
    docRef: R,
    data: Record<string, unknown>,
    options?: { merge?: boolean }
  ) => MockFirestoreTransaction
  delete: <R extends MockTxnDocRef>(docRef: R) => MockFirestoreTransaction
}

// In-memory Firestore mock for unit testing firestore providers.
export type FirestoreTestMock = {
  store: Map<string, Record<string, unknown>>
  mockFirestore: Firestore
  mockApp: App
}

// Creates an in-memory Firestore mock with doc/get/set API.
export const createFirestoreTestMock = (): FirestoreTestMock => {
  const store = new Map<string, Record<string, unknown>>()

  // Fake Firestore instance backed by the in-memory store, injected via DI.
  // Serialize runTransaction like Firestore's per-client contention handling so
  // concurrent consume races in unit tests see a committed prior delete.
  let transactionQueue: Promise<unknown> = Promise.resolve()

  const mockFirestore = {
    settings: () => {},
    doc: (path: string) => {
      const docRef = {
        path,
        get: async () => ({
          exists: store.has(path),
          data: () => store.get(path),
          ref: docRef,
        }),
        set: async (data: Record<string, unknown>, options?: { merge?: boolean }) => {
          if (options?.merge) {
            const current = store.get(path) ?? {}
            store.set(path, { ...current, ...data })
          } else {
            store.set(path, { ...data })
          }
        },
        delete: async () => {
          store.delete(path)
        },
      }
      return docRef
    },
    runTransaction: async <T>(
      updateFunction: (transaction: MockFirestoreTransaction) => Promise<T>
    ): Promise<T> => {
      const run = transactionQueue.then(async () => {
        const transaction: MockFirestoreTransaction = {
          get: async (docRef) => ({
            exists: store.has(docRef.path),
            data: () => store.get(docRef.path),
            ref: docRef,
          }),
          set: (docRef, data, options) => {
            if (options?.merge) {
              const current = store.get(docRef.path) ?? {}
              store.set(docRef.path, { ...current, ...data })
            } else {
              store.set(docRef.path, { ...data })
            }
            return transaction
          },
          delete: (docRef) => {
            store.delete(docRef.path)
            return transaction
          },
        }
        return updateFunction(transaction)
      })
      // Keep the queue moving even when a transaction throws.
      transactionQueue = run.then(
        () => undefined,
        () => undefined
      )
      return run
    },
  } as unknown as Firestore

  // Fake App instance backed by the in-memory Firestore mock, injected via DI.
  const mockApp = {
    name: 'mock-app',
    options: {},
    getOrInitService: (serviceName: string) => {
      if (serviceName !== 'firestore') {
        throw new Error(`Unexpected service: ${serviceName}`)
      }
      return {
        getDatabase: () => mockFirestore,
      }
    },
  } as unknown as App

  return { store, mockFirestore, mockApp }
}
