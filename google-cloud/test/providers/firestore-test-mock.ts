import { App } from 'firebase-admin/app'
import { Firestore } from 'firebase-admin/firestore'

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
  const mockFirestore = {
    settings: () => {},
    doc: (path: string) => ({
      get: async () => ({
        exists: store.has(path),
        data: () => store.get(path),
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
    }),
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
