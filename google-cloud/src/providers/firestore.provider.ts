import { Provider } from '@trustknots/vcknots/providers'
import { App } from 'firebase-admin/app'
import { Firestore, getFirestore } from 'firebase-admin/firestore'
import { firestoreIssuerMetadataStore } from './firestore-issuer-metadata-store.provider'
import { firestoreVerifierMetadataStore } from './firestore-verifier-metadata-store.provider'
import { firestoreAuthzServerMetadataStore } from './firestore-authz-metadata-store.provider'

export type FirestoreProviderOptions = {
  app?: App // This is the Firebase app instance. If omitted, it defaults to the default app.
  databaseId?: string // This is the Firestore database ID. If omitted, it defaults to '(default)'.
  namespace?: string // This is the root collection name. If omitted, it defaults to 'vcknots'.
}

// Resolves a Firestore instance from the given options, or falls back to the default.
export const resolveFirestore = (options?: FirestoreProviderOptions): Firestore =>
  options?.databaseId
    ? options.app
      ? getFirestore(options.app, options.databaseId)
      : getFirestore(options.databaseId)
    : options?.app
      ? getFirestore(options.app)
      : getFirestore()

// Returns all Firestore-backed providers.
export const firestore = (options?: FirestoreProviderOptions): Provider[] => {
  return [
    firestoreIssuerMetadataStore(options),
    firestoreVerifierMetadataStore(options),
    firestoreAuthzServerMetadataStore(options),
  ]
}
