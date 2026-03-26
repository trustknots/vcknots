import { Provider } from '@trustknots/vcknots/providers'
import { App } from 'firebase-admin/app'
import { Firestore, getFirestore } from 'firebase-admin/firestore'
import { firestoreIssuerMetadataStore } from './firestore-issuer-metadata-store.provider'
import { firestoreVerifierMetadataStore } from './firestore-verifier-metadata-store.provider'
import { firestoreAuthzServerMetadataStore } from './firestore-authz-metadata-store.provider'
import { firestorePreAuthorizedCodeStore } from './firestore-pre-authorized-code-store.provider'
import { firestoreRequestObjectStore } from './firestore-request-object-store.provider'
import { firestoreCnonceStore } from './firestore-cnonce-store.provider'

const configuredInstances = new WeakSet<Firestore>()

// Configure this setting only once for each Firestore instance
const configureInstance = (firestore: Firestore): Firestore => {
  if (configuredInstances.has(firestore)) {
    return firestore
  }

  // Running `settings` twice on the same instance will result in an error.
  try {
    firestore.settings({
      ignoreUndefinedProperties: true,
    })
  } catch (cause) {
    throw new Error(
      'Failed to configure Firestore instance. This usually means the instance was obtained via getFirestore() elsewhere and already used before configuration.',
      { cause: cause as Error }
    )
  }
  configuredInstances.add(firestore)
  return firestore
}

export type FirestoreProviderOptions = {
  app?: App // This is the Firebase app instance. If omitted, it defaults to the default app.
  databaseId?: string // This is the Firestore database ID. If omitted, it defaults to '(default)'.
  namespace?: string // This is the root collection name. If omitted, it defaults to 'vcknots'.
}

// Resolves a Firestore instance from the given options, or falls back to the default.
export const resolveFirestore = (options?: FirestoreProviderOptions): Firestore => {
  // Get the singleton instance of Firestore
  const instance = options?.databaseId
    ? options.app
      ? getFirestore(options.app, options.databaseId)
      : getFirestore(options.databaseId)
    : options?.app
      ? getFirestore(options.app)
      : getFirestore()

  // This configuration is applied only once per instance
  return configureInstance(instance)
}

// Returns all Firestore-backed providers.
export const firestore = (options?: FirestoreProviderOptions): Provider[] => {
  return [
    firestoreIssuerMetadataStore(options),
    firestoreVerifierMetadataStore(options),
    firestoreAuthzServerMetadataStore(options),
    firestorePreAuthorizedCodeStore(options),
    firestoreRequestObjectStore(options),
    firestoreCnonceStore(options),
  ]
}
