import { createHash } from 'node:crypto'
import { VerifierClientId, VerifierMetadata } from '@trustknots/vcknots/verifier'
import { VerifierMetadataStoreProvider } from '@trustknots/vcknots/providers'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

export const firestoreVerifierMetadataStore = (
  options?: FirestoreProviderOptions
): VerifierMetadataStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'
  const md5 = (verifier: VerifierClientId) => createHash('md5').update(verifier).digest('base64url')

  return {
    kind: 'verifier-metadata-store-provider',
    name: 'firestore-verifier-metadata-store-provider',
    single: true,

    async fetch(verifier) {
      const id = md5(verifier)
      const doc = await firestore.doc(`${ns}/v1/verifiers/${id}`).get()

      if (!doc.exists) return null

      return VerifierMetadata(doc.data())
    },
    async save(verifier, metadata) {
      const id = md5(verifier)
      const docRef = firestore.doc(`${ns}/v1/verifiers/${id}`)
      await docRef.set(metadata, { merge: true })
    },
  }
}
