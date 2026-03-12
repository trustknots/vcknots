import { createHash } from 'node:crypto'
import { AuthorizationServerIssuer, AuthorizationServerMetadata } from '@trustknots/vcknots/authz'
import { AuthzServerMetadataStoreProvider } from '@trustknots/vcknots/providers'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

export const firestoreAuthzServerMetadataStore = (
  options?: FirestoreProviderOptions
): AuthzServerMetadataStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'
  const md5 = (issuer: AuthorizationServerIssuer) =>
    createHash('md5').update(issuer).digest('base64url')

  return {
    kind: 'authz-server-metadata-store-provider',
    name: 'firestore-authz-server-metadata-store-provider',
    single: true,

    async fetch(issuer) {
      const id = md5(issuer)
      const doc = await firestore.doc(`${ns}/v1/authServers/${id}`).get()

      if (!doc.exists) return null

      return AuthorizationServerMetadata(doc.data())
    },
    async save(metadata) {
      const id = md5(metadata.issuer)
      const docRef = firestore.doc(`${ns}/v1/authServers/${id}`)
      await docRef.set(metadata, { merge: true })
    },
  }
}
