import { RequestObject } from '@trustknots/vcknots'
import { RequestObjectStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

export const firestoreRequestObjectStore = (
  options?: FirestoreProviderOptions & { expiresIn?: number }
): RequestObjectStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'

  return {
    kind: 'request-object-store-provider',
    name: 'firestore-request-object-store-provider',
    single: true,

    async fetch(id) {
      const doc = await firestore.doc(`${ns}/v1/requestObjects/${id}`).get()
      if (!doc.exists) {
        return null
      }
      const { requestObject, expires_at } = doc.data() as {
        requestObject: RequestObject
        expires_at: Timestamp
      }
      if (new Date().getTime() > expires_at.toMillis()) {
        await firestore.doc(`${ns}/v1/requestObjects/${id}`).delete()
        return null
      }
      return requestObject
    },

    async save(id, requestObject) {
      const expiresAt = Timestamp.fromMillis(
        new Date().getTime() + (options?.expiresIn ?? 60 * 5 * 1000)
      ) // 5 minutes
      const docRef = firestore.doc(`${ns}/v1/requestObjects/${id}`)
      await docRef.set({ requestObject, expires_at: expiresAt })
    },

    async delete(id) {
      await firestore.doc(`${ns}/v1/requestObjects/${id}`).delete()
    },
  }
}
