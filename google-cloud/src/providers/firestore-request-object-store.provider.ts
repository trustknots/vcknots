import { RequestObject } from '@trustknots/vcknots'
import { RequestObjectStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

const DEFAULT_EXPIRES_IN_MS = 5 * 60 * 1000

type StoredRequestObject = Omit<RequestObject, 'dcql_query'> & { dcql_query: string }

const serialize = (requestObject: RequestObject): StoredRequestObject => {
  const { dcql_query, ...rest } = requestObject
  return { ...rest, dcql_query: JSON.stringify(dcql_query) }
}

const deserialize = (raw: StoredRequestObject): RequestObject =>
  ({
    ...raw,
    dcql_query: JSON.parse(raw.dcql_query) as RequestObject['dcql_query'],
  }) as RequestObject

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
        requestObject: StoredRequestObject
        expires_at: Timestamp
      }
      if (new Date().getTime() > expires_at.toMillis()) {
        await firestore.doc(`${ns}/v1/requestObjects/${id}`).delete()
        return null
      }
      return deserialize(requestObject)
    },

    async save(id, requestObject) {
      const expiresAt = Timestamp.fromMillis(
        new Date().getTime() + (options?.expiresIn ?? DEFAULT_EXPIRES_IN_MS)
      )
      const docRef = firestore.doc(`${ns}/v1/requestObjects/${id}`)
      await docRef.set({ requestObject: serialize(requestObject), expires_at: expiresAt })
    },

    async delete(id) {
      await firestore.doc(`${ns}/v1/requestObjects/${id}`).delete()
    },
  }
}
