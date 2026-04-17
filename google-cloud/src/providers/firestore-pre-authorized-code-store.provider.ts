import { PreAuthorizedCodeStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

export const firestorePreAuthorizedCodeStore = (
  options?: FirestoreProviderOptions & { expiresIn?: number }
): PreAuthorizedCodeStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'

  return {
    kind: 'pre-authorized-code-store-provider',
    name: 'firestore-pre-authorized-code-store-provider',
    single: true,

    async save(code) {
      const expiresAt = Timestamp.fromMillis(new Date().getTime() + (options?.expiresIn ?? 60 * 5 * 1000)) // 5 minutes
      const docRef = firestore.doc(`${ns}/v1/preCodes/${code}`)
      await docRef.set({ code, expires_at: expiresAt })
    },
    async validate(code) {
      const doc = await firestore.doc(`${ns}/v1/preCodes/${code}`).get()
      if (!doc.exists) {
        return false
      }
      const { expires_at } = doc.data() as { expires_at: Timestamp }
      if (new Date().getTime() > expires_at.toMillis()) {
        await firestore.doc(`${ns}/v1/preCodes/${code}`).delete()
        return false
      }
      return true
    },
    async delete(code) {
      await firestore.doc(`${ns}/v1/preCodes/${code}`).delete()
    },
  }
}
