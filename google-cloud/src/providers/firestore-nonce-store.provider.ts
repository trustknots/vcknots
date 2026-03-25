import { NonceStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

export const firestoreNonceStore = (options?: FirestoreProviderOptions): NonceStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'

  return {
    kind: 'nonce-store-provider',
    name: 'firestore-nonce-store-provider',
    single: true,

    async save(nonce): Promise<void> {
      const ttlMs = nonce.nonce_expires_in
      if (ttlMs == null) {
        throw new Error('nonce_expires_in is required when saving nonce')
      }
      const expiresAt = Timestamp.fromMillis(new Date().getTime() + ttlMs)
      const docRef = firestore.doc(`${ns}/v1/nonces/${nonce.nonce}`)
      await docRef.set({ nonce, expires_at: expiresAt })
    },
    async validate(nonce): Promise<boolean> {
      const doc = await firestore.doc(`${ns}/v1/nonces/${nonce.nonce}`).get()
      if (!doc.exists) {
        return false
      }
      const { expires_at } = doc.data() as { expires_at: Timestamp }
      if (new Date().getTime() > expires_at.toMillis()) {
        await doc.ref.delete()
        return false
      }
      return true
    },
    async revoke(nonce): Promise<boolean> {
      await firestore.doc(`${ns}/v1/nonces/${nonce.nonce}`).delete()
      return true
    },
  }
}
