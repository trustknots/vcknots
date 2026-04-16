import { CnonceStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

export const firestoreCnonceStore = (
  options?: FirestoreProviderOptions & { c_nonce_expire_in?: number }
): CnonceStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'

  return {
    kind: 'cnonce-store-provider',
    name: 'firestore-cnonce-store-provider',
    single: true,

    async save(cnonce): Promise<void> {
      const expiresAt = Timestamp.fromMillis(
        new Date().getTime() + (options?.c_nonce_expire_in ?? 60 * 5 * 1000)
      ) // 5 minutes

      const docRef = firestore.doc(`${ns}/v1/nonces/${cnonce}`)
      await docRef.set({ c_nonce: cnonce, c_nonce_expires_at: expiresAt })
    },
    async validate(cnonce): Promise<boolean> {
      const doc = await firestore.doc(`${ns}/v1/nonces/${cnonce}`).get()
      if (!doc.exists) {
        return false
      }
      const { c_nonce_expires_at } = doc.data() as { c_nonce_expires_at: Timestamp }
      if (new Date().getTime() > c_nonce_expires_at.toMillis()) {
        await doc.ref.delete()
        return false
      }
      return true
    },
    async revoke(cnonce): Promise<void> {
      await firestore.doc(`${ns}/v1/nonces/${cnonce}`).delete()
    },
  }
}
