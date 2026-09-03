import { createHash } from 'node:crypto'
import { OAuthClientAssertionJtiStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

const DEFAULT_OAUTH_CLIENT_ASSERTION_JTI_TTL_MS = 5 * 60 * 1000

const createDocumentId = (clientId: string, jti: string): string =>
  createHash('sha256').update(JSON.stringify([clientId, jti])).digest('hex')

export const firestoreOAuthClientAssertionJtiStore = (
  options?: FirestoreProviderOptions & { expiresIn?: number }
): OAuthClientAssertionJtiStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'

  return {
    kind: 'oauth-client-assertion-jti-store-provider',
    name: 'firestore-oauth-client-assertion-jti-store-provider',
    single: true,

    async saveIfAbsent(clientId, jti, saveOptions): Promise<boolean> {
      const now = Date.now()
      const ttlMs =
        saveOptions?.ttlMs ?? options?.expiresIn ?? DEFAULT_OAUTH_CLIENT_ASSERTION_JTI_TTL_MS
      const docId = createDocumentId(clientId, jti)
      const docRef = firestore.doc(`${ns}/v1/oauthClientAssertionJtis/${docId}`)

      return firestore.runTransaction(async (transaction) => {
        const doc = await transaction.get(docRef)
        if (doc.exists) {
          const { expires_at } = doc.data() as { expires_at?: Timestamp }
          if (expires_at && now <= expires_at.toMillis()) {
            return false
          }
        }

        transaction.set(docRef, {
          client_id: clientId,
          jti,
          expires_at: Timestamp.fromMillis(now + ttlMs),
          created_at: Timestamp.fromMillis(now),
        })
        return true
      })
    },
  }
}
