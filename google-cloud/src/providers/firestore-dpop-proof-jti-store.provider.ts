import { createHash } from 'node:crypto'
import { DPoPProofJtiStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

const DEFAULT_DPOP_PROOF_JTI_TTL_MS = 6 * 60 * 1000

const createDocumentId = (jwkThumbprint: string, jti: string): string =>
  createHash('sha256').update(`${jwkThumbprint}:${jti}`).digest('hex')

export const firestoreDpopProofJtiStore = (
  options?: FirestoreProviderOptions & { expiresIn?: number }
): DPoPProofJtiStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'

  return {
    kind: 'dpop-proof-jti-store-provider',
    name: 'firestore-dpop-proof-jti-store-provider',
    single: true,

    async saveIfAbsent(jwkThumbprint, jti, saveOptions): Promise<boolean> {
      const now = Date.now()
      const ttlMs = saveOptions?.ttlMs ?? options?.expiresIn ?? DEFAULT_DPOP_PROOF_JTI_TTL_MS
      const docId = createDocumentId(jwkThumbprint, jti)
      const docRef = firestore.doc(`${ns}/v1/dpopProofJtis/${docId}`)

      return firestore.runTransaction(async (transaction) => {
        const doc = await transaction.get(docRef)
        if (doc.exists) {
          const { expires_at } = doc.data() as { expires_at?: Timestamp }
          if (expires_at && now <= expires_at.toMillis()) {
            return false
          }
        }

        transaction.set(docRef, {
          jwk_thumbprint: jwkThumbprint,
          jti,
          expires_at: Timestamp.fromMillis(now + ttlMs),
          created_at: Timestamp.fromMillis(now),
        })
        return true
      })
    },
  }
}
