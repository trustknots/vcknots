import { CredentialIssuanceStoreEntry } from '@trustknots/vcknots'
import { IssuanceContextStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

type FirestoreCredentialIssuanceContextDoc = Omit<
  CredentialIssuanceStoreEntry,
  'jti' | 'expires_at'
> & {
  expires_at: Timestamp
}

export const firestoreIssuanceContextStore = (
  options?: FirestoreProviderOptions & { expiresIn?: number }
): IssuanceContextStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'

  return {
    kind: 'issuance-context-store-provider',
    name: 'firestore-issuance-context-store-provider',
    single: true,

    async save(jti, credential_configuration_ids, ttl) {
      const ttlSecRaw = Number(ttl ?? options?.expiresIn ?? 300)
      const ttlSecCandidate = Math.floor(ttlSecRaw)
      const ttlSec = Number.isFinite(ttlSecRaw) && ttlSecCandidate > 0 ? ttlSecCandidate : 300
      const expiresAt = Timestamp.fromMillis(new Date().getTime() + ttlSec * 1000)

      const docRef = firestore.doc(`${ns}/v1/issuanceContexts/${jti}`)
      const data: FirestoreCredentialIssuanceContextDoc = {
        credential_configuration_ids: credential_configuration_ids,
        expires_at: expiresAt,
      }

      await docRef.set(data)
    },

    async fetch(jti) {
      const doc = await firestore.doc(`${ns}/v1/issuanceContexts/${jti}`).get()
      if (!doc.exists) {
        return null
      }

      const data = doc.data() as FirestoreCredentialIssuanceContextDoc
      if (data.expires_at.toMillis() < Date.now()) {
        await firestore.doc(`${ns}/v1/issuanceContexts/${jti}`).delete()
        return null
      }

      return data.credential_configuration_ids
    },

    async delete(jti) {
      await firestore.doc(`${ns}/v1/issuanceContexts/${jti}`).delete()
    },
  }
}
