import { AllowedCredentialConfigurationStoreEntry } from '@trustknots/vcknots'
import { AllowedCredentialConfigurationStoreProvider } from '@trustknots/vcknots/providers'
import { Timestamp } from 'firebase-admin/firestore'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

type FirestoreAllowedCredentialConfigurationDoc = Omit<
  AllowedCredentialConfigurationStoreEntry,
  'expires_at'
> & {
  expires_at: Timestamp
  created_at: Timestamp
}

export const firestoreAllowedCredentialConfigurationStore = (
  options?: FirestoreProviderOptions & { expiresIn?: number }
): AllowedCredentialConfigurationStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'

  return {
    kind: 'allowed-credential-configuration-store-provider',
    name: 'firestore-allowed-credential-configuration-store-provider',
    single: true,

    async save(accessTokenHash, credential_configuration_ids, ttl) {
      const now = Date.now()
      const ttlSecRaw = Number(ttl ?? options?.expiresIn ?? 300)
      const ttlSecCandidate = Math.floor(ttlSecRaw)
      const ttlSec = Number.isFinite(ttlSecRaw) && ttlSecCandidate > 0 ? ttlSecCandidate : 300

      const docRef = firestore.doc(`${ns}/v1/allowedCredentialConfigurations/${accessTokenHash}`)
      const data: FirestoreAllowedCredentialConfigurationDoc = {
        credential_configuration_ids: credential_configuration_ids,
        expires_at: Timestamp.fromMillis(now + ttlSec * 1000),
        created_at: Timestamp.fromMillis(now),
      }

      await docRef.set(data)
    },

    async fetch(accessTokenHash) {
      const doc = await firestore.doc(`${ns}/v1/allowedCredentialConfigurations/${accessTokenHash}`).get()
      if (!doc.exists) {
        return null
      }

      const data = doc.data() as FirestoreAllowedCredentialConfigurationDoc
      if (data.expires_at.toMillis() < Date.now()) {
        await firestore.doc(`${ns}/v1/allowedCredentialConfigurations/${accessTokenHash}`).delete()
        return null
      }

      return data.credential_configuration_ids
    },

    async delete(accessTokenHash) {
      await firestore.doc(`${ns}/v1/allowedCredentialConfigurations/${accessTokenHash}`).delete()
    },
  }
}
