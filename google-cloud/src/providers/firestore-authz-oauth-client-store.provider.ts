import { createHash } from 'node:crypto'
import { AuthorizationServerIssuer, AuthzOAuthClient } from '@trustknots/vcknots/authz'
import { AuthzOAuthClientStoreProvider } from '@trustknots/vcknots/providers'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

type AuthzOAuthClientDocument = AuthzOAuthClient & {
  issuer?: AuthorizationServerIssuer
}

export const firestoreAuthzOAuthClientStore = (
  options?: FirestoreProviderOptions
): AuthzOAuthClientStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'
  const hash = (value: string) => createHash('sha256').update(value).digest('base64url')
  const docPath = (issuer: AuthorizationServerIssuer, clientId: string) =>
    `${ns}/v1/authzOAuthClients/${hash(issuer)}/clients/${hash(clientId)}`

  return {
    kind: 'authz-oauth-client-store-provider',
    name: 'firestore-authz-oauth-client-store-provider',
    single: true,

    async fetch(issuer, clientId) {
      const doc = await firestore.doc(docPath(issuer, clientId)).get()
      if (!doc.exists) return null

      const { issuer: _issuer, ...client } = doc.data() as AuthzOAuthClientDocument
      const parsed = AuthzOAuthClient(client)
      if (parsed.enabled === false) return null
      return parsed
    },

    async save(issuer, client) {
      const docRef = firestore.doc(docPath(issuer, client.client_id))
      await docRef.set({ issuer, ...client }, { merge: true })
    },
  }
}
