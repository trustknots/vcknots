import { createHash } from 'node:crypto'
import { AuthorizationServerIssuer, AuthzOAuthPolicy } from '@trustknots/vcknots/authz'
import { AuthzOAuthPolicyStoreProvider } from '@trustknots/vcknots/providers'
import { FirestoreProviderOptions, resolveFirestore } from './firestore.provider'

type AuthzOAuthPolicyDocument = AuthzOAuthPolicy & {
  issuer?: AuthorizationServerIssuer
}

export const firestoreAuthzOAuthPolicyStore = (
  options?: FirestoreProviderOptions
): AuthzOAuthPolicyStoreProvider => {
  const firestore = resolveFirestore(options)
  const ns = options?.namespace?.replace(/\//g, '') || 'vcknots'
  const md5 = (issuer: AuthorizationServerIssuer) =>
    createHash('md5').update(issuer).digest('base64url')

  return {
    kind: 'authz-oauth-policy-store-provider',
    name: 'firestore-authz-oauth-policy-store-provider',
    single: true,

    async fetch(issuer) {
      const id = md5(issuer)
      const doc = await firestore.doc(`${ns}/v1/authzOAuthPolicies/${id}`).get()

      if (!doc.exists) return null

      const { issuer: _issuer, ...policy } = doc.data() as AuthzOAuthPolicyDocument
      return AuthzOAuthPolicy(policy)
    },

    async save(issuer, policy) {
      const id = md5(issuer)
      const docRef = firestore.doc(`${ns}/v1/authzOAuthPolicies/${id}`)
      await docRef.set({ issuer, ...policy }, { merge: true })
    },
  }
}
