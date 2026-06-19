import { AuthorizationServerIssuer } from '../../authorization-server.types'
import { AuthzOAuthPolicy } from '../../authz-oauth-policy.types'
import { AuthzOAuthPolicyStoreProvider } from '../provider.types'

export const inMemoryAuthzOAuthPolicyStore = (): AuthzOAuthPolicyStoreProvider => {
  const policies = new Map<AuthorizationServerIssuer, AuthzOAuthPolicy>()

  return {
    kind: 'authz-oauth-policy-store-provider',
    name: 'in-memory-authz-oauth-policy-store-provider',
    single: true,

    async fetch(issuer) {
      return policies.get(issuer) ?? null
    },

    async save(issuer, policy) {
      policies.set(issuer, policy)
    },
  }
}
