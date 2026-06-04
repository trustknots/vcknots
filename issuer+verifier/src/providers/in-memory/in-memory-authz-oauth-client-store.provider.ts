import { AuthorizationServerIssuer } from '../../authorization-server.types'
import { AuthzOAuthClient } from '../../authz-oauth-client.types'
import { AuthzOAuthClientStoreProvider } from '../provider.types'

export const inMemoryAuthzOAuthClientStore = (): AuthzOAuthClientStoreProvider => {
  const clients = new Map<string, AuthzOAuthClient>()
  const key = (issuer: AuthorizationServerIssuer, clientId: string) => `${issuer}\n${clientId}`

  return {
    kind: 'authz-oauth-client-store-provider',
    name: 'in-memory-authz-oauth-client-store-provider',
    single: true,

    async fetch(issuer, clientId) {
      const client = clients.get(key(issuer, clientId)) ?? null
      if (client?.enabled === false) return null
      return client
    },

    async save(issuer, client) {
      clients.set(key(issuer, client.client_id), client)
    },
  }
}
