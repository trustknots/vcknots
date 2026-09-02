import { createHash } from 'node:crypto'
import { GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { AuthorizationServerIssuer, AuthzOAuthClient } from '@trustknots/vcknots/authz'
import { AuthzOAuthClientStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'

export type DynamoDbAuthzOAuthClientStoreOptions = DynamoDbProviderOptions & {
  tableName: string
}

const md5 = (value: string): string => createHash('md5').update(value).digest('hex')

// issuer is hashed (matches the other authz stores; it's a URL and DynamoDB has no character
// restriction on partition keys, but hashing keeps parity with dynamodb-authz-metadata-store).
// client_id is appended in the clear so distinct clients under the same issuer get distinct keys.
const buildId = (issuer: AuthorizationServerIssuer, clientId: string): string =>
  `${md5(issuer)}#${clientId}`

export const dynamodbAuthzOAuthClientStore = (
  options: DynamoDbAuthzOAuthClientStoreOptions
): AuthzOAuthClientStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options

  return {
    kind: 'authz-oauth-client-store-provider',
    name: 'dynamodb-authz-oauth-client-store-provider',
    single: true,

    async fetch(issuer, clientId) {
      const id = buildId(issuer, clientId)
      const result = await client.send(
        new GetCommand({
          TableName: tableName,
          Key: { id },
        })
      )

      if (!result.Item) {
        return null
      }

      const { id: _id, issuer: _issuer, ...data } = result.Item
      const parsed = AuthzOAuthClient(data)
      if (parsed.enabled === false) return null
      return parsed
    },

    async save(issuer, oauthClient) {
      const id = buildId(issuer, oauthClient.client_id)
      await client.send(
        new PutCommand({
          TableName: tableName,
          // issuer is stored alongside the client only for DynamoDB console visibility
          // (parity with the Firestore provider); it is stripped again on fetch.
          Item: { id, issuer, ...oauthClient },
        })
      )
    },
  }
}
