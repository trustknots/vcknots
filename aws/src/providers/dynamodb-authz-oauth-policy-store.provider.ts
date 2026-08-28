import { createHash } from 'node:crypto'
import { GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { AuthorizationServerIssuer, AuthzOAuthPolicy } from '@trustknots/vcknots/authz'
import { AuthzOAuthPolicyStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'

export type DynamoDbAuthzOAuthPolicyStoreOptions = DynamoDbProviderOptions & {
  tableName: string
}

const md5 = (issuer: AuthorizationServerIssuer): string =>
  createHash('md5').update(issuer).digest('base64url')

export const dynamodbAuthzOAuthPolicyStore = (
  options: DynamoDbAuthzOAuthPolicyStoreOptions
): AuthzOAuthPolicyStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options

  return {
    kind: 'authz-oauth-policy-store-provider',
    name: 'dynamodb-authz-oauth-policy-store-provider',
    single: true,

    async fetch(issuer) {
      const id = md5(issuer)
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
      return AuthzOAuthPolicy(data)
    },

    async save(issuer, policy) {
      const id = md5(issuer)
      await client.send(
        new PutCommand({
          TableName: tableName,
          // issuer is stored alongside the policy only for DynamoDB console visibility
          // (parity with the Firestore provider); it is stripped again on fetch.
          Item: { id, issuer, ...policy },
        })
      )
    },
  }
}
