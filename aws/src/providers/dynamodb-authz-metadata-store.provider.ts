import { createHash } from 'node:crypto'
import { GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { AuthorizationServerIssuer, AuthorizationServerMetadata } from '@trustknots/vcknots/authz'
import { AuthzServerMetadataStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'

export type DynamoDbAuthzServerMetadataStoreOptions = DynamoDbProviderOptions & {
  tableName: string
}

const md5 = (issuer: AuthorizationServerIssuer): string =>
  createHash('md5').update(issuer).digest('base64url')

export const dynamodbAuthzServerMetadataStore = (
  options: DynamoDbAuthzServerMetadataStoreOptions
): AuthzServerMetadataStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options

  return {
    kind: 'authz-server-metadata-store-provider',
    name: 'dynamodb-authz-server-metadata-store-provider',
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

      const { id: _id, ...data } = result.Item
      return AuthorizationServerMetadata(data)
    },

    async save(metadata) {
      const id = md5(metadata.issuer)
      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: { id, ...metadata },
        })
      )
    },
  }
}
