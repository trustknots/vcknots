import { DeleteCommand, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { RequestObject } from '@trustknots/vcknots'
import { RequestObjectStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'

export type DynamoDbRequestObjectStoreOptions = DynamoDbProviderOptions & {
  tableName: string
  /** TTL in milliseconds. Defaults to 5 minutes. */
  expiresIn?: number
}

const DEFAULT_EXPIRES_IN_MS = 60 * 5 * 1000

export const dynamodbRequestObjectStore = (
  options: DynamoDbRequestObjectStoreOptions
): RequestObjectStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName, expiresIn = DEFAULT_EXPIRES_IN_MS } = options

  return {
    kind: 'request-object-store-provider',
    name: 'dynamodb-request-object-store-provider',
    single: true,

    async fetch(id) {
      const result = await client.send(
        new GetCommand({
          TableName: tableName,
          Key: { id },
        })
      )

      if (!result.Item) {
        return null
      }

      const { expires_at, requestObject } = result.Item as {
        expires_at: number
        requestObject: RequestObject
      }

      // DynamoDB TTL deletion is eventually consistent — check expiry manually.
      if (typeof expires_at !== 'number' || Math.floor(Date.now() / 1000) > expires_at) {
        return null
      }

      return requestObject
    },

    async save(id, requestObject) {
      const expires_at = Math.floor((Date.now() + expiresIn) / 1000)
      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: { id, requestObject, expires_at },
        })
      )
    },

    async delete(id) {
      await client.send(
        new DeleteCommand({
          TableName: tableName,
          Key: { id },
        })
      )
    },
  }
}
