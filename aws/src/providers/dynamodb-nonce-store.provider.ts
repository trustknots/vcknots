import { DeleteCommand, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { Nonce } from '@trustknots/vcknots'
import { NonceStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'

export type DynamoDbNonceStoreOptions = DynamoDbProviderOptions & {
  tableName: string
}

type NonceItem = {
  id: string
  nonce: Nonce
  expires_at: number
}

export const dynamodbNonceStore = (options: DynamoDbNonceStoreOptions): NonceStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options

  const isExpired = (expires_at: unknown): boolean =>
    typeof expires_at !== 'number' || Math.floor(Date.now() / 1000) > expires_at

  return {
    kind: 'nonce-store-provider',
    name: 'dynamodb-nonce-store-provider',
    single: true,

    async save(nonce): Promise<void> {
      const ttlMs = nonce.nonce_expires_in
      if (ttlMs == null) {
        throw new Error('nonce_expires_in is required when saving nonce')
      }
      // DynamoDB TTL expects an epoch time in seconds.
      const expires_at = Math.floor((Date.now() + ttlMs) / 1000)
      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: { id: nonce.nonce, nonce, expires_at } satisfies NonceItem,
        })
      )
    },

    async validate(nonce): Promise<boolean> {
      const result = await client.send(
        new GetCommand({
          TableName: tableName,
          Key: { id: nonce.nonce },
        })
      )

      if (!result.Item) {
        return false
      }

      // DynamoDB TTL deletion is eventually consistent — check expiry manually.
      const { expires_at } = result.Item as NonceItem
      return !isExpired(expires_at)
    },

    async revoke(nonce): Promise<boolean> {
      const result = await client.send(
        new DeleteCommand({
          TableName: tableName,
          Key: { id: nonce.nonce },
          ReturnValues: 'ALL_OLD',
        })
      )
      return result.Attributes != null
    },

    async consume(nonce): Promise<boolean> {
      // Atomically remove and return the previous item so a nonce can be used only once.
      const result = await client.send(
        new DeleteCommand({
          TableName: tableName,
          Key: { id: nonce.nonce },
          ReturnValues: 'ALL_OLD',
        })
      )

      if (!result.Attributes) {
        return false
      }

      const { expires_at } = result.Attributes as NonceItem
      return !isExpired(expires_at)
    },
  }
}
