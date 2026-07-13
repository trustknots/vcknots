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
  /** Epoch milliseconds — used for manual expiry checks (parity with Firestore / in-memory). */
  expires_at: number
  /** Epoch seconds — DynamoDB TTL attribute (infra-only, see CDK `timeToLiveAttribute: 'ttl'`). */
  ttl: number
}

export const dynamodbNonceStore = (options: DynamoDbNonceStoreOptions): NonceStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options

  // Match the Firestore / in-memory providers: expires_at is epoch ms and the exact boundary is still valid (>).
  const isExpired = (expires_at: unknown): boolean =>
    typeof expires_at !== 'number' || Date.now() > expires_at

  return {
    kind: 'nonce-store-provider',
    name: 'dynamodb-nonce-store-provider',
    single: true,

    async save(nonce): Promise<void> {
      const ttlMs = nonce.nonce_expires_in
      if (ttlMs == null) {
        throw new Error('nonce_expires_in is required when saving nonce')
      }
      const expires_at = Date.now() + ttlMs
      // DynamoDB TTL expects epoch seconds; round up so TTL never deletes before the real (ms) expiry.
      const ttl = Math.ceil(expires_at / 1000)
      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: { id: nonce.nonce, nonce, expires_at, ttl } satisfies NonceItem,
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
      if (isExpired(expires_at)) {
        // Match the Firestore provider: proactively delete expired nonces instead of waiting for TTL.
        await client.send(
          new DeleteCommand({
            TableName: tableName,
            Key: { id: nonce.nonce },
          })
        )
        return false
      }
      return true
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
