import { DeleteCommand, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { Transaction } from '@trustknots/vcknots'
import { VerifierTransactionDataStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'

export type DynamoDbVerifierTransactionDataStoreOptions = DynamoDbProviderOptions & {
  tableName: string
  /** TTL in milliseconds. Defaults to 5 minutes. */
  expiresIn?: number
}

const DEFAULT_EXPIRES_IN_MS = 60 * 5 * 1000

type VerifierTransactionItem = {
  id: string
  // DynamoDB stores nested lists natively, so unlike Firestore the query is not JSON-encoded.
  dcqlQuery: Transaction['dcqlQuery']
  clientId: Transaction['clientId']
  verifierId: Transaction['verifierId']
  state?: string
  nonce: string
  /** Epoch milliseconds — used for manual expiry checks (parity with Firestore / in-memory). */
  expires_at: number
  /** Epoch seconds — DynamoDB TTL attribute (infra-only, see CDK `timeToLiveAttribute: 'ttl'`). */
  ttl: number
}

export const dynamodbVerifierTransactionDataStore = (
  options: DynamoDbVerifierTransactionDataStoreOptions
): VerifierTransactionDataStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName, expiresIn = DEFAULT_EXPIRES_IN_MS } = options
  const ttlMs = Number.isFinite(expiresIn) ? expiresIn : DEFAULT_EXPIRES_IN_MS

  return {
    kind: 'verifier-transaction-store-provider',
    name: 'dynamodb-verifier-transaction-store-provider',
    single: true,

    async save(transactionId, record) {
      const expires_at = Date.now() + ttlMs
      // DynamoDB TTL expects epoch seconds; round up so TTL never deletes before the real (ms) expiry.
      const ttl = Math.ceil(expires_at / 1000)
      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: {
            id: transactionId,
            dcqlQuery: record.dcqlQuery,
            clientId: record.clientId,
            verifierId: record.verifierId,
            ...(record.state !== undefined ? { state: record.state } : {}),
            nonce: record.nonce,
            expires_at,
            ttl,
          } satisfies VerifierTransactionItem,
        })
      )
    },

    async fetch(transactionId) {
      const result = await client.send(
        new GetCommand({
          TableName: tableName,
          Key: { id: transactionId },
          // The wallet's response can land on a different Lambda instance than the request that
          // saved the transaction, so read strongly to never miss a transaction just written.
          ConsistentRead: true,
        })
      )

      if (!result.Item) {
        return null
      }

      const item = result.Item as VerifierTransactionItem

      // DynamoDB TTL is eventually consistent — check manually.
      if (typeof item.expires_at !== 'number' || Date.now() > item.expires_at) {
        return null
      }

      return Transaction({
        transaction_id: transactionId,
        transaction_data_expires_at: item.expires_at,
        dcqlQuery: item.dcqlQuery,
        clientId: item.clientId,
        verifierId: item.verifierId,
        state: item.state,
        nonce: item.nonce,
      })
    },

    async delete(transactionId) {
      await client.send(
        new DeleteCommand({
          TableName: tableName,
          Key: { id: transactionId },
        })
      )
    },
  }
}
