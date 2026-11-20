import { createHash, randomUUID } from 'node:crypto'
import { DeleteCommand, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from '@trustknots/aws'
import type { DirectPostVpAudTransactionStore } from '@trustknots/server-core'

const DEFAULT_TTL_MS = 5 * 60 * 1000

type StoredState = {
  /** SHA-256 (hex) of `state`. */
  id: string
  transaction_id: string
  reservation_token: string
  status: 'reserved' | 'registered' | 'processing'
  /** Epoch milliseconds — application-level expiry check (parity with in-memory / Firestore). */
  expires_at: number
  /** Epoch seconds — DynamoDB TTL attribute (see CDK `timeToLiveAttribute: 'ttl'`). */
  ttl: number
}

// `state` is chosen by the client, so hash it to keep arbitrary values safe as a key.
const stateToId = (state: string) => createHash('sha256').update(state).digest('hex')

// DynamoDB TTL expects epoch seconds; round up so TTL never deletes before the real (ms) expiry.
const toTtl = (expiresAtMs: number) => Math.ceil(expiresAtMs / 1000)

const isConditionalCheckFailed = (error: unknown): boolean =>
  (error as { name?: string })?.name === 'ConditionalCheckFailedException'

const errorResult = (error_description: string) => ({
  ok: false as const,
  error: { error: 'invalid_request', error_description },
})

export const createDynamoDbDirectPostStateStore = (
  options: DynamoDbProviderOptions & { tableName: string; ttlMs?: number }
): DirectPostVpAudTransactionStore => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS

  // Each operation is a single conditional write on one item, which DynamoDB applies atomically:
  // of concurrent callers on the same state, only one passes the condition.
  // An item counts as live up to and including `expires_at`, matching the in-memory store; an
  // expired item may still exist until DynamoDB TTL removes it, so conditions check `expires_at`.

  const reserve = async (state: string) => {
    const now = Date.now()
    const expiresAt = now + ttlMs
    const reservationToken = randomUUID()
    try {
      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: {
            id: stateToId(state),
            transaction_id: '',
            reservation_token: reservationToken,
            status: 'reserved',
            expires_at: expiresAt,
            ttl: toTtl(expiresAt),
          } satisfies StoredState,
          ConditionExpression: 'attribute_not_exists(id) OR expires_at < :now',
          ExpressionAttributeValues: { ':now': now },
        })
      )
      return { ok: true as const, reservationToken }
    } catch (error) {
      if (isConditionalCheckFailed(error)) {
        return errorResult('state is already in use for an active presentation transaction')
      }
      throw error
    }
  }

  const register = async (state: string, transactionId: string, reservationToken: string) => {
    const now = Date.now()
    const expiresAt = now + ttlMs
    try {
      await client.send(
        new UpdateCommand({
          TableName: tableName,
          Key: { id: stateToId(state) },
          UpdateExpression:
            'SET transaction_id = :transactionId, #status = :registered, expires_at = :expiresAt, #ttl = :ttl',
          ConditionExpression:
            'attribute_exists(id) AND expires_at >= :now AND #status = :reserved AND reservation_token = :reservationToken',
          ExpressionAttributeNames: { '#status': 'status', '#ttl': 'ttl' },
          ExpressionAttributeValues: {
            ':transactionId': transactionId,
            ':registered': 'registered',
            ':reserved': 'reserved',
            ':reservationToken': reservationToken,
            ':expiresAt': expiresAt,
            ':ttl': toTtl(expiresAt),
            ':now': now,
          },
        })
      )
      return { ok: true as const }
    } catch (error) {
      if (isConditionalCheckFailed(error)) {
        return errorResult('state is already in use for an active presentation transaction')
      }
      throw error
    }
  }

  const acquire = async (state: string | undefined) => {
    if (state == null || state.trim() === '') {
      return errorResult('state is required for VP audience validation')
    }
    try {
      const result = await client.send(
        new UpdateCommand({
          TableName: tableName,
          Key: { id: stateToId(state) },
          UpdateExpression: 'SET #status = :processing',
          ConditionExpression:
            'attribute_exists(id) AND expires_at >= :now AND #status = :registered',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: {
            ':processing': 'processing',
            ':registered': 'registered',
            ':now': Date.now(),
          },
          ReturnValues: 'ALL_NEW',
        })
      )
      const item = result.Attributes as StoredState | undefined
      if (!item) return errorResult('unknown or expired state')
      return { ok: true as const, transactionId: item.transaction_id }
    } catch (error) {
      if (isConditionalCheckFailed(error)) {
        return errorResult('unknown or expired state')
      }
      throw error
    }
  }

  /** Deletes only if the binding still belongs to `transactionId`, so a newer generation survives. */
  const consume = async (state: string, transactionId: string) => {
    try {
      await client.send(
        new DeleteCommand({
          TableName: tableName,
          Key: { id: stateToId(state) },
          ConditionExpression: 'transaction_id = :transactionId',
          ExpressionAttributeValues: { ':transactionId': transactionId },
        })
      )
    } catch (error) {
      if (!isConditionalCheckFailed(error)) throw error
    }
  }

  const release = async (state: string, reservationToken: string) => {
    try {
      await client.send(
        new DeleteCommand({
          TableName: tableName,
          Key: { id: stateToId(state) },
          ConditionExpression: '#status = :reserved AND reservation_token = :reservationToken',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: {
            ':reserved': 'reserved',
            ':reservationToken': reservationToken,
          },
        })
      )
    } catch (error) {
      if (!isConditionalCheckFailed(error)) throw error
    }
  }

  return { reserve, register, acquire, consume, release }
}
