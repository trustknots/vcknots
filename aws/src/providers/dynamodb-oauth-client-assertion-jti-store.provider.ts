import { createHash } from 'node:crypto'
import { PutCommand } from '@aws-sdk/lib-dynamodb'
import { OAuthClientAssertionJtiStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'

const DEFAULT_OAUTH_CLIENT_ASSERTION_JTI_TTL_MS = 5 * 60 * 1000

export type DynamoDbOAuthClientAssertionJtiStoreOptions = DynamoDbProviderOptions & {
  tableName: string
  /** Default retention (ms) when the caller passes no `ttlMs`. */
  expiresIn?: number
}

type OAuthClientAssertionJtiItem = {
  id: string
  client_id: string
  jti: string
  /** Epoch milliseconds — used for manual expiry checks (parity with Firestore / in-memory). */
  expires_at: number
  /** Epoch milliseconds. */
  created_at: number
  /** Epoch seconds — DynamoDB TTL attribute (infra-only, see CDK `timeToLiveAttribute: 'ttl'`). */
  ttl: number
}

// Match the Firestore provider: hash a JSON-encoded replay key so arbitrary client ids and jti
// values are safe as an id and cannot collide through a shared delimiter.
const createItemId = (clientId: string, jti: string): string =>
  createHash('sha256')
    .update(JSON.stringify([clientId, jti]))
    .digest('hex')

export const dynamodbOAuthClientAssertionJtiStore = (
  options: DynamoDbOAuthClientAssertionJtiStoreOptions
): OAuthClientAssertionJtiStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options

  return {
    kind: 'oauth-client-assertion-jti-store-provider',
    name: 'dynamodb-oauth-client-assertion-jti-store-provider',
    single: true,

    async saveIfAbsent(clientId, jti, saveOptions): Promise<boolean> {
      const ttlMs =
        saveOptions?.ttlMs ?? options.expiresIn ?? DEFAULT_OAUTH_CLIENT_ASSERTION_JTI_TTL_MS
      if (!Number.isFinite(ttlMs)) {
        throw new Error('ttlMs must be a finite number when saving OAuth client assertion jti')
      }
      const now = Date.now()
      const expires_at = now + ttlMs
      // DynamoDB TTL expects epoch seconds; round up so TTL never deletes before the real (ms) expiry.
      const ttl = Math.ceil(expires_at / 1000)

      try {
        // A single conditional put is atomic: concurrent requests with the same assertion cannot
        // both succeed. An entry whose TTL deletion is still pending (eventually consistent) is
        // overwritten once expired; the exact boundary still counts as used, matching Firestore.
        await client.send(
          new PutCommand({
            TableName: tableName,
            Item: {
              id: createItemId(clientId, jti),
              client_id: clientId,
              jti,
              expires_at,
              created_at: now,
              ttl,
            } satisfies OAuthClientAssertionJtiItem,
            ConditionExpression: 'attribute_not_exists(id) OR expires_at < :now',
            ExpressionAttributeValues: { ':now': now },
          })
        )
        return true
      } catch (error) {
        if ((error as { name?: string })?.name === 'ConditionalCheckFailedException') {
          return false
        }
        throw error
      }
    },
  }
}
