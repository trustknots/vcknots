import { createHash } from 'node:crypto'
import { PutCommand } from '@aws-sdk/lib-dynamodb'
import { DPoPProofJtiStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'

const DEFAULT_DPOP_PROOF_JTI_TTL_MS = 6 * 60 * 1000

export type DynamoDbDpopProofJtiStoreOptions = DynamoDbProviderOptions & {
  tableName: string
  /** Default retention (ms) when the caller passes no `ttlMs`. */
  expiresIn?: number
}

type DpopProofJtiItem = {
  id: string
  jwk_thumbprint: string
  jti: string
  /** Epoch milliseconds — used for manual expiry checks (parity with Firestore / in-memory). */
  expires_at: number
  /** Epoch milliseconds. */
  created_at: number
  /** Epoch seconds — DynamoDB TTL attribute (infra-only, see CDK `timeToLiveAttribute: 'ttl'`). */
  ttl: number
}

// Match the Firestore provider: hash the replay key so arbitrary jti values are safe as an id.
const createItemId = (jwkThumbprint: string, jti: string): string =>
  createHash('sha256').update(`${jwkThumbprint}:${jti}`).digest('hex')

export const dynamodbDpopProofJtiStore = (
  options: DynamoDbDpopProofJtiStoreOptions
): DPoPProofJtiStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options

  return {
    kind: 'dpop-proof-jti-store-provider',
    name: 'dynamodb-dpop-proof-jti-store-provider',
    single: true,

    async saveIfAbsent(jwkThumbprint, jti, saveOptions): Promise<boolean> {
      const ttlMs = saveOptions?.ttlMs ?? options.expiresIn ?? DEFAULT_DPOP_PROOF_JTI_TTL_MS
      if (!Number.isFinite(ttlMs)) {
        throw new Error('ttlMs must be a finite number when saving DPoP proof jti')
      }
      const now = Date.now()
      const expires_at = now + ttlMs
      // DynamoDB TTL expects epoch seconds; round up so TTL never deletes before the real (ms) expiry.
      const ttl = Math.ceil(expires_at / 1000)

      try {
        // A single conditional put is atomic: concurrent requests with the same proof cannot both
        // succeed. An entry whose TTL deletion is still pending (eventually consistent) is
        // overwritten once expired; the exact boundary still counts as used, matching Firestore.
        await client.send(
          new PutCommand({
            TableName: tableName,
            Item: {
              id: createItemId(jwkThumbprint, jti),
              jwk_thumbprint: jwkThumbprint,
              jti,
              expires_at,
              created_at: now,
              ttl,
            } satisfies DpopProofJtiItem,
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
