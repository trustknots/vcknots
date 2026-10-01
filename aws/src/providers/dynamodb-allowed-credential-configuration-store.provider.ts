import { DeleteCommand, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { AllowedCredentialConfigurationStoreEntry } from '@trustknots/vcknots'
import { AllowedCredentialConfigurationStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'

export type DynamoDbAllowedCredentialConfigurationStoreOptions = DynamoDbProviderOptions & {
  tableName: string
  /** Default TTL in seconds when a per-save ttlSec is not provided. Defaults to 300 (5 minutes). */
  expiresIn?: number
}

const DEFAULT_TTL_SEC = 300

/**
 * Item stored in DynamoDB. The access token hash is the partition key (`id`).
 * `expires_at` is the application-level expiry in **epoch milliseconds** (used for
 * manual expiry checks, matching the Firestore / in-memory providers); `ttl` is a
 * separate **epoch-seconds** value used only by DynamoDB TTL.
 */
type AllowedCredentialConfigurationItem = {
  id: string
  credential_configuration_ids: AllowedCredentialConfigurationStoreEntry['credential_configuration_ids']
  expires_at: number
  ttl: number
  created_at: number
}

export const dynamodbAllowedCredentialConfigurationStore = (
  options: DynamoDbAllowedCredentialConfigurationStoreOptions
): AllowedCredentialConfigurationStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options

  // Match the Firestore / in-memory providers: expires_at is epoch ms and the exact boundary is still valid.
  const isExpired = (expires_at: unknown): boolean =>
    typeof expires_at !== 'number' || expires_at < Date.now()

  const deleteItem = async (accessTokenHash: string): Promise<void> => {
    await client.send(
      new DeleteCommand({
        TableName: tableName,
        Key: { id: accessTokenHash },
      })
    )
  }

  return {
    kind: 'allowed-credential-configuration-store-provider',
    name: 'dynamodb-allowed-credential-configuration-store-provider',
    single: true,

    async save(accessTokenHash, credential_configuration_ids, ttl) {
      const now = Date.now()
      const ttlSecRaw = Number(ttl ?? options.expiresIn ?? DEFAULT_TTL_SEC)
      const ttlSecCandidate = Math.floor(ttlSecRaw)
      const ttlSec =
        Number.isFinite(ttlSecRaw) && ttlSecCandidate > 0 ? ttlSecCandidate : DEFAULT_TTL_SEC
      const expires_at = now + ttlSec * 1000

      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: {
            id: accessTokenHash,
            credential_configuration_ids,
            expires_at,
            // DynamoDB TTL expects epoch seconds; round up so TTL never deletes before the real (ms) expiry.
            ttl: Math.ceil(expires_at / 1000),
            created_at: now,
          } satisfies AllowedCredentialConfigurationItem,
        })
      )
    },

    async fetch(accessTokenHash) {
      const result = await client.send(
        new GetCommand({
          TableName: tableName,
          Key: { id: accessTokenHash },
        })
      )

      if (!result.Item) {
        return null
      }

      // DynamoDB TTL deletion is eventually consistent — check expiry manually.
      const item = result.Item as AllowedCredentialConfigurationItem
      if (isExpired(item.expires_at)) {
        // Match the Firestore provider: proactively delete expired entries instead of waiting for TTL.
        await deleteItem(accessTokenHash)
        return null
      }

      return item.credential_configuration_ids
    },

    async delete(accessTokenHash) {
      await deleteItem(accessTokenHash)
    },
  }
}
