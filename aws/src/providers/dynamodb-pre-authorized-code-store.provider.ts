import { DeleteCommand, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { PreAuthorizedCodeStoreEntry } from '@trustknots/vcknots'
import { raise } from '@trustknots/vcknots/errors'
import { PreAuthorizedCodeStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'
import { hashTxCode } from './hash.utils'

export type DynamoDbPreAuthorizedCodeStoreOptions = DynamoDbProviderOptions & {
  tableName: string
  /** Default TTL in milliseconds when a per-save ttlSec is not provided. Defaults to 5 minutes. */
  expiresIn?: number
}

const DEFAULT_EXPIRES_IN_MS = 60 * 5 * 1000

/**
 * Item stored in DynamoDB. The pre-authorized code itself is the partition key
 * (`id`). `tx_code` is never persisted in the clear — only its HMAC hash is
 * stored as `tx_code_hash`. `expires_at` is a UNIX timestamp in **seconds** so
 * DynamoDB TTL can expire the item automatically.
 */
type DynamoDbPreAuthorizedCodeItem = {
  id: string
  credential_configuration_ids: PreAuthorizedCodeStoreEntry['credential_configuration_ids']
  tx_code_input_mode?: 'numeric' | 'text'
  tx_code_hash?: string
  expires_at: number
}

const toDigitString = (value: string | number): string | null => {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 0 ? value.toString() : null
  }
  return /^\d+$/.test(value) ? value : null
}

export const dynamodbPreAuthorizedCodeStore = (
  options: DynamoDbPreAuthorizedCodeStoreOptions
): PreAuthorizedCodeStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName, expiresIn = DEFAULT_EXPIRES_IN_MS } = options
  const defaultTtlSec = Math.max(1, Math.floor(expiresIn / 1000))

  /**
   * Deletes a stored code. When `conditional` is true the delete only succeeds
   * if the item still exists, and a lost race is surfaced as `invalid_grant`.
   */
  const deleteCode = async (code: string, conditional = false): Promise<void> => {
    try {
      await client.send(
        new DeleteCommand({
          TableName: tableName,
          Key: { id: code },
          ...(conditional && { ConditionExpression: 'attribute_exists(id)' }),
        })
      )
    } catch (error) {
      if (conditional && (error as { name?: string })?.name === 'ConditionalCheckFailedException') {
        throw raise('invalid_grant', {
          message: 'Pre-authorized code has already been consumed',
        })
      }
      throw error
    }
  }

  return {
    kind: 'pre-authorized-code-store-provider',
    name: 'dynamodb-pre-authorized-code-store-provider',
    single: true,

    async save(code, credentialConfigurationIds, tx_code, saveOptions) {
      const ttlSecRaw = Number(saveOptions?.ttlSec ?? defaultTtlSec)
      const ttlSecCandidate = Math.floor(ttlSecRaw)
      const ttlSec =
        Number.isFinite(ttlSecRaw) && ttlSecCandidate > 0 ? ttlSecCandidate : defaultTtlSec
      const tx_code_input_mode = saveOptions?.tx_code_input_mode ?? 'numeric'
      const expires_at = Math.floor(Date.now() / 1000) + ttlSec

      const item: DynamoDbPreAuthorizedCodeItem = {
        id: code,
        credential_configuration_ids: credentialConfigurationIds,
        tx_code_input_mode,
        expires_at,
      }

      if (tx_code !== undefined) {
        if (tx_code_input_mode !== 'text') {
          const canonical = toDigitString(tx_code)
          if (canonical === null) {
            raise('invalid_tx_code', {
              message: 'tx_code must be a non-negative integer for numeric input mode',
            })
          }
          item.tx_code_hash = hashTxCode(canonical)
        } else {
          item.tx_code_hash = hashTxCode(tx_code)
        }
      }

      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: item,
        })
      )
    },

    async consume(code, tx_code) {
      const result = await client.send(
        new GetCommand({
          TableName: tableName,
          Key: { id: code },
        })
      )

      if (!result.Item) {
        throw raise('invalid_grant', {
          message: 'Pre-authorized code not found',
        })
      }

      const item = result.Item as DynamoDbPreAuthorizedCodeItem

      // DynamoDB TTL deletion is eventually consistent — check expiry manually.
      if (typeof item.expires_at !== 'number' || Math.floor(Date.now() / 1000) > item.expires_at) {
        await deleteCode(code)
        throw raise('invalid_grant', {
          message: 'Pre-authorized code has expired',
        })
      }

      if (item.tx_code_hash) {
        if (tx_code === undefined) {
          throw raise('invalid_request', {
            message: 'tx_code is required for this pre-authorized code',
          })
        }
        const inputMode = item.tx_code_input_mode ?? 'numeric'
        if (inputMode !== 'text') {
          const actual = toDigitString(tx_code)
          if (actual === null || item.tx_code_hash !== hashTxCode(actual)) {
            throw raise('invalid_grant', {
              message: 'Invalid tx_code provided',
            })
          }
        } else {
          if (typeof tx_code !== 'string' || item.tx_code_hash !== hashTxCode(tx_code)) {
            throw raise('invalid_grant', {
              message: 'Invalid tx_code provided',
            })
          }
        }
      } else if (tx_code !== undefined) {
        throw raise('invalid_request', {
          message: 'tx_code should not be provided for this pre-authorized code',
        })
      }

      // Atomically delete to prevent the code from being consumed twice. A
      // failed condition means another request already consumed it.
      await deleteCode(code, true)

      return item.credential_configuration_ids ?? null
    },
  }
}
