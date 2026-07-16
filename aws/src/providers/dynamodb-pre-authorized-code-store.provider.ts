import { DeleteCommand, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb'
import { PreAuthorizedCodeStoreEntry } from '@trustknots/vcknots'
import { raise } from '@trustknots/vcknots/errors'
import { PreAuthorizedCodeStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'
import { hashTxCode } from './hash.utils'

export type DynamoDbPreAuthorizedCodeStoreOptions = DynamoDbProviderOptions & {
  tableName: string
  /** Default TTL in milliseconds when a per-save ttlSec is not provided. Defaults to 5 minutes. */
  expiresIn?: number
  /**
   * Number of failed `tx_code` attempts allowed per pre-authorized code before it
   * is invalidated (brute-force lockout). Defaults to 5.
   */
  maxTxCodeAttempts?: number
}

const DEFAULT_EXPIRES_IN_MS = 60 * 5 * 1000
const DEFAULT_TTL_SEC = DEFAULT_EXPIRES_IN_MS / 1000
const DEFAULT_MAX_TX_CODE_ATTEMPTS = 5

/**
 * Returned for every code that can no longer be exchanged — unknown, already consumed,
 * or locked out. The three cases are deliberately indistinguishable to the caller.
 */
const LOCKED_MESSAGE = 'Pre-authorized code is invalid, consumed, or locked'

/**
 * Item stored in DynamoDB. The pre-authorized code itself is the partition key
 * (`id`). `tx_code` is never persisted in the clear — only its HMAC hash is
 * stored as `tx_code_hash`. `expires_at` is the application-level expiry in
 * **epoch milliseconds** (used for manual expiry checks, matching the Firestore /
 * in-memory providers); `ttl` is a separate **epoch-seconds** value used only by
 * DynamoDB TTL.
 */
type DynamoDbPreAuthorizedCodeItem = {
  id: string
  credential_configuration_ids: PreAuthorizedCodeStoreEntry['credential_configuration_ids']
  tx_code_input_mode?: 'numeric' | 'text'
  tx_code_hash?: string
  expires_at: number
  ttl: number
  /** Number of failed `tx_code` attempts so far (brute-force lockout counter). */
  attempts?: number
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
  // save() falls back to this value, so a non-finite expiresIn has to be resolved here —
  // otherwise NaN flows straight through that fallback into `expires_at` and `ttl`.
  const defaultTtlSecRaw = Math.floor(expiresIn / 1000)
  const defaultTtlSec = Number.isFinite(defaultTtlSecRaw)
    ? Math.max(1, defaultTtlSecRaw)
    : DEFAULT_TTL_SEC
  // A non-finite limit would reach DynamoDB as the gate's `:max` and fail every consume,
  // so fall back to the default rather than propagating it.
  const maxTxCodeAttemptsRaw = options.maxTxCodeAttempts ?? DEFAULT_MAX_TX_CODE_ATTEMPTS
  const maxTxCodeAttempts = Number.isFinite(maxTxCodeAttemptsRaw)
    ? Math.max(1, Math.floor(maxTxCodeAttemptsRaw))
    : DEFAULT_MAX_TX_CODE_ATTEMPTS

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
      const expires_at = Date.now() + ttlSec * 1000

      const item: DynamoDbPreAuthorizedCodeItem = {
        id: code,
        credential_configuration_ids: credentialConfigurationIds,
        tx_code_input_mode,
        expires_at,
        // DynamoDB TTL expects epoch seconds; round up so TTL never deletes before the real (ms) expiry.
        ttl: Math.ceil(expires_at / 1000),
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
      // Count-first admission gate (brute-force lockout): atomically increment `attempts`
      // only while the code still exists AND the per-code limit hasn't been reached, then
      // read the item back to compare the tx_code. DynamoDB serializes conditional writes
      // per item, so even a highly concurrent burst admits at most `maxTxCodeAttempts`
      // guesses — once the limit is hit, every further attempt (including the correct PIN)
      // fails the condition and is rejected before the tx_code is ever compared.
      let item: DynamoDbPreAuthorizedCodeItem
      try {
        const result = await client.send(
          new UpdateCommand({
            TableName: tableName,
            Key: { id: code },
            UpdateExpression: 'ADD #attempts :one',
            ConditionExpression:
              'attribute_exists(id) AND (attribute_not_exists(#attempts) OR #attempts < :max)',
            ExpressionAttributeNames: { '#attempts': 'attempts' },
            ExpressionAttributeValues: { ':one': 1, ':max': maxTxCodeAttempts },
            ReturnValues: 'ALL_NEW',
          })
        )
        item = result.Attributes as DynamoDbPreAuthorizedCodeItem
      } catch (error) {
        if ((error as { name?: string })?.name === 'ConditionalCheckFailedException') {
          // Not found, already consumed, or locked out after too many tx_code attempts.
          throw raise('invalid_grant', { message: LOCKED_MESSAGE })
        }
        throw error
      }

      /**
       * Called before failing an attempt that the gate admitted. When the attempt
       * exhausted the per-code limit, the code is deleted and the lockout is reported
       * right away: the holder learns the code is dead on the attempt that killed it,
       * rather than being told only that the tx_code was wrong — which would invite a
       * retry that can no longer succeed. Attempts that leave the limit intact fall
       * through, so the holder still gets the specific `Invalid tx_code` error.
       */
      const lockoutIfExhausted = async (): Promise<void> => {
        if ((item.attempts ?? 0) >= maxTxCodeAttempts) {
          await deleteCode(code)
          raise('invalid_grant', { message: LOCKED_MESSAGE })
        }
      }

      // expires_at is epoch ms (parity with Firestore / in-memory). DynamoDB TTL is eventually consistent — check manually.
      if (typeof item.expires_at !== 'number' || Date.now() > item.expires_at) {
        await deleteCode(code)
        throw raise('invalid_grant', {
          message: 'Pre-authorized code has expired',
        })
      }

      if (item.tx_code_hash) {
        if (tx_code === undefined) {
          await lockoutIfExhausted()
          throw raise('invalid_request', {
            message: 'tx_code is required for this pre-authorized code',
          })
        }
        const inputMode = item.tx_code_input_mode ?? 'numeric'
        if (inputMode !== 'text') {
          const actual = toDigitString(tx_code)
          if (actual === null || item.tx_code_hash !== hashTxCode(actual)) {
            await lockoutIfExhausted()
            throw raise('invalid_grant', {
              message: 'Invalid tx_code provided',
            })
          }
        } else {
          if (typeof tx_code !== 'string' || item.tx_code_hash !== hashTxCode(tx_code)) {
            await lockoutIfExhausted()
            throw raise('invalid_grant', {
              message: 'Invalid tx_code provided',
            })
          }
        }
      } else if (tx_code !== undefined) {
        await lockoutIfExhausted()
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
