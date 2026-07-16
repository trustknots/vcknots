import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'
import { DeleteCommand, DynamoDBDocumentClient, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb'
import { CredentialConfigurationId, PreAuthorizedCode } from '@trustknots/vcknots'
import { mockClient } from 'aws-sdk-client-mock'
import { dynamodbPreAuthorizedCodeStore } from '../src/providers/dynamodb-pre-authorized-code-store.provider'

const TABLE_NAME = 'PreCodesTable'
const ddbMock = mockClient(DynamoDBDocumentClient)

const configurations: CredentialConfigurationId[] = [CredentialConfigurationId('University_Degree')]

const conditionalCheckFailed = () =>
  Object.assign(new Error('conditional check failed'), {
    name: 'ConditionalCheckFailedException',
  })

describe('dynamodbPreAuthorizedCodeStore', () => {
  afterEach(() => {
    ddbMock.reset()
  })

  const createProvider = (expiresIn?: number, maxTxCodeAttempts?: number) =>
    dynamodbPreAuthorizedCodeStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
      ...(expiresIn !== undefined && { expiresIn }),
      ...(maxTxCodeAttempts !== undefined && { maxTxCodeAttempts }),
    })

  /** Grab the Item written by the most recent PutCommand. */
  const lastPutItem = () => ddbMock.commandCalls(PutCommand).at(-1)?.args[0].input.Item

  /**
   * Wire the count-first consume gate: the UpdateCommand (ReturnValues ALL_NEW) returns the
   * item that would exist, with the given attempt count. Defaults to the last saved item.
   */
  const armConsume = (item: Record<string, unknown> | undefined, attempts = 1) => {
    ddbMock.on(UpdateCommand).resolves(item === undefined ? {} : { Attributes: { ...item, attempts } })
  }
  const armConsumeFromLastPut = (attempts = 1) =>
    armConsume(lastPutItem() as Record<string, unknown>, attempts)
  /** Wire the gate to reject the attempt (code not found, consumed, or locked out). */
  const armConsumeRejected = () => ddbMock.on(UpdateCommand).rejects(conditionalCheckFailed())

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'pre-authorized-code-store-provider')
    assert.equal(provider.name, 'dynamodb-pre-authorized-code-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and consume a code without tx_code', async () => {
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('code-123'), configurations)
    armConsumeFromLastPut()

    const result = await provider.consume(PreAuthorizedCode('code-123'))
    assert.deepEqual(result, configurations)
    assert.equal(ddbMock.commandCalls(DeleteCommand).length, 1)
  })

  it('should save and validate a code with tx_code (numeric)', async () => {
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('code-numeric'), configurations, 123, {
      tx_code_input_mode: 'numeric',
    })
    armConsumeFromLastPut()

    const result = await provider.consume(PreAuthorizedCode('code-numeric'), 123)
    assert.deepEqual(result, configurations)
  })

  it('should save and validate a code with tx_code (text)', async () => {
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('code-text'), configurations, 'abc123', {
      tx_code_input_mode: 'text',
    })
    armConsumeFromLastPut()

    const result = await provider.consume(PreAuthorizedCode('code-text'), 'abc123')
    assert.deepEqual(result, configurations)
  })

  it('should throw invalid_grant for incorrect tx_code', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('code-wrong'), configurations, 123, {
      tx_code_input_mode: 'numeric',
    })
    armConsumeFromLastPut()

    await assert.rejects(provider.consume(PreAuthorizedCode('code-wrong'), 456), {
      name: 'invalid_grant',
    })
  })

  it('should allow string numeric tx_code in numeric mode', async () => {
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('code-type'), configurations, 123, {
      tx_code_input_mode: 'numeric',
    })
    armConsumeFromLastPut()

    const result = await provider.consume(PreAuthorizedCode('code-type'), '123')
    assert.deepEqual(result, configurations)
  })

  it('should throw invalid_grant for non-numeric string tx_code in numeric mode', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('code-invalid-num'), configurations, 123, {
      tx_code_input_mode: 'numeric',
    })
    armConsumeFromLastPut()

    await assert.rejects(provider.consume(PreAuthorizedCode('code-invalid-num'), '12a3'), {
      name: 'invalid_grant',
    })
  })

  it('should preserve leading zeros in numeric mode', async () => {
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('code-leading-zero'), configurations, '0123', {
      tx_code_input_mode: 'numeric',
    })
    armConsumeFromLastPut()

    const result = await provider.consume(PreAuthorizedCode('code-leading-zero'), '0123')
    assert.deepEqual(result, configurations)
  })

  it('should throw invalid_grant when leading-zero digit-string is validated as number', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('code-leading-zero-mismatch'), configurations, '0123', {
      tx_code_input_mode: 'numeric',
    })
    armConsumeFromLastPut()

    await assert.rejects(provider.consume(PreAuthorizedCode('code-leading-zero-mismatch'), 123), {
      name: 'invalid_grant',
    })
  })

  it('should throw invalid_tx_code for a non-digit tx_code in numeric mode on save', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await assert.rejects(
      provider.save(PreAuthorizedCode('code-bad-save'), configurations, 'not-a-number', {
        tx_code_input_mode: 'numeric',
      }),
      { name: 'invalid_tx_code' }
    )
  })

  it('should require tx_code when a hash is stored', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('code-requires-tx'), configurations, 123, {
      tx_code_input_mode: 'numeric',
    })
    armConsumeFromLastPut()

    await assert.rejects(provider.consume(PreAuthorizedCode('code-requires-tx')), {
      name: 'invalid_request',
    })
  })

  it('should reject tx_code when none was stored', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('code-no-tx'), configurations)
    armConsumeFromLastPut()

    await assert.rejects(provider.consume(PreAuthorizedCode('code-no-tx'), 123), {
      name: 'invalid_request',
    })
  })

  it('should store only the hashed tx_code, never the clear value', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('hashed-code'), configurations, 123, {
      tx_code_input_mode: 'numeric',
    })

    const item = lastPutItem()
    assert.ok(item)
    assert.equal(item.tx_code_input_mode, 'numeric')
    assert.equal(typeof item.tx_code_hash, 'string')
    assert.equal(item.tx_code_hash.length, 64) // SHA-256 hex length
    assert.ok(!('tx_code' in item))
    assert.ok(!Object.values(item).includes(123))
    assert.ok(!Object.values(item).includes('123'))
  })

  it('should default to numeric mode when not specified', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('default-mode'), configurations, 456)

    assert.equal(lastPutItem()?.tx_code_input_mode, 'numeric')
  })

  it('should persist credential_configuration_ids and id', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('stored-config'), configurations)

    const putCall = ddbMock.commandCalls(PutCommand)[0]
    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.equal(lastPutItem()?.id, 'stored-config')
    assert.deepEqual(lastPutItem()?.credential_configuration_ids, configurations)
  })

  it('should store expires_at in epoch ms and ttl in epoch seconds', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('ttl-default'), configurations)

    const after = Date.now()
    const item = lastPutItem()
    const expiresAt = item?.expires_at
    assert.equal(typeof expiresAt, 'number')
    // expires_at is epoch ms (parity with Firestore / in-memory).
    assert.ok(expiresAt >= before + 300 * 1000)
    assert.ok(expiresAt <= after + 300 * 1000)
    // ttl is epoch seconds, rounded up so TTL never fires before the real (ms) expiry.
    assert.equal(item?.ttl, Math.ceil(expiresAt / 1000))
  })

  it('should honor a custom expiresIn', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const provider = createProvider(60 * 1000)
    await provider.save(PreAuthorizedCode('ttl-custom'), configurations)

    const after = Date.now()
    const expiresAt = lastPutItem()?.expires_at
    assert.ok(expiresAt >= before + 60 * 1000)
    assert.ok(expiresAt <= after + 60 * 1000)
  })

  it('should prefer saveOptions.ttlSec over the default', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('ttl-override'), configurations, undefined, {
      ttlSec: 30,
    })

    const after = Date.now()
    const expiresAt = lastPutItem()?.expires_at
    assert.ok(expiresAt >= before + 30 * 1000)
    assert.ok(expiresAt <= after + 30 * 1000)
  })

  it('should fall back to the default ttl when saveOptions.ttlSec is invalid', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('ttl-nan'), configurations, undefined, {
      ttlSec: Number.NaN,
    })

    const after = Date.now()
    const expiresAt = lastPutItem()?.expires_at
    assert.ok(expiresAt >= before + 300 * 1000)
    assert.ok(expiresAt <= after + 300 * 1000)
  })

  it('should floor a fractional ttlSec', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('ttl-frac'), configurations, undefined, { ttlSec: 30.9 })

    const after = Date.now()
    const expiresAt = lastPutItem()?.expires_at
    assert.ok(expiresAt >= before + 30 * 1000)
    assert.ok(expiresAt <= after + 30 * 1000)
  })

  it('should throw invalid_grant when the code is unknown', async () => {
    // The count-first gate rejects (attribute_exists(id) fails) when the code doesn't exist.
    armConsumeRejected()

    const provider = createProvider()
    await assert.rejects(provider.consume(PreAuthorizedCode('unknown')), {
      name: 'invalid_grant',
    })
  })

  it('should throw invalid_grant and delete when the code is expired', async () => {
    const pastExpiry = Date.now() - 1000
    armConsume({ id: 'expired', credential_configuration_ids: configurations, expires_at: pastExpiry })
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await assert.rejects(provider.consume(PreAuthorizedCode('expired')), {
      name: 'invalid_grant',
    })
    assert.equal(ddbMock.commandCalls(DeleteCommand).length, 1)
  })

  it('should throw invalid_grant when expires_at is missing', async () => {
    armConsume({ id: 'no-exp', credential_configuration_ids: configurations })
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await assert.rejects(provider.consume(PreAuthorizedCode('no-exp')), {
      name: 'invalid_grant',
    })
  })

  it('should delete the code conditionally after a successful consume', async () => {
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('consume-delete'), configurations)
    armConsumeFromLastPut()

    await provider.consume(PreAuthorizedCode('consume-delete'))

    const deleteCall = ddbMock.commandCalls(DeleteCommand)[0]
    assert.equal(deleteCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(deleteCall?.args[0].input.Key, { id: 'consume-delete' })
    assert.equal(deleteCall?.args[0].input.ConditionExpression, 'attribute_exists(id)')
  })

  it('should surface a lost delete race as invalid_grant (double consume)', async () => {
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(DeleteCommand).rejects(conditionalCheckFailed())

    const provider = createProvider()
    await provider.save(PreAuthorizedCode('race'), configurations)
    armConsumeFromLastPut()

    await assert.rejects(provider.consume(PreAuthorizedCode('race')), {
      name: 'invalid_grant',
    })
  })

  describe('tx_code brute-force lockout (count-first gate)', () => {
    const LOCKED_MESSAGE = 'Pre-authorized code is invalid, consumed, or locked'
    const INVALID_TX_CODE_MESSAGE = 'Invalid tx_code provided'

    const saveWithTxCode = async (provider: ReturnType<typeof createProvider>, code: string) => {
      await provider.save(PreAuthorizedCode(code), configurations, 1234, {
        tx_code_input_mode: 'numeric',
      })
    }

    it('gates each attempt with an atomic, capped ADD before comparing tx_code', async () => {
      ddbMock.on(PutCommand).resolves({})

      const provider = createProvider()
      await saveWithTxCode(provider, 'bf-gate')
      armConsumeFromLastPut(1)

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-gate'), 9999), {
        name: 'invalid_grant',
      })

      const upd = ddbMock.commandCalls(UpdateCommand)[0]?.args[0].input
      assert.equal(upd?.UpdateExpression, 'ADD #attempts :one')
      assert.equal(
        upd?.ConditionExpression,
        'attribute_exists(id) AND (attribute_not_exists(#attempts) OR #attempts < :max)'
      )
      assert.deepEqual(upd?.ExpressionAttributeNames, { '#attempts': 'attempts' })
      // Default limit of 5 is enforced atomically in the condition.
      assert.equal(upd?.ExpressionAttributeValues?.[':max'], 5)
      assert.deepEqual(upd?.Key, { id: 'bf-gate' })
    })

    it('rejects a locked/exhausted code before comparing the tx_code', async () => {
      ddbMock.on(PutCommand).resolves({})
      // Gate fails: the code is over the attempt limit (or gone) — DynamoDB rejects the ADD.
      armConsumeRejected()

      const provider = createProvider()
      await saveWithTxCode(provider, 'bf-locked')

      // Even the correct PIN is rejected once the code is locked.
      await assert.rejects(provider.consume(PreAuthorizedCode('bf-locked'), 1234), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      // The tx_code is never compared, and nothing is consumed.
      assert.equal(ddbMock.commandCalls(DeleteCommand).length, 0)
    })

    it('enforces a custom maxTxCodeAttempts in the gate condition', async () => {
      ddbMock.on(PutCommand).resolves({})

      const provider = createProvider(undefined, 2)
      await saveWithTxCode(provider, 'bf-custom')
      armConsumeFromLastPut(1)

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-custom'), 9999), {
        name: 'invalid_grant',
      })
      assert.equal(
        ddbMock.commandCalls(UpdateCommand)[0]?.args[0].input.ExpressionAttributeValues?.[':max'],
        2
      )
    })

    it('keeps the code while attempts remain below the limit', async () => {
      ddbMock.on(PutCommand).resolves({})
      ddbMock.on(DeleteCommand).resolves({})

      const provider = createProvider()
      await saveWithTxCode(provider, 'bf-under')
      // 1st of the 5 allowed attempts.
      armConsumeFromLastPut(1)

      // Attempts remain, so the holder is told what was actually wrong and can retry.
      await assert.rejects(provider.consume(PreAuthorizedCode('bf-under'), 9999), {
        name: 'invalid_grant',
        message: INVALID_TX_CODE_MESSAGE,
      })
      assert.equal(ddbMock.commandCalls(DeleteCommand).length, 0)
    })

    it('deletes the code once a failed attempt exhausts the limit', async () => {
      ddbMock.on(PutCommand).resolves({})
      ddbMock.on(DeleteCommand).resolves({})

      const provider = createProvider()
      await saveWithTxCode(provider, 'bf-exhaust')
      // The gate admits the 5th (final) attempt, which then fails the tx_code check.
      armConsumeFromLastPut(5)

      // The lockout is reported on the attempt that trips it — not `Invalid tx_code`,
      // which would invite a retry that can no longer succeed.
      await assert.rejects(provider.consume(PreAuthorizedCode('bf-exhaust'), 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      // A locked-out code is removed rather than left to linger until its TTL.
      assert.equal(ddbMock.commandCalls(DeleteCommand).length, 1)
      const del = ddbMock.commandCalls(DeleteCommand)[0]?.args[0].input
      assert.deepEqual(del?.Key, { id: 'bf-exhaust' })
      assert.equal(del?.ConditionExpression, undefined)
    })

    it('deletes the code when a custom maxTxCodeAttempts is exhausted', async () => {
      ddbMock.on(PutCommand).resolves({})
      ddbMock.on(DeleteCommand).resolves({})

      const provider = createProvider(undefined, 2)
      await saveWithTxCode(provider, 'bf-custom-exhaust')
      armConsumeFromLastPut(2)

      await assert.rejects(provider.consume(PreAuthorizedCode('bf-custom-exhaust'), 9999), {
        name: 'invalid_grant',
        message: LOCKED_MESSAGE,
      })
      assert.equal(ddbMock.commandCalls(DeleteCommand).length, 1)
    })

    it('admits and consumes the correct tx_code through the same gate', async () => {
      ddbMock.on(PutCommand).resolves({})
      ddbMock.on(DeleteCommand).resolves({})

      const provider = createProvider()
      await saveWithTxCode(provider, 'bf-ok')
      armConsumeFromLastPut(1)

      const result = await provider.consume(PreAuthorizedCode('bf-ok'), 1234)
      assert.deepEqual(result, configurations)
      // Exactly one gated increment, then a conditional delete on success.
      assert.equal(ddbMock.commandCalls(UpdateCommand).length, 1)
      assert.equal(ddbMock.commandCalls(DeleteCommand).length, 1)
    })
  })
})
