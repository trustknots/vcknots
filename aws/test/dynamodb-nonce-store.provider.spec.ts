import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'
import { DeleteCommand, DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { mockClient } from 'aws-sdk-client-mock'
import { Nonce } from '@trustknots/vcknots'
import { dynamodbNonceStore } from '../src/providers/dynamodb-nonce-store.provider'

const TABLE_NAME = 'NoncesTable'
const ddbMock = mockClient(DynamoDBDocumentClient)

describe('dynamodbNonceStore', () => {
  const nonce: Nonce = { nonce: 'test-nonce', nonce_expires_in: 300 * 1000 }

  afterEach(() => {
    ddbMock.reset()
  })

  const createProvider = () =>
    dynamodbNonceStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
    })

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'nonce-store-provider')
    assert.equal(provider.name, 'dynamodb-nonce-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save with epoch-ms expires_at and epoch-seconds ttl', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const provider = createProvider()
    await provider.save(nonce)

    const after = Date.now()
    const putCall = ddbMock.commandCalls(PutCommand)[0]
    const item = putCall?.args[0].input.Item

    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.equal(item?.id, nonce.nonce)
    assert.deepEqual(item?.nonce, nonce)
    // expires_at is epoch ms (parity with Firestore / in-memory).
    assert.ok(item?.expires_at >= before + 300 * 1000)
    assert.ok(item?.expires_at <= after + 300 * 1000)
    // ttl is epoch seconds, rounded up so TTL never fires before the real (ms) expiry.
    assert.equal(item?.ttl, Math.ceil(item?.expires_at / 1000))
  })

  it('should throw when nonce_expires_in is missing on save', async () => {
    const provider = createProvider()
    await assert.rejects(() => provider.save({ nonce: 'no-ttl' }), /nonce_expires_in is required/)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 0)
  })

  it('validate should return true for a valid nonce', async () => {
    const futureExpiry = Date.now() + 300 * 1000
    ddbMock.on(GetCommand).resolves({
      Item: { id: nonce.nonce, nonce, expires_at: futureExpiry },
    })

    const provider = createProvider()
    assert.equal(await provider.validate(nonce), true)
    const getCall = ddbMock.commandCalls(GetCommand)[0]
    assert.equal(getCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(getCall?.args[0].input.Key, { id: nonce.nonce })
  })

  it('validate should return false for an unknown nonce', async () => {
    ddbMock.on(GetCommand).resolves({})

    const provider = createProvider()
    assert.equal(await provider.validate(nonce), false)
  })

  it('validate should return false and delete an expired nonce', async () => {
    const pastExpiry = Date.now() - 1000
    ddbMock.on(GetCommand).resolves({
      Item: { id: nonce.nonce, nonce, expires_at: pastExpiry },
    })
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    assert.equal(await provider.validate(nonce), false)

    // Match the Firestore provider: expired nonces are proactively deleted, not left to TTL.
    const deleteCall = ddbMock.commandCalls(DeleteCommand)[0]
    assert.equal(deleteCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(deleteCall?.args[0].input.Key, { id: nonce.nonce })
  })

  it('revoke should return true when the nonce existed', async () => {
    ddbMock.on(DeleteCommand).resolves({
      Attributes: { id: nonce.nonce, nonce, expires_at: Date.now() + 300 * 1000 },
    })

    const provider = createProvider()
    assert.equal(await provider.revoke(nonce), true)
    const deleteCall = ddbMock.commandCalls(DeleteCommand)[0]
    assert.equal(deleteCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(deleteCall?.args[0].input.Key, { id: nonce.nonce })
    assert.equal(deleteCall?.args[0].input.ReturnValues, 'ALL_OLD')
  })

  it('revoke should return false when the nonce did not exist', async () => {
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    assert.equal(await provider.revoke(nonce), false)
  })

  it('consume should return true and delete a valid nonce', async () => {
    ddbMock.on(DeleteCommand).resolves({
      Attributes: { id: nonce.nonce, nonce, expires_at: Date.now() + 300 * 1000 },
    })

    const provider = createProvider()
    assert.equal(await provider.consume(nonce), true)
    const deleteCall = ddbMock.commandCalls(DeleteCommand)[0]
    assert.equal(deleteCall?.args[0].input.ReturnValues, 'ALL_OLD')
  })

  it('consume should return false for an unknown nonce', async () => {
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    assert.equal(await provider.consume(nonce), false)
  })

  it('consume should return false for an expired nonce', async () => {
    ddbMock.on(DeleteCommand).resolves({
      Attributes: { id: nonce.nonce, nonce, expires_at: Date.now() - 1000 },
    })

    const provider = createProvider()
    assert.equal(await provider.consume(nonce), false)
  })
})
