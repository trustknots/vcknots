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

  it('should save with correct table name and epoch-seconds expires_at', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Math.floor(Date.now() / 1000)

    const provider = createProvider()
    await provider.save(nonce)

    const after = Math.floor(Date.now() / 1000)
    const putCall = ddbMock.commandCalls(PutCommand)[0]
    const item = putCall?.args[0].input.Item

    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.equal(item?.id, nonce.nonce)
    assert.deepEqual(item?.nonce, nonce)
    assert.ok(item?.expires_at >= before + 300)
    assert.ok(item?.expires_at <= after + 300)
  })

  it('should throw when nonce_expires_in is missing on save', async () => {
    const provider = createProvider()
    await assert.rejects(() => provider.save({ nonce: 'no-ttl' }), /nonce_expires_in is required/)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 0)
  })

  it('validate should return true for a valid nonce', async () => {
    const futureExpiry = Math.floor(Date.now() / 1000) + 300
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

  it('validate should return false for an expired nonce', async () => {
    const pastExpiry = Math.floor(Date.now() / 1000) - 1
    ddbMock.on(GetCommand).resolves({
      Item: { id: nonce.nonce, nonce, expires_at: pastExpiry },
    })

    const provider = createProvider()
    assert.equal(await provider.validate(nonce), false)
  })

  it('revoke should return true when the nonce existed', async () => {
    ddbMock.on(DeleteCommand).resolves({
      Attributes: { id: nonce.nonce, nonce, expires_at: Math.floor(Date.now() / 1000) + 300 },
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
      Attributes: { id: nonce.nonce, nonce, expires_at: Math.floor(Date.now() / 1000) + 300 },
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
      Attributes: { id: nonce.nonce, nonce, expires_at: Math.floor(Date.now() / 1000) - 1 },
    })

    const provider = createProvider()
    assert.equal(await provider.consume(nonce), false)
  })
})
