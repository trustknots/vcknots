import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'
import { DeleteCommand, DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { mockClient } from 'aws-sdk-client-mock'
import { RequestObject, RequestObjectId } from '@trustknots/vcknots'
import { dynamodbRequestObjectStore } from '../src/providers/dynamodb-request-object-store.provider'

const TABLE_NAME = 'RequestObjectsTable'
const ddbMock = mockClient(DynamoDBDocumentClient)

describe('dynamodbRequestObjectStore', () => {
  const requestObjectId = RequestObjectId('test-request-object-id')
  const requestObject: RequestObject = {
    client_id: 'https://verifier.example.com',
    response_type: 'vp_token',
    response_mode: 'direct_post',
    nonce: 'test-nonce',
    presentation_definition: {
      id: 'test-pd',
      input_descriptors: [],
    },
  }

  afterEach(() => {
    ddbMock.reset()
  })

  const createProvider = (expiresIn?: number) =>
    dynamodbRequestObjectStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
      ...(expiresIn !== undefined && { expiresIn }),
    })

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'request-object-store-provider')
    assert.equal(provider.name, 'dynamodb-request-object-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch a request object', async () => {
    const futureExpiry = Math.floor(Date.now() / 1000) + 300
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: requestObjectId, requestObject, expires_at: futureExpiry },
    })

    const provider = createProvider()
    await provider.save(requestObjectId, requestObject)
    const fetched = await provider.fetch(requestObjectId)

    assert.deepEqual(fetched, requestObject)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 1)
    assert.equal(ddbMock.commandCalls(GetCommand).length, 1)
  })

  it('should return null when fetching an unknown id', async () => {
    ddbMock.on(GetCommand).resolves({})

    const provider = createProvider()
    const fetched = await provider.fetch(RequestObjectId('unknown-id'))

    assert.equal(fetched, null)
  })

  it('should return null when the item is expired', async () => {
    const pastExpiry = Math.floor(Date.now() / 1000) - 1
    ddbMock.on(GetCommand).resolves({
      Item: { id: requestObjectId, requestObject, expires_at: pastExpiry },
    })

    const provider = createProvider()
    const fetched = await provider.fetch(requestObjectId)

    assert.equal(fetched, null)
  })

  it('should save with correct table name and expires_at', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Math.floor(Date.now() / 1000)

    const provider = createProvider()
    await provider.save(requestObjectId, requestObject)

    const after = Math.floor(Date.now() / 1000)
    const putCall = ddbMock.commandCalls(PutCommand)[0]
    const item = putCall?.args[0].input.Item

    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.equal(item?.id, requestObjectId)
    assert.deepEqual(item?.requestObject, requestObject)
    assert.ok(item?.expires_at >= before + 300)
    assert.ok(item?.expires_at <= after + 300)
  })

  it('should delete a request object', async () => {
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await provider.delete(requestObjectId)

    const deleteCall = ddbMock.commandCalls(DeleteCommand)[0]
    assert.equal(deleteCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(deleteCall?.args[0].input.Key, { id: requestObjectId })
  })
})
